package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	ghtml "github.com/yuin/goldmark/renderer/html"
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// md renders untrusted finding Markdown: raw HTML is omitted (no script,
// no Confluence macro injection), output is XHTML for the storage format.
var md = goldmark.New(goldmark.WithExtensions(extension.GFM), goldmark.WithRendererOptions(ghtml.WithXHTML()))

var codeBlock = regexp.MustCompile(`(?s)<pre><code(?: class="language-([A-Za-z0-9_+-]+)")?>(.*?)</code></pre>`)

// macros turns fenced code blocks into Confluence code macros.
func macros(x string) string {
	return codeBlock.ReplaceAllStringFunc(x, func(m string) string {
		sub := codeBlock.FindStringSubmatch(m)
		body := strings.ReplaceAll(html.UnescapeString(sub[2]), "]]>", "]]]]><![CDATA[>")
		lang := ""
		if sub[1] != "" {
			lang = `<ac:parameter ac:name="language">` + sub[1] + `</ac:parameter>`
		}
		return `<ac:structured-macro ac:name="code">` + lang + `<ac:plain-text-body><![CDATA[` + body + `]]></ac:plain-text-body></ac:structured-macro>`
	})
}

func esc(s string) string {
	return strings.ReplaceAll(html.EscapeString(strings.TrimSpace(s)), "\n", "<br />")
}

// XHTML renders the report body; confluenceMacros turns code blocks into
// Confluence code macros (push mode).
func XHTML(in Input, confluenceMacros bool) string {
	var b strings.Builder
	for _, f := range in.ordered() {
		m := f.Meta
		fmt.Fprintf(&b, "<h1>%s %s</h1>\n<table><tbody>\n", esc(m.ID), esc(m.Title))
		for _, r := range summary(f, in.Cfg) {
			fmt.Fprintf(&b, "<tr><th>%s</th><td>%s</td></tr>\n", esc(r.Label), esc(r.Value))
		}
		b.WriteString("</tbody></table>\n")
		if rs := reasons(f, in.Cfg); len(rs) > 0 {
			b.WriteString("<p><strong>CVSS explanation</strong></p>\n<table><tbody>\n<tr><th>Metric</th><th>Value</th><th>Explanation</th></tr>\n")
			for _, r := range rs {
				fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n", esc(r[0]), esc(r[1]), esc(r[2]))
			}
			b.WriteString("</tbody></table>\n")
		}
		for _, s := range f.Sections {
			body := strings.Trim(s.Body, "\n")
			if strings.TrimSpace(body) == "" {
				continue
			}
			var buf bytes.Buffer
			md.Convert([]byte(body), &buf)
			out := buf.String()
			if confluenceMacros {
				out = macros(out)
			}
			fmt.Fprintf(&b, "<h2>%s</h2>\n%s\n", esc(s.Name), out)
		}
	}
	return b.String()
}

func (r *Runner) confluence(ctx context.Context, e Exporter, in Input) (Result, error) {
	c := e.Confluence
	if c == nil || c.BaseURL == "" {
		doc := "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\" /><title>" + esc(in.Engagement.Name) + "</title></head><body>\n<h1>" +
			esc(in.Engagement.Name) + "</h1>\n<p>" + esc(in.subtitle()) + "</p>\n" + XHTML(in, false) + "</body></html>\n"
		return Result{Filename: in.Engagement.ID + ".html", ContentType: "text/html; charset=utf-8", Data: []byte(doc)}, nil
	}
	u, err := url.Parse(c.BaseURL)
	local := err == nil && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")
	if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && local)) {
		return Result{}, errors.New("confluence base_url must use https")
	}
	user, token := r.Getenv(c.UserEnv), r.Getenv(c.TokenEnv)
	if user == "" || token == "" {
		return Result{}, fmt.Errorf("confluence credentials missing: set %s and %s on the server", c.UserEnv, c.TokenEnv)
	}
	payload := map[string]any{
		"type":  "page",
		"title": in.Engagement.Name + " — findings",
		"space": map[string]string{"key": c.Space},
		"body":  map[string]any{"storage": map[string]string{"value": XHTML(in, true), "representation": "storage"}},
	}
	if c.ParentID != "" {
		payload["ancestors"] = []map[string]string{{"id": c.ParentID}}
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(c.BaseURL, "/")+"/rest/api/content", bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(user, token)
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("confluence push failed: %v", errors.Unwrap(err))
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		// the body may echo credentials: report only the status
		return Result{}, fmt.Errorf("confluence push failed: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Links struct{ Base, Webui string } `json:"_links"`
	}
	json.Unmarshal(data, &out)
	return Result{URL: out.Links.Base + out.Links.Webui}, nil
}
