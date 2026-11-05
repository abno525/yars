package export

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"yars/internal/finding"

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

var imgTag = regexp.MustCompile(`<img src="([^"]*)" alt="([^"]*)"(?: title="[^"]*")? ?/?>`)
var attachmentRef = regexp.MustCompile(`^attachments/[A-Za-z0-9][A-Za-z0-9._-]*$`)
var imageTypes = map[string]string{".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp"}

// images inlines the finding's own attachments as data URIs and removes every
// other image, so a report can never pull in server files or remote URLs.
func images(x string, f *finding.Finding, in Input) string {
	return imgTag.ReplaceAllStringFunc(x, func(m string) string {
		sub := imgTag.FindStringSubmatch(m)
		src, alt := html.UnescapeString(sub[1]), sub[2]
		ct := imageTypes[strings.ToLower(path.Ext(src))]
		if attachmentRef.MatchString(src) && ct != "" && in.Attachment != nil {
			if data, ok := in.Attachment(f, src); ok && (!in.strictImages || decodes(data)) {
				if in.imageSrc != nil {
					return `<img src="` + html.EscapeString(in.imageSrc(f, src, ct, data)) + `" alt="` + alt + `" />`
				}
				return `<img src="data:` + ct + `;base64,` + base64.StdEncoding.EncodeToString(data) + `" alt="` + alt + `" />`
			}
		}
		return `<em>[image removed: ` + alt + `]</em>`
	})
}

// decodes reports a whole, readable PNG, JPEG or GIF.
func decodes(data []byte) bool {
	_, _, err := image.Decode(bytes.NewReader(data))
	return err == nil
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
		writeSections(&b, f, in, confluenceMacros)
	}
	return b.String()
}

// writeSections renders the finding's non-empty sections, each under an h2.
func writeSections(b *strings.Builder, f *finding.Finding, in Input, confluenceMacros bool) {
	for _, s := range f.Sections {
		body := strings.Trim(s.Body, "\n")
		if strings.TrimSpace(body) == "" {
			continue
		}
		var buf bytes.Buffer
		md.Convert([]byte(body), &buf)
		out := images(buf.String(), f, in)
		if confluenceMacros {
			out = macros(out)
		}
		fmt.Fprintf(b, "<h2>%s</h2>\n%s\n", esc(s.Name), out)
	}
}

func (r *Runner) confluence(ctx context.Context, e Exporter, in Input) (Result, error) {
	c := e.Confluence
	if c == nil || c.BaseURL == "" {
		doc := "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\" /><title>" + esc(in.Engagement.Name) + "</title></head><body>\n<h1>" +
			esc(in.Engagement.Name) + "</h1>\n<p>" + esc(in.subtitle()) + "</p>\n" + XHTML(in, false) + "</body></html>\n"
		return Result{Filename: in.Engagement.ID + ".html", ContentType: "text/html; charset=utf-8", Data: []byte(doc)}, nil
	}
	if err := httpsOnly(c.BaseURL, "confluence"); err != nil {
		return Result{}, err
	}
	user, token, err := r.login(in, "confluence", c.UserEnv, c.TokenEnv)
	if err != nil {
		return Result{}, err
	}
	base := strings.TrimRight(c.BaseURL, "/") + "/rest/api/content"
	title := in.Engagement.Name + " — findings"
	if len(in.Findings) == 1 { // one finding is one page of its own
		title = in.Findings[0].Meta.ID + " " + in.Findings[0].Meta.Title + " — " + in.Engagement.Name
	}
	call := func(method, url string, body []byte) ([]byte, error) {
		return r.call(ctx, "confluence push", user, token, method, url, body)
	}
	payload := map[string]any{
		"type":  "page",
		"title": title,
		"space": map[string]string{"key": c.Space},
		"body":  map[string]any{"storage": map[string]string{"value": XHTML(in, true), "representation": "storage"}},
	}
	if c.ParentID != "" {
		payload["ancestors"] = []map[string]string{{"id": c.ParentID}}
	}
	// the page this finding became before, read for its current version
	var cur *confPage
	if len(in.Findings) == 1 {
		if k, ok := in.Known[in.Findings[0].Meta.ID]; ok && k.ID != "" {
			data, err := call("GET", base+"/"+url.PathEscape(k.ID)+"?expand=version,space", nil)
			switch {
			case err == nil:
				var p confPage
				if json.Unmarshal(data, &p) == nil && p.ID != "" && (p.Space.Key == "" || p.Space.Key == c.Space) {
					cur = &p
				}
			case !notFound(err): // gone: found by title or made again
				return Result{}, err
			}
		}
	}
	// otherwise the page with this title (titles are unique per space)
	if cur == nil {
		q := url.Values{"title": {title}, "spaceKey": {c.Space}, "expand": {"version"}}
		if data, err := call("GET", base+"?"+q.Encode(), nil); err == nil {
			var found struct{ Results []confPage }
			if json.Unmarshal(data, &found) == nil && len(found.Results) > 0 {
				cur = &found.Results[0]
			}
		}
	}
	method, target, action, version := "POST", base, "created", 1
	if cur != nil {
		method, target, action, version = "PUT", base+"/"+url.PathEscape(cur.ID), "updated", cur.Version.Number+1
		payload["id"] = cur.ID
		payload["version"] = map[string]int{"number": version}
	}
	body, _ := json.Marshal(payload)
	data, err := call(method, target, body)
	if err != nil {
		return Result{}, err
	}
	var out struct {
		confPage
		Links struct{ Base, Webui string } `json:"_links"`
	}
	json.Unmarshal(data, &out)
	rm := Remote{ID: out.ID, Version: out.Version.Number}
	if rm.ID == "" && cur != nil {
		rm.ID = cur.ID
	}
	if rm.Version == 0 {
		rm.Version = version
	}
	res := Result{Pushed: true, URL: out.Links.Base + out.Links.Webui}
	for _, f := range in.ordered() {
		res.Items = append(res.Items, Item{ID: f.Meta.ID, URL: res.URL, Remote: rm, Action: action})
	}
	return res, nil
}

// confPage is a Confluence page as the content API returns it.
type confPage struct {
	ID      string
	Version struct{ Number int }
	Space   struct{ Key string }
}

// httpsOnly refuses a service address that isn't https (plain http only to
// this machine, for tests and tunnels).
func httpsOnly(base, service string) error {
	u, err := url.Parse(base)
	local := err == nil && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && local)) {
		return errors.New(service + " base_url must use https")
	}
	return nil
}

// login is the sender's own key when the input has one, otherwise the
// server's from the environment.
func (r *Runner) login(in Input, service, userEnv, tokenEnv string) (string, string, error) {
	if in.Creds != nil {
		if in.Creds.User == "" || in.Creds.Token == "" {
			return "", "", errors.New(service + " personal key incomplete")
		}
		return in.Creds.User, in.Creds.Token, nil
	}
	user, token := r.Getenv(userEnv), r.Getenv(tokenEnv)
	if user == "" || token == "" {
		return "", "", fmt.Errorf("%s credentials missing: set %s and %s on the server", service, userEnv, tokenEnv)
	}
	return user, token, nil
}

// call sends one JSON request with Basic auth. Error messages from the
// service never carry the credentials.
func (r *Runner) call(ctx context.Context, what, user, token, method, url string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(user, token)
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s failed: %v", what, errors.Unwrap(err))
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Message       string
			ErrorMessages []string
			Errors        map[string]string
		}
		json.Unmarshal(data, &e)
		parts := append([]string{e.Message}, e.ErrorMessages...)
		for k, v := range e.Errors {
			parts = append(parts, k+": "+v)
		}
		msg := strings.TrimSpace(strings.Join(slices.DeleteFunc(parts, func(s string) bool { return s == "" }), "; "))
		for _, secret := range []string{token, user} { // never echo credentials
			if secret != "" {
				msg = strings.ReplaceAll(msg, secret, "***")
			}
		}
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		return nil, &statusError{resp.StatusCode, fmt.Sprintf("%s failed: HTTP %d %s", what, resp.StatusCode, msg)}
	}
	return data, nil
}

// statusError is a service's answer outside 2xx.
type statusError struct {
	code int
	msg  string
}

func (e *statusError) Error() string { return e.msg }

// notFound reports a 404 answer: the page or issue is gone.
func notFound(err error) bool {
	var se *statusError
	return errors.As(err, &se) && se.code == http.StatusNotFound
}
