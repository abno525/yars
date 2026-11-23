package export

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"yars/internal/finding"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	ghtml "github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// md renders untrusted finding Markdown: raw HTML is omitted (no script,
// no Confluence macro injection), output is XHTML for the storage format.
// A body's headings sit below the finding's title and its section's.
var md = goldmark.New(goldmark.WithExtensions(extension.GFM), goldmark.WithRendererOptions(ghtml.WithXHTML()),
	goldmark.WithParserOptions(parser.WithASTTransformers(util.Prioritized(headingFloor{}, 100))))

// headingFloor makes a body's # and ## headings h3: in a report a
// finding's title is the h1 and its sections are h2, so a heading written
// in a section is an h3 at most (the contents list holds h1 and h2 only).
type headingFloor struct{}

func (headingFloor) Transform(doc *ast.Document, _ text.Reader, _ parser.Context) {
	ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if h, ok := n.(*ast.Heading); ok && entering && h.Level < 3 {
			h.Level = 3
		}
		return ast.WalkContinue, nil
	})
}

var codeBlock = regexp.MustCompile(`(?s)<pre><code(?: class="language-([A-Za-z0-9_+-]+)")?>(.*?)</code></pre>`)

var checkbox = regexp.MustCompile(`<input (checked="" )?disabled="" type="checkbox" /> ?`)

// macros turns fenced code blocks into Confluence code macros, and a task
// list's checkboxes into ☐ and ☑ (storage format has no <input>).
func macros(x string) string {
	x = checkbox.ReplaceAllStringFunc(x, func(m string) string {
		if strings.Contains(m, "checked") {
			return "☑ "
		}
		return "☐ "
	})
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

// images inlines the finding's own attachments as data URIs (a push shows
// them as attachments of the page) and removes every other image, so a
// report can never pull in server files or remote URLs.
func images(x string, f *finding.Finding, in Input) string {
	return imgTag.ReplaceAllStringFunc(x, func(m string) string {
		sub := imgTag.FindStringSubmatch(m)
		src, alt := html.UnescapeString(sub[1]), sub[2]
		ct := imageTypes[strings.ToLower(path.Ext(src))]
		if attachmentRef.MatchString(src) && ct != "" && in.Attachment != nil {
			if data, ok := in.Attachment(f, src); ok && (!in.strictImages || decodes(data)) {
				if in.attach != nil {
					return `<ac:image ac:alt="` + alt + `"><ri:attachment ri:filename="` + html.EscapeString(in.attach(f, src, ct, data)) + `" /></ac:image>`
				}
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

// xmlChars drops the characters XML 1.0 forbids (controls but tab and line
// breaks, U+FFFE, U+FFFF), which pasted terminal output carries: Confluence
// refuses a storage body that holds one.
func xmlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r == 0xFFFE || r == 0xFFFF {
			return -1
		}
		return r
	}, s)
}

func esc(s string) string {
	return strings.ReplaceAll(html.EscapeString(strings.TrimSpace(s)), "\n", "<br />")
}

// reportHTML renders a report-level section's Markdown ("" when blank).
// It belongs to no finding, so it has no attachments: images are removed.
func reportHTML(body string, confluenceMacros bool) string {
	body = strings.Trim(body, "\n")
	if strings.TrimSpace(body) == "" {
		return ""
	}
	var buf bytes.Buffer
	md.Convert([]byte(body), &buf)
	out := images(buf.String(), nil, Input{})
	if confluenceMacros {
		out = macros(out)
	}
	return out
}

// isSummary reports whether a report section is the executive summary,
// which the themed report puts above the severity counts.
func isSummary(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), "Executive summary")
}

// XHTML renders the report body; confluenceMacros turns code blocks into
// Confluence code macros (push mode).
func XHTML(in Input, confluenceMacros bool) string {
	var b strings.Builder
	for _, rt := range in.Report {
		if out := reportHTML(rt.Body, confluenceMacros); out != "" {
			fmt.Fprintf(&b, "<h1>%s</h1>\n%s\n", esc(rt.Name), out)
		}
	}
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
		in.Report = nil
	}
	call := func(method, url string, body []byte) ([]byte, error) {
		return r.call(ctx, "confluence push", user, token, method, url, body)
	}
	// the findings' pictures become attachments of the page, shown where
	// they stand (Confluence may not show data URIs); names as the HTML ZIP's
	var pics []pagePic
	used := map[string]bool{}
	in.attach = func(f *finding.Finding, rel, ct string, data []byte) string {
		name := fileSafe(f.Meta.ID) + "-" + path.Base(rel)
		if !used[name] {
			used[name] = true
			pics = append(pics, pagePic{name, ct, data})
		}
		return name
	}
	page := func(storage string) map[string]any {
		p := map[string]any{
			"type":  "page",
			"title": title,
			"space": map[string]string{"key": c.Space},
			"body":  map[string]any{"storage": map[string]string{"value": storage, "representation": "storage"}},
		}
		if c.ParentID != "" {
			p["ancestors"] = []map[string]string{{"id": c.ParentID}}
		}
		return p
	}
	payload := page(xmlChars(XHTML(in, true)))
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
	created := cur == nil
	if created && len(pics) > 0 { // attachments need the page: made empty first
		body, _ := json.Marshal(page(""))
		data, err := call("POST", base, body)
		if err != nil {
			return Result{}, err
		}
		var p confPage
		json.Unmarshal(data, &p)
		if p.ID == "" {
			return Result{}, errors.New("confluence push failed: the new page has no id")
		}
		cur = &p
		cur.Version.Number = max(cur.Version.Number, 1)
	}
	// what an existing page holds: unchanged pictures are not sent again
	var had []confAttachment
	if !created {
		had, err = r.pageAttachments(ctx, user, token, base+"/"+url.PathEscape(cur.ID)+"/child/attachment")
		if err != nil {
			return Result{}, err
		}
	}
	for _, pic := range pics { // then the pictures, then the body that shows them
		if err := r.putAttachment(ctx, user, token, base+"/"+url.PathEscape(cur.ID)+"/child/attachment", pic, had); err != nil {
			return Result{}, err
		}
	}
	method, target, action, version := "POST", base, "created", 1
	if cur != nil {
		method, target, version = "PUT", base+"/"+url.PathEscape(cur.ID), cur.Version.Number+1
		if !created {
			action = "updated"
		}
		payload["id"] = cur.ID
		payload["version"] = map[string]int{"number": version}
	}
	body, _ := json.Marshal(payload)
	data, err := call(method, target, body)
	if err != nil {
		return Result{}, err
	}
	// last the pictures a push left that the body no longer shows: a current
	// attachment stays downloadable to anyone who can view the page
	for _, a := range had {
		if a.ID != "" && strings.HasPrefix(a.comment(), "sha256:") && !used[a.Title] {
			_, err := r.call(ctx, "confluence delete of "+a.Title, user, token, "DELETE", base+"/"+url.PathEscape(a.ID), nil)
			if err != nil && !notFound(err) {
				return Result{}, err
			}
		}
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

// pagePic is a finding's picture as an attachment of the page.
type pagePic struct {
	name, ct string
	data     []byte
}

// fileSafe keeps a finding ID to the characters of a file name.
func fileSafe(id string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, id)
}

// confAttachment is an attachment of a page as the content API lists it.
type confAttachment struct {
	ID, Title            string
	Metadata, Extensions struct{ Comment string }
}

// comment is in metadata or in extensions, by Confluence version.
func (a confAttachment) comment() string {
	return cmp.Or(a.Metadata.Comment, a.Extensions.Comment)
}

// pageAttachments lists the page's attachments (target), following the
// list's next link: a server may give fewer than asked for.
func (r *Runner) pageAttachments(ctx context.Context, user, token, target string) ([]confAttachment, error) {
	var all []confAttachment
	for {
		q := url.Values{"start": {strconv.Itoa(len(all))}, "limit": {"200"}}
		data, err := r.call(ctx, "confluence attachment list", user, token, "GET", target+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var got struct {
			Results []confAttachment
			Links   struct{ Next string } `json:"_links"`
		}
		json.Unmarshal(data, &got)
		all = append(all, got.Results...)
		if got.Links.Next == "" || len(got.Results) == 0 {
			return all, nil
		}
	}
}

// putAttachment uploads pic to the page's attachments (target): a new one,
// or a new version of the one with its name. It skips the upload when the
// page had these bytes already, by the sha256 every upload leaves in the
// attachment's comment.
func (r *Runner) putAttachment(ctx context.Context, user, token, target string, pic pagePic, had []confAttachment) error {
	h := sha256.Sum256(pic.data)
	comment := "sha256:" + hex.EncodeToString(h[:])
	for _, a := range had {
		if a.Title == pic.name && a.comment() == comment {
			return nil
		}
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {`form-data; name="file"; filename="` + pic.name + `"`},
		"Content-Type":        {pic.ct},
	})
	part.Write(pic.data)
	mw.WriteField("comment", comment)
	mw.WriteField("minorEdit", "true") // no mail to the page's watchers
	mw.Close()
	req, err := http.NewRequestWithContext(ctx, "PUT", target, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Atlassian-Token", "no-check") // uploads are refused without it
	_, err = r.send(req, "confluence upload of "+pic.name, user, token)
	return err
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
	return r.send(req, what, user, token)
}

// send sends req with Basic auth and reads the JSON answer, as call.
func (r *Runner) send(req *http.Request, what, user, token string) ([]byte, error) {
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
