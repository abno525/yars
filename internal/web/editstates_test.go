package web

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/events"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/store"
)

func testPNG(t *testing.T, c color.Color) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 3, 3))
	img.Set(1, 1, c)
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// sendFile posts a multipart form with one file field "file".
func (e *env) sendFile(t *testing.T, user, path, name string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", name)
	fw.Write(data)
	mw.Close()
	req := httptest.NewRequest("POST", path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks[user]})
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func TestPresence(t *testing.T) {
	e := setup(t)
	sub := e.srv.Events.Subscribe("acme", "F-001", 16)
	defer e.srv.Events.Unsubscribe(sub)
	// opening the editor says alice is editing Impact
	if rec := e.do(t, "alice", "GET", fpath+"/s/Impact/edit", nil, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), `data-presence="/e/acme/f/001/s/Impact/presence"`) {
		t.Fatalf("editor %d:\n%s", rec.Code, rec.Body.String())
	} else if !strings.Contains(rec.Body.String(), `hx-get="/e/acme/f/001/s/Impact/presence" hx-target="this"`) {
		// inside the editor form the slot would inherit the form's
		// hx-target and replace the whole editor (typed text lost)
		t.Fatalf("presence slot in the editor does not target itself:\n%s", rec.Body.String())
	}
	select {
	case ev := <-sub.C():
		if ev.Kind != events.Presence {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no presence event")
	}
	b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, `<strong title="alice">alice</strong> is editing`) {
		t.Fatalf("bob does not see alice editing:\n%s", b)
	}
	if !strings.Contains(b, `hx-get="/e/acme/f/001/s/Impact/presence"`) || !strings.Contains(b, "sse:presence") {
		t.Fatal("presence slot is not live")
	}
	noInline(t, "finding page", b)
	// nobody is shown to themself
	slot := e.do(t, "alice", "GET", fpath+"/s/Impact/presence", nil, nil).Body.String()
	if strings.Contains(slot, "alice") || !strings.Contains(slot, `class="slot w216 pres"`) {
		t.Fatalf("own presence:\n%s", slot)
	}
	// other sections are untouched
	if s := e.do(t, "bob", "GET", fpath+"/s/Remediation/presence", nil, nil).Body.String(); strings.Contains(s, "alice") {
		t.Fatalf("wrong section:\n%s", s)
	}
	// heartbeat keeps it; 60 s without one drops it
	if rec := e.do(t, "alice", "POST", fpath+"/s/Impact/presence", url.Values{}, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("heartbeat %d", rec.Code)
	}
	e.srv.presence.now = func() time.Time { return time.Now().Add(61 * time.Second) }
	if s := e.do(t, "bob", "GET", fpath+"/s/Impact/presence", nil, nil).Body.String(); strings.Contains(s, "alice") {
		t.Fatalf("expired presence shown:\n%s", s)
	}
	e.srv.presence.now = time.Now
	// saving ends it
	e.do(t, "alice", "POST", fpath+"/s/Impact/presence", url.Values{}, nil)
	ref, _ := e.srv.Store.Finding("acme", "F-001-sql-injection")
	body, _ := ref.F.Section("Impact")
	e.do(t, "alice", "POST", fpath+"/s/Impact", url.Values{"body": {"new"}, "base": {store.BodyHash(body)}}, nil)
	if s := e.do(t, "bob", "GET", fpath+"/s/Impact/presence", nil, nil).Body.String(); strings.Contains(s, "alice") {
		t.Fatalf("presence after save:\n%s", s)
	}
	js := e.do(t, "alice", "GET", "/static/sse.js", nil, nil).Body.String()
	if !strings.Contains(js, "'presence'") {
		t.Fatal("sse.js does not pass presence events on")
	}
}

// A finding locked while its editor is open: the save answers 403 with the
// reason as text, htmx does not swap it (the editor keeps the text) but
// raises an error, and app.js shows the text as a toast (backlog, M3).
func TestLockedSaveShowsWhy(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	rec := e.do(t, "alice", "POST", fpath+"/s/Impact", url.Values{"body": {"late"}}, map[string]string{"HX-Request": "true"})
	if rec.Code != http.StatusForbidden || strings.TrimSpace(rec.Body.String()) == "" || strings.Contains(rec.Body.String(), "<html") {
		t.Fatalf("locked save %d %q", rec.Code, rec.Body.String())
	}
	page := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(page, `{"code":"[45]..","swap":false,"error":true}`) {
		t.Fatal("htmx would swap a 403 into the editor")
	}
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	i := strings.Index(js, "'htmx:responseError'")
	if i < 0 || !strings.Contains(js[i:i+800], "xhr.responseText") || !strings.Contains(js[i:i+800], "yarsToast(") {
		t.Fatal("app.js does not show an unswapped error's text")
	}
}

// An expired session answers htmx requests with 401 (the page keeps the
// text as a draft); full pages still go to the login.
func TestSessionExpiredHX(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "", "POST", fpath+"/s/Impact", url.Values{"body": {"x"}}, map[string]string{"HX-Request": "true"})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Session expired") {
		t.Fatalf("htmx without session %d %q", rec.Code, rec.Body.String())
	}
	if rec := e.do(t, "", "GET", fpath, nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("page without session %d", rec.Code)
	}
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	for _, want := range []string{"401", "yars-draft:", "data-draft-restore", "Session expired"} {
		if !strings.Contains(js, want) {
			t.Fatalf("app.js lacks %s", want)
		}
	}
	ed := e.do(t, "alice", "GET", fpath+"/s/Impact/edit", nil, nil).Body.String()
	if !strings.Contains(ed, `data-draft-restore`) || !strings.Contains(ed, `class="btn secondary sm w96 invisible"`) {
		t.Fatalf("editor has no draft restore slot:\n%s", ed)
	}
}

// attachmentsPanel is the finding page's Attachments panel.
func attachmentsPanel(t *testing.T, b string) string {
	t.Helper()
	i := strings.Index(b, `<section class="panel compact" id="attachments"`)
	if i < 0 {
		t.Fatalf("no Attachments panel:\n%s", b)
	}
	return b[i : i+strings.Index(b[i:], "</section>")]
}

// D4: the finding page lists its attachments: name, type, size, Open, and a
// slot kept for Purge; the panel sits after the text, before Checks.
func TestAttachmentsPanelListsFiles(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, nil)
	if rec := e.sendFile(t, "alice", fpath+"/attachments", "shot.png", testPNG(t, color.White)); rec.Code != 200 {
		t.Fatalf("upload %d", rec.Code)
	}
	b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	p := attachmentsPanel(t, b)
	for _, want := range []string{`<span class="qcnt">1</span>`, `<th>Name</th><th class="c-kind">Type</th><th class="c-size">Size</th><th class="c-act">Action</th>`,
		`title="shot.png"><span class="attn"><span class="clip">shot.png</span></span></td>`, "<td>PNG</td>", `<a class="btn ghost sm w96" href="/e/acme/f/001/attachments/shot.png">Open</a><span class="slot w96"></span>`} {
		if !strings.Contains(p, want) {
			t.Fatalf("panel lacks %s:\n%s", want, p)
		}
	}
	// it refreshes itself like the other panels (D15): an upload from a
	// section editor shows up
	if !strings.Contains(b, `<section class="panel compact" id="attachments" data-kpanel hx-get="/e/acme/f/001/attachments" hx-trigger="sse:content, sse:resync, sse:poll" hx-swap="outerHTML" data-sse>`) {
		t.Fatalf("panel without live refresh:\n%s", p)
	}
	e.sendFile(t, "alice", fpath+"/attachments", "notes.txt", []byte("see above"))
	if q := attachmentsPanel(t, e.do(t, "bob", "GET", fpath+"/attachments", nil, nil).Body.String()); !strings.Contains(q, ">notes.txt<") || !strings.Contains(q, `<span class="qcnt">2</span>`) {
		t.Fatalf("refreshed panel:\n%s", q)
	}
	last, att, checks := strings.LastIndex(b, `<section class="panel" id="s-`), strings.Index(b, `id="attachments"`), strings.Index(b, `id="checks"`)
	if !(last < att && att < checks) {
		t.Fatalf("order: last section %d, attachments %d, checks %d", last, att, checks)
	}
	css := e.do(t, "bob", "GET", "/static/style.css", nil, nil).Body.String()
	if !strings.Contains(css, ".atttable th.c-kind, .atttable th.c-size { width: 96px; }") || !strings.Contains(css, ".atttable th.c-act { width: 224px; }") {
		t.Fatal("no Attachments column widths")
	}
}

// D4: without attachments the panel keeps its header and one empty row.
func TestAttachmentsPanelEmptyRow(t *testing.T) {
	e := setup(t)
	p := attachmentsPanel(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if !strings.Contains(p, `<span class="qcnt zero">0</span>`) || !strings.Contains(p, "<thead>") || !strings.Contains(p, `<tr class="emptyrow"><td colspan="4">—</td></tr>`) {
		t.Fatalf("empty panel:\n%s", p)
	}
}

// D28: an image redacted after its upload is marked on its thumbnail in the
// editor's strip and on its row in the Attachments panel; before, neither.
func TestMarkOnThumbAndRow(t *testing.T) {
	e := setup(t)
	if rec := e.sendFile(t, "alice", fpath+"/attachments", "shot.png", testPNG(t, color.White)); rec.Code != 200 {
		t.Fatalf("upload %d", rec.Code)
	}
	strip := func() string { return e.do(t, "alice", "GET", fpath+"/s/Impact/edit", nil, nil).Body.String() }
	panel := func() string { return attachmentsPanel(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()) }
	if strings.Contains(strip(), "histdot") || strings.Contains(panel(), "histdot") {
		t.Fatal("marked before any redaction")
	}
	if rec := e.sendFile(t, "alice", fpath+"/attachments/shot.png/redact", "blob", testPNG(t, color.Black)); rec.Code != 200 {
		t.Fatalf("redact %d:\n%s", rec.Code, rec.Body.String())
	}
	mark := `<span class="histdot" title="An earlier version is in git history"></span>`
	if s := strip(); !strings.Contains(between(s, `<div class="thumb">`, "</div>"), mark) {
		t.Fatalf("no mark on the thumbnail:\n%s", between(s, `class="attstrip`, `</div>
</div>`))
	}
	// the name clips, the mark beside it stays whole
	if p := panel(); !strings.Contains(p, `<td class="mono" title="shot.png"><span class="attn"><span class="clip">shot.png</span>`+mark+`</span></td>`) {
		t.Fatalf("no mark on the row:\n%s", p)
	}
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	for _, want := range []string{".histdot { display: inline-block; width: 8px; height: 8px; background: var(--accent); }",
		".thumb .histdot { position: absolute; top: 4px; right: 4px; }",
		".attn { display: flex; align-items: center; gap: 8px; min-width: 0; }", ".attn .histdot { flex: none; }"} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %s", want)
		}
	}
}

func TestAttachmentsUploadServeRedact(t *testing.T) {
	e := setup(t)
	ed := e.do(t, "alice", "GET", fpath+"/s/Impact/edit", nil, nil).Body.String()
	for _, want := range []string{`class="attstrip`, `data-upload="/e/acme/f/001/attachments"`, `accept="image/*,text/*"`} {
		if !strings.Contains(ed, want) {
			t.Fatalf("editor lacks %s:\n%s", want, ed)
		}
	}
	img := testPNG(t, color.White)
	rec := e.sendFile(t, "alice", fpath+"/attachments", "shot one.png", img)
	if rec.Code != 200 || rec.Header().Get("X-Yars-Name") != "shot-one.png" || !strings.Contains(rec.Body.String(), "shot-one.png") {
		t.Fatalf("upload %d %q:\n%s", rec.Code, rec.Header().Get("X-Yars-Name"), rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `data-insert="![shot-one.png](attachments/shot-one.png)"`) || !strings.Contains(rec.Body.String(), `data-redact=`) {
		t.Fatalf("strip:\n%s", rec.Body.String())
	}
	noInline(t, "strip", rec.Body.String())
	if got := e.lastCommit(t); got != "alice|F-001: attach shot-one.png" {
		t.Fatalf("commit %q", got)
	}
	get := e.do(t, "bob", "GET", fpath+"/attachments/shot-one.png", nil, nil)
	if get.Code != 200 || get.Header().Get("Content-Type") != "image/png" || get.Header().Get("X-Content-Type-Options") != "nosniff" || !bytes.Equal(get.Body.Bytes(), img) {
		t.Fatalf("serve %d %q", get.Code, get.Header().Get("Content-Type"))
	}
	if rec := e.sendFile(t, "alice", fpath+"/attachments", "page.html", []byte("<html><script>alert(1)</script>")); rec.Code != 200 {
		t.Fatalf("text upload %d", rec.Code)
	}
	get = e.do(t, "bob", "GET", fpath+"/attachments/page.html", nil, nil)
	if !strings.HasPrefix(get.Header().Get("Content-Type"), "text/plain") || !strings.Contains(get.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("text served as %q csp %q", get.Header().Get("Content-Type"), get.Header().Get("Content-Security-Policy"))
	}
	if rec := e.sendFile(t, "alice", fpath+"/attachments", "a.zip", []byte("PK\x03\x04zzzz")); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("zip %d", rec.Code)
	}
	if rec := e.sendFile(t, "alice", fpath+"/attachments", "big.txt", bytes.Repeat([]byte("a"), store.MaxAttachment+10)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("big %d", rec.Code)
	}
	// redact: the redacted image replaces the file in a new commit
	black := testPNG(t, color.Black)
	rec = e.sendFile(t, "alice", fpath+"/attachments/shot-one.png/redact", "blob", black)
	if rec.Code != 200 {
		t.Fatalf("redact %d %s", rec.Code, rec.Body.String())
	}
	if got := e.lastCommit(t); got != "alice|F-001: redact shot-one.png" {
		t.Fatalf("commit %q", got)
	}
	if b := e.do(t, "bob", "GET", fpath+"/attachments/shot-one.png", nil, nil).Body.Bytes(); !bytes.Equal(b, black) {
		t.Fatal("not replaced")
	}
	// the finding page links images to the attachment route and has the
	// redact dialog
	e.srv.Store.UpdateSection("acme", "F-001-sql-injection", "Impact", "![s](attachments/shot-one.png)", "", gitrepo.Author{Name: "alice", Email: "a@x"})
	p := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(p, `src="/e/acme/f/001/attachments/shot-one.png?v=`) || !strings.Contains(p, `id="redact"`) {
		t.Fatalf("finding page:\n%s", p)
	}
	noInline(t, "finding page", p)
	// read only: an archived engagement refuses uploads
	if err := e.srv.Store.Archive("acme", config.User{Username: "dora", Role: "director"}); err != nil {
		t.Fatal(err)
	}
	if rec := e.sendFile(t, "alice", fpath+"/attachments", "x.txt", []byte("x")); rec.Code != http.StatusForbidden {
		t.Fatalf("archived %d", rec.Code)
	}
}

// A redacted image gets a new URL everywhere it is shown (strip thumbnail,
// finding page, live preview): the browser keeps an image it already
// loaded on the page for the same URL, so the original would stay visible.
func TestRedactedImageGetsNewURL(t *testing.T) {
	e := setup(t)
	re := regexp.MustCompile(`src="(/e/acme/f/001/attachments/shot\.png[^"]*)"`)
	src := func(what, html string) string {
		t.Helper()
		m := re.FindStringSubmatch(html)
		if m == nil {
			t.Fatalf("%s has no image src:\n%s", what, html)
		}
		return m[1]
	}
	strip := e.sendFile(t, "alice", fpath+"/attachments", "shot.png", testPNG(t, color.White)).Body.String()
	e.srv.Store.UpdateSection("acme", "F-001-sql-injection", "Impact", "![s](attachments/shot.png)", "", gitrepo.Author{Name: "alice", Email: "a@x"})
	preview := func() string {
		return e.do(t, "alice", "POST", "/e/acme/preview?f=F-001-sql-injection&s=Impact", url.Values{"body": {"![s](attachments/shot.png)"}}, nil).Body.String()
	}
	before := []string{src("strip", strip), src("page", e.do(t, "bob", "GET", fpath, nil, nil).Body.String()), src("preview", preview())}
	time.Sleep(10 * time.Millisecond)
	strip = e.sendFile(t, "alice", fpath+"/attachments/shot.png/redact", "blob", testPNG(t, color.Black)).Body.String()
	after := []string{src("strip", strip), src("page", e.do(t, "bob", "GET", fpath, nil, nil).Body.String()), src("preview", preview())}
	for i, what := range []string{"strip", "page", "preview"} {
		if before[i] == after[i] {
			t.Errorf("%s keeps the URL %s after a redaction", what, after[i])
		}
	}
	// the versioned URL serves the file
	if get := e.do(t, "bob", "GET", after[1], nil, nil); get.Code != 200 || !bytes.Equal(get.Body.Bytes(), testPNG(t, color.Black)) {
		t.Fatalf("versioned URL %s: %d", after[1], get.Code)
	}
}

func TestConflictDiffAndHTTPBlocks(t *testing.T) {
	e := setup(t)
	a := gitrepo.Author{Name: "carol", Email: "carol@yars.local"}
	e.srv.Store.UpdateSection("acme", "F-001-sql-injection", "Impact", "line one\ntheirs", "", a)
	rec := e.do(t, "bob", "POST", fpath+"/s/Impact", url.Values{"body": {"line one\nmine"}, "base": {"0000000000000000"}}, nil)
	c := rec.Body.String()
	for _, want := range []string{"Changed by carol", ">Show diff<", ">Mine<", `class="ln add"`, "mine", "theirs", ">Keep mine<", ">Take theirs<"} {
		if !strings.Contains(c, want) {
			t.Fatalf("conflict lacks %s:\n%s", want, c)
		}
	}
	noInline(t, "conflict", c)
	e.srv.Store.UpdateSection("acme", "F-001-sql-injection", "Impact", "```http\nGET /x HTTP/1.1\nHost: a\n```", "", a)
	p := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(p, `<pre class="http">`) || !strings.Contains(p, `<span class="h-m">GET</span>`) {
		t.Fatalf("http block:\n%s", p)
	}
}
