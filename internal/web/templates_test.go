package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

// addTemplate stores a template with a description and a low severity.
func (e *env) addTemplate(t *testing.T, slug, title string) {
	t.Helper()
	st := e.srv.Store
	err := st.SaveTemplate(slug, e.authorOf(wDora), func(*finding.Finding) (*finding.Finding, error) {
		f := st.NewTemplate(title)
		f.SetSection("Description", "The server does not send "+title+".")
		if err := f.SetMeta("cvss", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"); err != nil {
			return nil, err
		}
		return f, f.SetMeta("severity", "low")
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The bar over the templates list bottom-aligns its items (.filterbar, made
// for Activity's labelled fields): the "N of M" count is a 40px slot whose
// text is centred, level with the 40px search field and Search beside it,
// not resting on their bottom edge.
func TestTemplatesCountLevel(t *testing.T) {
	e := setup(t)
	e.addTemplate(t, "missing-hsts", "Missing HSTS")
	b := e.do(t, "dora", "GET", "/templates", nil, nil).Body.String()
	bar := between(b, `<form class="filterbar" method="get" action="/templates">`, "</form>")
	if !strings.Contains(bar, `<span class="mono slot">1 of 1</span>`) {
		t.Fatalf("templates bar:\n%s", bar)
	}
	css := e.do(t, "dora", "GET", staticPrefix()+"/style.css", nil, nil).Body.String()
	if f := between(css, "\n.filterbar {", "}"); !strings.Contains(f, "align-items: flex-end;") {
		t.Fatalf(".filterbar: %q", f)
	}
	if s := between(css, "\n.slot {", "}"); !strings.Contains(s, "display: inline-flex; align-items: center;") || !strings.Contains(s, "min-height: 40px;") {
		t.Fatalf(".slot: %q", s)
	}
}

// A template shows its version, owner (who made it) and last edit from
// git; History lists every version.
func TestTemplateOwnerAndVersions(t *testing.T) {
	e := setupSerial(t) // counts git processes
	if rec := e.do(t, "bob", "POST", "/templates/new", url.Values{"title": {"SQL injection"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("create %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/templates/sql-injection", url.Values{"title": {"SQL injection"}, "severity": {"high"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d %s", rec.Code, rec.Body.String())
	}
	today := time.Now().Format("2006-01-02")
	b := e.do(t, "alice", "GET", "/templates", nil, nil).Body.String()
	for _, want := range []string{`<span class="tplver mono">v2</span>`, ">Last edited</th>", ">Owner</th>", `<td class="mono edited">` + today + ` · dora</td>`, `<td class="owner" title="bob">bob</td>`} {
		if !strings.Contains(b, want) {
			t.Fatalf("list lacks %q:\n%s", want, b)
		}
	}
	noInline(t, "templates", b)
	p := e.do(t, "alice", "GET", "/templates/sql-injection", nil, nil).Body.String()
	for _, want := range []string{`<span class="idchip">v2</span>`, `Used 0 · dora · ` + today, `<a class="btn secondary w128" href="/templates/sql-injection/history" aria-keyshortcuts="Shift+H">History</a>`, "Owner bob"} {
		if !strings.Contains(p, want) {
			t.Fatalf("template page lacks %q:\n%s", want, p)
		}
	}
	rec := e.do(t, "alice", "GET", "/templates/sql-injection/history", nil, nil)
	h := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("history %d", rec.Code)
	}
	for _, want := range []string{"<thead>", ">Version</th>", ">Date</th>", ">Author</th>", ">Change</th>", ">v2</td>", ">v1</td>", "templates: save sql-injection"} {
		if !strings.Contains(h, want) {
			t.Fatalf("history lacks %q:\n%s", want, h)
		}
	}
	if strings.Index(h, ">v2</td>") > strings.Index(h, ">v1</td>") {
		t.Fatal("history not newest first")
	}
	noInline(t, "template history", h)
	if rec := e.do(t, "alice", "GET", "/templates/nope/history", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown template history %d", rec.Code)
	}
	// the list reads git once per change of the main repo
	before := gitrepo.Spawned()
	e.do(t, "alice", "GET", "/templates", nil, nil)
	if n := gitrepo.Spawned() - before; n != 0 {
		t.Fatalf("%d git processes for the templates page", n)
	}
}

func TestTemplatesPage(t *testing.T) {
	e := setup(t)
	e.addTemplate(t, "missing-hsts", "Missing HSTS header")
	e.srv.Store.CreateFindingFrom("acme", "HSTS on api", "missing-hsts", e.authorOf(wAlice))
	// everyone reads
	rec := e.do(t, "alice", "GET", "/templates", nil, nil)
	b := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, "Missing HSTS header") || !strings.Contains(b, `class="tag sev-low"`) || !strings.Contains(b, "<th") {
		t.Fatalf("code %d:\n%s", rec.Code, b)
	}
	if !strings.Contains(b, `<span class="badge">1</span>`) {
		t.Fatalf("usage badge missing:\n%s", b)
	}
	noInline(t, "templates", b)
	// pentesters don't get New template; the slot keeps its place
	if strings.Contains(b, `action="/templates/new"`) || !strings.Contains(b, `class="slot w152"`) {
		t.Fatalf("pentester sees New template:\n%s", b)
	}
	if b := e.do(t, "bob", "GET", "/templates", nil, nil).Body.String(); !strings.Contains(b, `action="/templates/new"`) {
		t.Fatalf("reviewer lacks New template:\n%s", b)
	}
	if rec := e.do(t, "alice", "POST", "/templates/new", url.Values{"title": {"Open redirect"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pentester create %d", rec.Code)
	}
	rec = e.do(t, "bob", "POST", "/templates/new", url.Values{"title": {"Open redirect"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/templates/open-redirect" {
		t.Fatalf("create %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if _, err := e.srv.Store.Template("open-redirect"); err != nil {
		t.Fatal(err)
	}
}

func TestTemplateEdit(t *testing.T) {
	e := setup(t)
	e.addTemplate(t, "hsts", "Missing HSTS header")
	b := e.do(t, "dora", "GET", "/templates/hsts", nil, nil).Body.String()
	if !strings.Contains(b, `hx-get="/templates/hsts/s/Description/edit"`) || !strings.Contains(b, `value="Missing HSTS header"`) {
		t.Fatalf("editor page:\n%s", b)
	}
	noInline(t, "template edit", b)
	// a pentester reads only
	if b := e.do(t, "alice", "GET", "/templates/hsts", nil, nil).Body.String(); strings.Contains(b, "/s/Description/edit") || strings.Contains(b, `action="/templates/hsts"`) {
		t.Fatalf("pentester can edit:\n%s", b)
	}
	if rec := e.do(t, "alice", "GET", "/templates/hsts/s/Description/edit", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pentester editor %d", rec.Code)
	}
	ed := e.do(t, "dora", "GET", "/templates/hsts/s/Description/edit", nil, nil).Body.String()
	if !strings.Contains(ed, `hx-post="/templates/hsts/s/Description"`) || !strings.Contains(ed, `hx-post="/preview"`) {
		t.Fatalf("section editor:\n%s", ed)
	}
	tp, _ := e.srv.Store.Template("hsts")
	body, _ := tp.F.Section("Description")
	rec := e.do(t, "dora", "POST", "/templates/hsts/s/Description", url.Values{"body": {"Send HSTS."}, "base": {store.BodyHash(body)}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Send HSTS.") {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	if rec := e.do(t, "dora", "POST", "/templates/hsts/s/Description", url.Values{"body": {"x"}, "base": {store.BodyHash(body)}}, nil); rec.Code != http.StatusConflict {
		t.Fatalf("stale save %d", rec.Code)
	}
	// title, severity and vector
	rec = e.do(t, "dora", "POST", "/templates/hsts", url.Values{"title": {"HSTS missing"}, "severity": {"medium"}, "cvss": {""}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("meta save %d %s", rec.Code, rec.Body.String())
	}
	tp, _ = e.srv.Store.Template("hsts")
	if tp.F.Meta.Title != "HSTS missing" || tp.F.Meta.Severity != "medium" || tp.F.Meta.CVSS != "" {
		t.Fatalf("meta %+v", tp.F.Meta)
	}
	if rec := e.do(t, "dora", "POST", "/templates/hsts", url.Values{"title": {"x"}, "severity": {"huge"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad severity %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/templates/hsts", url.Values{"title": {"x"}, "severity": {"low"}, "cvss": {"CVSS:9"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad vector %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/templates/hsts/delete", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete %d", rec.Code)
	}
	if rec := e.do(t, "dora", "GET", "/templates/hsts", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("after delete %d", rec.Code)
	}
}

func TestSaveFindingAsTemplate(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	st.UpdateSection("acme", fdir, "Description", "The login form builds SQL from input.", "", e.authorOf(wAlice))
	st.UpdateDetails("acme", fdir, map[string]string{"Location": "https://acme.example/login"}, "", e.authorOf(wAlice))
	st.UpdateSeverity("acme", fdir, "high", "", e.authorOf(wAlice))
	// the finding page offers it to reviewers and directors only
	if b := e.do(t, "alice", "GET", fshort, nil, nil).Body.String(); strings.Contains(b, fshort+"/template") {
		t.Fatal("pentester sees Save as template")
	}
	if b := e.do(t, "bob", "GET", fshort, nil, nil).Body.String(); !strings.Contains(b, `href="`+fshort+`/template"`) {
		t.Fatalf("reviewer lacks Save as template:\n%s", b)
	}
	if rec := e.do(t, "alice", "GET", fshort+"/template", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pentester form %d", rec.Code)
	}
	b := e.do(t, "bob", "GET", fshort+"/template", nil, nil).Body.String()
	if !strings.Contains(b, `value="SQL injection"`) || !strings.Contains(b, `name="strip"`) {
		t.Fatalf("form:\n%s", b)
	}
	noInline(t, "save as template", b)
	rec := e.do(t, "bob", "POST", fshort+"/template", url.Values{"title": {"SQL injection"}, "strip": {"details"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/templates/sql-injection" {
		t.Fatalf("save %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	tp, err := st.Template("sql-injection")
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := tp.F.Section("Description"); !strings.Contains(d, "builds SQL") || tp.F.Meta.Severity != "high" || len(tp.F.Meta.Details) != 0 || tp.F.Meta.ID != "" || tp.F.Meta.Author != "" {
		t.Fatalf("template %+v", tp.F.Meta)
	}
	// an existing name is refused
	if rec := e.do(t, "bob", "POST", fshort+"/template", url.Values{"title": {"SQL injection"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate %d", rec.Code)
	}
	// another title with the same slug gets a free one
	rec = e.do(t, "bob", "POST", fshort+"/template", url.Values{"title": {"SQL injection!"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/templates/sql-injection-2" {
		t.Fatalf("same slug %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
}

func TestNewFindingFromTemplate(t *testing.T) {
	e := setup(t)
	e.addTemplate(t, "missing-hsts", "Missing HSTS header")
	e.addTemplate(t, "verbose-errors", "Verbose error pages")
	b := e.do(t, "alice", "GET", "/e/acme/findings/new", nil, nil).Body.String()
	for _, want := range []string{`name="mode" value="template" checked`, `name="mode" value="blank"`, `name="q"`, "<th", "Missing HSTS header", "Verbose error pages", `class="tplpreview`, `class="btn secondary w128"`, `class="btn primary w128"`, `>2 of 2</span>`} {
		if !strings.Contains(b, want) {
			t.Fatalf("missing %q:\n%s", want, b)
		}
	}
	noInline(t, "new finding", b)
	// search narrows the list; the chosen one previews
	b = e.do(t, "alice", "GET", "/e/acme/findings/new?q=hsts&t=missing-hsts", nil, nil).Body.String()
	if strings.Contains(b, "Verbose error pages") || !strings.Contains(b, `value="missing-hsts" checked`) || !strings.Contains(b, "The server does not send Missing HSTS header.") {
		t.Fatalf("search/preview:\n%s", b)
	}
	frag := e.do(t, "alice", "GET", "/e/acme/findings/new/templates?q=verbose", nil, map[string]string{"HX-Request": "true"}).Body.String()
	if strings.Contains(frag, "<html") || strings.Contains(frag, "Missing HSTS") || !strings.Contains(frag, "Verbose error pages") {
		t.Fatalf("list fragment:\n%s", frag)
	}
	pv := e.do(t, "alice", "GET", "/e/acme/findings/new/preview?t=verbose-errors", nil, map[string]string{"HX-Request": "true"}).Body.String()
	if strings.Contains(pv, "<html") || !strings.Contains(pv, "Verbose error pages.") {
		t.Fatalf("preview fragment:\n%s", pv)
	}
	rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"HSTS on api"}, "mode": {"template"}, "template": {"missing-hsts"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	ref, err := e.srv.Store.Finding("acme", "2")
	if err != nil {
		t.Fatal(err)
	}
	if ref.F.Meta.Extra["template"] != "missing-hsts" || ref.F.Meta.Severity != "low" {
		t.Fatalf("meta %+v", ref.F.Meta)
	}
	// blank ignores a picked template
	e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"Plain"}, "mode": {"blank"}, "template": {"missing-hsts"}}, nil)
	if ref, _ := e.srv.Store.Finding("acme", "3"); ref.F.Meta.Extra["template"] != nil {
		t.Fatalf("blank used the template: %+v", ref.F.Meta)
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"x"}, "mode": {"template"}, "template": {"nope"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown template %d", rec.Code)
	}
}
