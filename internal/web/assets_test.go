package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/store"
	"yars/internal/workflow"
)

// assetsBase is the current asset base of F-001.
func (e *env) assetsBase(t *testing.T) string {
	t.Helper()
	ref, err := e.srv.Store.Finding("acme", "F-001-sql-injection")
	if err != nil {
		t.Fatal(err)
	}
	return store.AssetsHash(ref.F.Meta)
}

func TestAssetsPanelAndEditor(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	for _, want := range []string{`id="assets"`, ">Affected assets<", ">Host</th>", ">URL</th>", ">Port</th>", ">Note</th>", `class="badge0">0<`} {
		if !strings.Contains(b, want) {
			t.Fatalf("finding page lacks %s", want)
		}
	}
	ed := e.do(t, "alice", "GET", fpath+"/assets/edit", nil, nil)
	if ed.Code != 200 || !strings.Contains(ed.Body.String(), `name="host_0"`) || !strings.Contains(ed.Body.String(), `name="base"`) {
		t.Fatalf("editor %d:\n%s", ed.Code, ed.Body.String())
	}
	noInline(t, "assets editor", ed.Body.String())
	base := e.assetsBase(t)
	// Add row keeps what was typed and commits nothing
	form := url.Values{"base": {base}, "n": {"1"}, "host_0": {"app.example"}, "port_0": {"443"}, "op": {"add"}}
	rec := e.do(t, "alice", "POST", fpath+"/assets", form, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `name="host_1"`) || !strings.Contains(rec.Body.String(), `value="app.example"`) {
		t.Fatalf("add row %d:\n%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(e.lastCommit(t), "assets") {
		t.Fatal("add row committed")
	}
	// Remove drops the row
	form = url.Values{"base": {base}, "n": {"2"}, "host_0": {"gone.example"}, "host_1": {"kept.example"}, "op": {"del-0"}}
	rec = e.do(t, "alice", "POST", fpath+"/assets", form, nil)
	if b := rec.Body.String(); strings.Contains(b, "gone.example") || !strings.Contains(b, "kept.example") {
		t.Fatalf("remove:\n%s", b)
	}
	// Save
	form = url.Values{"base": {base}, "n": {"2"}, "host_0": {"app.example"}, "port_0": {"443"}, "url_1": {"https://app.example/search"}, "note_1": {"q"}}
	rec = e.do(t, "alice", "POST", fpath+"/assets", form, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "https://app.example/search") || !strings.Contains(rec.Body.String(), `class="badge">2<`) {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	if got := e.lastCommit(t); got != "alice|F-001: edit assets" {
		t.Fatalf("commit %q", got)
	}
	noInline(t, "assets panel", rec.Body.String())
	// a stale base: 409, the typed rows stay
	form.Set("host_0", "mine.example")
	rec = e.do(t, "alice", "POST", fpath+"/assets", form, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "mine.example") || !strings.Contains(rec.Body.String(), "Assets changed by someone else") {
		t.Fatalf("conflict %d:\n%s", rec.Code, rec.Body.String())
	}
	// invalid: 400 with the reason
	form = url.Values{"base": {e.assetsBase(t)}, "n": {"1"}, "host_0": {"a.example"}, "port_0": {"http"}}
	rec = e.do(t, "alice", "POST", fpath+"/assets", form, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "port") {
		t.Fatalf("invalid %d:\n%s", rec.Code, rec.Body.String())
	}
	// locked: withdrawn
	if err := e.srv.Store.Transition("acme", "F-001-sql-injection", workflow.Withdraw, "dup", config.User{Username: "dora", Role: "director"}); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "alice", "GET", fpath+"/assets/edit", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("locked edit %d", rec.Code)
	}
}

func TestDuplicates(t *testing.T) {
	e := setup(t)
	nf := e.do(t, "alice", "GET", "/e/acme/findings/new", nil, nil).Body.String()
	if !strings.Contains(nf, `hx-get="/e/acme/findings/new/dups"`) || !strings.Contains(nf, "delay:") || !strings.Contains(nf, `id="dups"`) {
		t.Fatalf("new finding page lacks the duplicate check:\n%s", nf)
	}
	b := e.do(t, "alice", "GET", "/e/acme/findings/new/dups?title=sql+injection", nil, nil).Body.String()
	for _, want := range []string{"F-001", "100%", ">ID</th>", ">Similarity</th>", `class="badge">1<`, `href="/e/acme/f/001"`} {
		if !strings.Contains(b, want) {
			t.Fatalf("dups lack %s:\n%s", want, b)
		}
	}
	noInline(t, "dups", b)
	b = e.do(t, "alice", "GET", "/e/acme/findings/new/dups?title=zzzz", nil, nil).Body.String()
	if strings.Contains(b, "F-001") || !strings.Contains(b, `class="badge0">0<`) || !strings.Contains(b, ">ID</th>") {
		t.Fatalf("no dups:\n%s", b)
	}
	// on the finding page: each one shows the other
	a := gitrepo.Author{Name: "alice", Email: "alice@yars.local"}
	ref, err := e.srv.Store.CreateFinding("acme", "SQL injection", a)
	if err != nil {
		t.Fatal(err)
	}
	p := e.do(t, "alice", "GET", "/e/acme/f/002", nil, nil).Body.String()
	if !strings.Contains(p, `id="dups"`) || !strings.Contains(p, `href="/e/acme/f/001"`) {
		t.Fatalf("finding page dups:\n%s", p)
	}
	p = e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(p, `href="/e/acme/f/002"`) {
		t.Fatalf("F-001 does not list F-002")
	}
	// a director gets Merge on each row
	p = e.do(t, "dora", "GET", "/e/acme/f/002", nil, nil).Body.String()
	if !strings.Contains(p, `href="/e/acme/f/002/merge?into=F-001-sql-injection"`) {
		t.Fatalf("no merge link for a director:\n%s", p)
	}
	_ = ref
}

func TestMergePage(t *testing.T) {
	e := setup(t)
	a := gitrepo.Author{Name: "alice", Email: "alice@yars.local"}
	src, err := e.srv.Store.CreateFinding("acme", "SQL injection in export", a)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Store.UpdateSection("acme", src.Dir, "Impact", "Export leaks.", "", a)
	e.srv.Store.UpdateAssets("acme", src.Dir, []finding.Asset{{Host: "x.example"}}, "", a)
	// title row: Merge into for directors only
	if p := e.do(t, "dora", "GET", "/e/acme/f/002", nil, nil).Body.String(); !strings.Contains(p, `class="btn secondary w136" href="/e/acme/f/002/merge"`) {
		t.Fatalf("no Merge into for a director:\n%s", p)
	}
	if p := e.do(t, "alice", "GET", "/e/acme/f/002", nil, nil).Body.String(); strings.Contains(p, "/merge") {
		t.Fatal("Merge into for a pentester")
	}
	if rec := e.do(t, "alice", "GET", "/e/acme/f/002/merge", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pentester merge page %d", rec.Code)
	}
	rec := e.do(t, "dora", "GET", "/e/acme/f/002/merge?into=F-001-sql-injection", nil, nil)
	b := rec.Body.String()
	for _, want := range []string{"Merge F-002 into", `value="F-001-sql-injection" checked`, ">ID</th>", ">Title</th>", ">Part</th>", "Affected assets", ">1<"} {
		if !strings.Contains(b, want) {
			t.Fatalf("merge page lacks %s:\n%s", want, b)
		}
	}
	if strings.Contains(b, `value="`+src.Dir+`"`) {
		t.Fatal("the finding itself is a target")
	}
	noInline(t, "merge page", b)
	if rec := e.do(t, "dora", "POST", "/e/acme/f/002/merge", url.Values{}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("no target %d", rec.Code)
	}
	rec = e.do(t, "dora", "POST", "/e/acme/f/002/merge", url.Values{"into": {"F-001-sql-injection"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/f/001" {
		t.Fatalf("merge %d %q:\n%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if st := e.statusOf(t, "acme", src.Dir); st != "withdrawn" {
		t.Fatalf("source %s", st)
	}
	p := e.do(t, "dora", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(p, "Merged from F-002") || !strings.Contains(p, "x.example") || !strings.Contains(p, `class="event ev-merge"`) {
		t.Fatalf("target after merge:\n%s", p)
	}
}
