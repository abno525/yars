package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
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
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "mine.example") || !strings.Contains(rec.Body.String(), "The finding changed since you read it") {
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

// A refused (400) or conflicting (409) save brings back what was typed with
// every field marked, so text in any field (not only Host, which a row may
// leave empty) counts as unsaved: Cancel, Esc and leaving the page ask.
func TestAssetsRefusedMarksEveryField(t *testing.T) {
	e := setup(t)
	stale := e.assetsBase(t)
	if err := e.srv.Store.UpdateAssets("acme", "F-001-sql-injection", []finding.Asset{{Host: "other.example"}}, "", wDora); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		code int
		form url.Values
	}{
		{http.StatusBadRequest, url.Values{"base": {e.assetsBase(t)}, "n": {"1"}, "url_0": {"https://app.example/login"}, "port_0": {"http"}, "note_0": {"the login form"}}},
		{http.StatusConflict, url.Values{"base": {stale}, "n": {"1"}, "url_0": {"https://app.example/login"}, "port_0": {"8443"}, "note_0": {"mine"}}},
	} {
		rec := e.do(t, "alice", "POST", fpath+"/assets", c.form, nil)
		b := rec.Body.String()
		if rec.Code != c.code {
			t.Fatalf("code %d, want %d:\n%s", rec.Code, c.code, b)
		}
		for _, f := range []string{"host_0", "url_0", "port_0", "note_0"} {
			i := strings.Index(b, `name="`+f+`"`)
			if i < 0 || !strings.Contains(b[i:i+strings.Index(b[i:], ">")], "data-dirty") {
				t.Fatalf("%d: %s is not marked unsaved:\n%s", c.code, f, b)
			}
		}
	}
}

// Add row and Remove row draw the editor again: rows that are not what is
// saved stay unsaved (marked), so Cancel, Esc and leaving still ask; an
// empty row added to the saved list is no change.
func TestAssetsAddRemoveKeepUnsaved(t *testing.T) {
	e := setup(t)
	marked := func(b, f string) bool {
		i := strings.Index(b, `name="`+f+`"`)
		return i >= 0 && strings.Contains(b[i:i+strings.Index(b[i:], ">")], "data-dirty")
	}
	post := func(form url.Values) string {
		t.Helper()
		rec := e.do(t, "alice", "POST", fpath+"/assets", form, nil)
		if rec.Code != 200 {
			t.Fatalf("%v: %d", form, rec.Code)
		}
		return rec.Body.String()
	}
	// a URL typed, then Add row
	b := post(url.Values{"base": {e.assetsBase(t)}, "n": {"1"}, "url_0": {"https://app.example/login"}, "op": {"add"}})
	if !marked(b, "url_0") || !marked(b, "host_1") {
		t.Fatalf("typed row not unsaved after Add row:\n%s", b)
	}
	// nothing typed, Add row: no change
	if b := post(url.Values{"base": {e.assetsBase(t)}, "n": {"1"}, "op": {"add"}}); strings.Contains(b, "data-dirty") {
		t.Fatalf("an empty row marked:\n%s", b)
	}
	// a saved row removed: the one left is unsaved
	if err := e.srv.Store.UpdateAssets("acme", "F-001-sql-injection", []finding.Asset{{Host: "a.example"}, {Host: "b.example"}}, "", wDora); err != nil {
		t.Fatal(err)
	}
	b = post(url.Values{"base": {e.assetsBase(t)}, "n": {"2"}, "host_0": {"a.example"}, "host_1": {"b.example"}, "op": {"del-0"}})
	if !marked(b, "host_0") || !strings.Contains(b, `value="b.example"`) {
		t.Fatalf("removal not unsaved:\n%s", b)
	}
	// the saved rows and an empty one added: no change
	if b := post(url.Values{"base": {e.assetsBase(t)}, "n": {"2"}, "host_0": {"a.example"}, "host_1": {"b.example"}, "op": {"add"}}); strings.Contains(b, "data-dirty") || strings.Contains(b, "data-unsaved") {
		t.Fatalf("saved rows marked:\n%s", b)
	}
	// every saved row removed: the fields are empty, the form says unsaved
	// (app.js counts it so, whatever the fields hold)
	post(url.Values{"base": {e.assetsBase(t)}, "n": {"2"}, "host_0": {"a.example"}, "host_1": {"b.example"}, "op": {"del-0"}})
	b = post(url.Values{"base": {e.assetsBase(t)}, "n": {"1"}, "host_0": {"b.example"}, "op": {"del-0"}})
	if !strings.Contains(b, `data-guard data-unsaved>`) {
		t.Fatalf("all rows removed, the form is not unsaved:\n%s", b)
	}
	if js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String(); !strings.Contains(js, "form[data-guard][data-unsaved]") {
		t.Fatal("app.js does not count a form marked unsaved")
	}
	// a saved list not in its cleaned form (a push may keep an empty or
	// spaced row): the same rows drawn again are no change
	if assetsDirty([]finding.Asset{{Host: "a.example"}, {}}, []finding.Asset{{Host: "a.example"}, {Note: " "}}, "") {
		t.Fatal("a saved list with an empty row counts as changed")
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
	// title row: Merge into (in More, D4) for directors only
	if p := e.do(t, "dora", "GET", "/e/acme/f/002", nil, nil).Body.String(); !strings.Contains(between(p, `<details class="pop more">`, "</details>"), `href="/e/acme/f/002/merge">Merge into</a>`) {
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
	// what does not move is listed: none yet, so the panel holds its empty row
	stays := between(b, `<h2>Not moved</h2>`, "</section>")
	if !strings.Contains(stays, `class="emptyrow"`) {
		t.Fatalf("empty Not moved panel:\n%s", stays)
	}
	if err := e.srv.Store.UpdateDetails("acme", src.Dir, map[string]string{"Location": "/export"}, "", a); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Store.UpdateCVSS("acme", src.Dir, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", nil, "", a); err != nil {
		t.Fatal(err)
	}
	was, _ := e.srv.Store.Finding("acme", fdir)
	b = e.do(t, "dora", "GET", "/e/acme/f/002/merge", nil, nil).Body.String()
	stays = between(b, `<h2>Not moved</h2>`, "</section>")
	for _, want := range []string{`<th scope="row">Location</th><td class="text">/export</td>`, `<th scope="row">CVSS</th><td class="mono">CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H · 9.8</td>`} {
		if !strings.Contains(stays, want) {
			t.Fatalf("Not moved lacks %s:\n%s", want, stays)
		}
	}
	if strings.Contains(stays, `class="emptyrow"`) {
		t.Fatalf("empty row beside rows:\n%s", stays)
	}
	defer func() { // the target keeps its own details rows and CVSS
		now, _ := e.srv.Store.Finding("acme", fdir)
		if now.F.Meta.CVSS != was.F.Meta.CVSS || now.F.Meta.Details["Location"] != was.F.Meta.Details["Location"] {
			t.Errorf("target took the source's: cvss %q details %v", now.F.Meta.CVSS, now.F.Meta.Details)
		}
	}()
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
	if !strings.Contains(p, "Merged from F-002") || !strings.Contains(p, "x.example") || !strings.Contains(p, `class="chatev ev-merge"`) {
		t.Fatalf("target after merge:\n%s", p)
	}
}
