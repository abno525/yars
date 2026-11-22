package web

import (
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/db"
	"yars/internal/store"
	"yars/internal/workflow"
)

func TestNewRetestFlow(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	e.srv.Store.CreateFinding("acme", "Open redirect", e.authorOf(wAlice))
	if rec := e.do(t, "alice", "GET", "/e/acme/retest/new", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pentester form code %d", rec.Code)
	}
	b := e.do(t, "dora", "GET", "/e/acme/retest/new", nil, nil).Body.String()
	// the complete finding is pre-selected, the draft isn't
	if !strings.Contains(b, `id="pick-F-001-sql-injection" checked`) || strings.Contains(b, `id="pick-F-002-open-redirect" checked`) {
		t.Fatalf("form selection:\n%s", b)
	}
	if !strings.Contains(b, `value="acme-retest"`) || !strings.Contains(b, `name="assignee"`) {
		t.Fatal("id not prefilled or no retester field")
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/retest/new", url.Values{"id": {"x"}, "name": {"X"}, "finding": {"F-001-sql-injection"}, "assignee": {"mallory"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown assignee code %d", rec.Code)
	}
	form := url.Values{"id": {"acme-rt"}, "name": {"ACME retest"}, "finding": {"F-001-sql-injection", "F-002-open-redirect"}}
	rec := e.do(t, "dora", "POST", "/e/acme/retest/new", form, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme-rt" {
		t.Fatalf("code %d loc %q body %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	b = e.do(t, "alice", "GET", "/e/acme-rt", nil, nil).Body.String()
	if !strings.Contains(b, "Retest of") || !strings.Contains(b, `href="/e/acme"`) || !strings.Contains(b, "Open redirect") || !strings.Contains(b, `<th class="col-result"><a`) || !strings.Contains(b, ">Result") {
		t.Fatalf("retest engagement page:\n%s", b)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/retest/new", url.Values{"id": {"x"}, "name": {"X"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty selection code %d", rec.Code)
	}
}

// The New retest picker has its head above its table, as the export picker
// does (TestExportPickHeadFirst): first in the page, with the count of ticked
// findings rendered by the server.
func TestNewRetestPickHeadFirst(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	e.srv.Store.CreateFinding("acme", "Open redirect", e.authorOf(wAlice))
	b := e.do(t, "dora", "GET", "/e/acme/retest/new", nil, nil).Body.String()
	panel := between(b, `<section class="panel pickpanel">`, "</section>")
	head, table := strings.Index(panel, `class="panelhead"`), strings.Index(panel, "<table")
	if head < 0 || table < 0 || head > table {
		t.Fatalf("pick panel order:\n%s", panel)
	}
	if !strings.Contains(panel, `<span class="mono selof" data-of="2">1 of 2</span>`) {
		t.Fatalf("no count in the head:\n%s", panel)
	}
}

func TestRetestPanel(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.CreateRetest(store.Engagement{ID: "rt", Name: "RT"}, "acme", []string{"F-001-sql-injection"}, "", wDora); err != nil {
		t.Fatal(err)
	}
	p := "/e/rt/f/F-001-sql-injection"
	b := e.do(t, "alice", "GET", p, nil, nil).Body.String()
	if !strings.Contains(b, `id="retest"`) || !strings.Contains(b, `href="/e/acme/f/001"`) {
		t.Fatalf("retest panel missing:\n%s", b)
	}
	rec := e.do(t, "alice", "POST", p+"/retest", url.Values{"result": {"partially_fixed"}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `value="partially_fixed" checked`) {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("HX-Refresh") != "true" {
		t.Fatal("result change doesn't refresh the page (workflow bar/gate stay stale)")
	}
	if rec := e.do(t, "alice", "POST", p+"/retest", url.Values{"result": {"maybe"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid result code %d", rec.Code)
	}
	if b := e.do(t, "alice", "GET", "/e/rt", nil, nil).Body.String(); !strings.Contains(b, "Partially fixed") {
		t.Fatal("table lacks result pill")
	}
	// the original finding page has no retest panel
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); strings.Contains(b, `id="retest"`) {
		t.Fatal("retest panel on original")
	}
}

// A retest whose source names no finding (no "/": only `yars migrate` of a
// hand-edited file can store one) shows the original as missing, not an
// empty link and status (backlog, M7).
func TestRetestSourceWithoutFinding(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.CreateRetest(store.Engagement{ID: "rt", Name: "RT"}, "acme", []string{"F-001-sql-injection"}, "", wDora); err != nil {
		t.Fatal(err)
	}
	d := e.srv.Store.DB()
	st, err := d.State("rt", "F-001")
	if err != nil {
		t.Fatal(err)
	}
	st.RetestSource = "acme"
	if err := d.TxFor("rt", func(tx *db.Tx) error { return tx.PutState("rt", "F-001", st) }); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/e/rt/f/F-001-sql-injection", nil, nil).Body.String()
	i := strings.Index(b, `id="retest"`)
	if i < 0 {
		t.Fatal("no retest panel")
	}
	orig := b[i:]
	orig = orig[:strings.Index(orig, "</summary>")]
	if strings.Contains(orig, `href=""`) || strings.Contains(orig, `class="tag status-"`) || !strings.Contains(orig, `<span class="slot w96"></span>`) {
		t.Fatalf("the original's head:\n%s", orig)
	}
}

// The result form says which result it showed: a choice made on a page
// that is out of date (someone set another result since) is refused, and
// the panel comes back with the result as it is now (backlog, M7).
func TestRetestResultBase(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.CreateRetest(store.Engagement{ID: "rt", Name: "RT"}, "acme", []string{"F-001-sql-injection"}, "", wDora); err != nil {
		t.Fatal(err)
	}
	p := "/e/rt/f/F-001-sql-injection"
	if b := e.do(t, "alice", "GET", p, nil, nil).Body.String(); !strings.Contains(b, `<input type="hidden" name="was" value="">`) {
		t.Fatal("the form does not say which result it shows")
	}
	if rec := e.do(t, "alice", "POST", p+"/retest", url.Values{"result": {"fixed"}, "was": {""}}, nil); rec.Code != http.StatusOK {
		t.Fatalf("first choice: %d", rec.Code)
	}
	// bob's page still shows no result
	rec := e.do(t, "bob", "POST", p+"/retest", url.Values{"result": {"not_fixed"}, "was": {""}}, nil)
	b := rec.Body.String()
	if rec.Code != http.StatusConflict || !strings.Contains(b, "the result changed since you opened the page") || !strings.Contains(b, `value="fixed" checked`) || !strings.Contains(b, `name="was" value="fixed"`) {
		t.Fatalf("a choice on an old page: %d\n%s", rec.Code, b)
	}
	if rec := e.do(t, "bob", "POST", p+"/retest", url.Values{"result": {"not_fixed"}, "was": {"fixed"}}, nil); rec.Code != http.StatusOK {
		t.Fatalf("a choice on the current page: %d", rec.Code)
	}
	// the result someone already chose (or a second click) is no conflict
	if rec := e.do(t, "alice", "POST", p+"/retest", url.Values{"result": {"not_fixed"}, "was": {"fixed"}}, nil); rec.Code != http.StatusOK {
		t.Fatalf("the result already chosen: %d", rec.Code)
	}
}

// A retest that fails for a reason other than the form's (here the disk)
// answers the form again with what was typed and a line saying so, not a
// bare "internal error" (backlog, M7).
func TestRetestCreateFailureKeepsForm(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into read-only folders")
	}
	e := setup(t)
	engs := filepath.Join(e.dir, "engagements")
	if err := os.Chmod(engs, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(engs, 0o755) })
	form := url.Values{"id": {"acme-rt2"}, "name": {"Second look"}, "finding": {"F-001-sql-injection"}}
	rec := e.do(t, "dora", "POST", "/e/acme/retest/new", form, nil)
	b := rec.Body.String()
	if rec.Code != http.StatusInternalServerError || !strings.Contains(b, "<html") || !strings.Contains(b, "the retest could not be created; try again") || !strings.Contains(b, `value="Second look"`) {
		t.Fatalf("code %d:\n%s", rec.Code, b)
	}
}

// Q13: an attachment over the read limit (written into the repository by
// hand) is named in the New retest form with the limit, not "try again".
func TestRetestOversizeAttachmentForm(t *testing.T) {
	e := setup(t)
	big := filepath.Join(e.dir, "engagements", "acme", "findings", fdir, "attachments", "dump.png")
	if err := os.MkdirAll(filepath.Dir(big), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(20<<20 + 1)
	f.Close()
	form := url.Values{"id": {"acme-rt"}, "name": {"Second look"}, "finding": {fdir}}
	rec := e.do(t, "dora", "POST", "/e/acme/retest/new", form, nil)
	b := rec.Body.String()
	if rec.Code != http.StatusBadRequest || !strings.Contains(between(b, `<div class="errslot">`, "</div>"), ">finding F-001-sql-injection: attachment dump.png is larger than 20 MB</p>") || !strings.Contains(b, `value="Second look"`) {
		t.Fatalf("code %d:\n%s", rec.Code, b)
	}
}

// A retest engagement with no source (only a hand edit on the server makes
// one: the website and pushes refuse it) names none in its head, instead of
// linking to /e/ (backlog, M7).
func TestRetestHeadWithoutSource(t *testing.T) {
	e := setup(t)
	repo := filepath.Join(e.dir, "engagements", "acme")
	f := filepath.Join(repo, "engagement.yaml")
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "type: pentest") {
		t.Fatalf("engagement.yaml:\n%s", b)
	}
	if err := os.WriteFile(f, []byte(strings.Replace(string(b), "type: pentest", "type: retest", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "hand edit").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	e.srv.Store.Invalidate("acme")
	page := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String()
	if !strings.Contains(page, "Retest of") || strings.Contains(page, `href="/e/"`) {
		t.Fatalf("the head links nowhere:\n%s", page)
	}
}

func TestRetestPanelLocked(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	st.CreateRetest(store.Engagement{ID: "rt", Name: "RT"}, "acme", []string{"F-001-sql-injection"}, "", wDora)
	d := "F-001-sql-injection"
	st.SetRetestResult("rt", d, "fixed", wDora)
	st.SetReviewers("rt", d, []string{"bob"}, wDora)
	st.UpdateSeverity("rt", d, "high", "", wDora)
	if err := st.Transition("rt", d, workflow.Submit, "", wDora); err != nil {
		t.Fatal(err)
	}
	st.Transition("rt", d, workflow.Clear, "", wBob)
	if err := st.Transition("rt", d, workflow.Approve, "", wDora); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "alice", "POST", "/e/rt/f/"+d+"/retest", url.Values{"result": {"not_fixed"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("locked code %d", rec.Code)
	}
}
