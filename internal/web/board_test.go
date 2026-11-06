package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"yars/internal/chat"
	"yars/internal/workflow"
)

// between returns the HTML from the first from to the next to after it.
func between(b, from, to string) string {
	i := strings.Index(b, from)
	if i < 0 {
		return ""
	}
	j := strings.Index(b[i:], to)
	if j < 0 {
		return b[i:]
	}
	return b[i : i+j]
}

// The board: status filters with counts (withdrawn too), progress and
// severity bars, black 0 chat badges, 0.0 for findings without a score.
func TestBoardCountsAndBars(t *testing.T) {
	e := setup(t)
	e.toVerification(t) // F-001: high, verification
	d2 := e.second(t, "alice")
	if _, err := e.srv.Store.PostChat("acme", d2, chat.Message{Text: "PoC?", Section: "Impact"}, wBob); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String()
	seg := between(b, `class="seg`, "</nav>")
	for _, want := range []string{">All · 2<", ">Draft · 1<", ">Verification · 1<", ">Signed off · 0<", ">Complete · 0<", ">Reported · 0<", ">Withdrawn · 0<"} {
		if !strings.Contains(seg, want) {
			t.Fatalf("filters lack %q:\n%s", want, seg)
		}
	}
	bars := between(b, `class="bars"`, "</section>")
	for _, want := range []string{"0 of 2 reported", "2 findings", `class="seg-verification"`, `class="seg-high"`, ">Critical<", ">0<"} {
		if !strings.Contains(bars, want) {
			t.Fatalf("bars lack %q:\n%s", want, bars)
		}
	}
	tbl := between(b, `id="findings"`, "</table>")
	if !strings.Contains(between(tbl, "F-002", "</tr>"), `class="badge">1<`) || !strings.Contains(between(tbl, "F-001", "</tr>"), `class="badge0">0<`) {
		t.Fatalf("chat badges:\n%s", tbl)
	}
	if !strings.Contains(between(tbl, "F-002", "</tr>"), `class="num">0.0<`) {
		t.Fatalf("no 0.0 score:\n%s", tbl)
	}
	if !strings.Contains(between(tbl, "F-001", "</tr>"), `class="rv"`) {
		t.Fatalf("reviewer without clearance mark:\n%s", tbl)
	}
	// withdrawn: counted in its filter only
	e.do(t, "alice", "POST", fpath+"/action/withdraw", url.Values{"reason": {"dup"}}, nil)
	b = e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String()
	seg = between(b, `class="seg`, "</nav>")
	if !strings.Contains(seg, ">All · 1<") || !strings.Contains(seg, ">Withdrawn · 1<") || !strings.Contains(between(b, `class="bars"`, "</section>"), "1 finding<") {
		t.Fatalf("after withdraw:\n%s", b)
	}
}

func TestBoardClearedReviewer(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	if err := e.srv.Store.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	tbl := between(e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(), `id="findings"`, "</table>")
	if !strings.Contains(tbl, `class="rv cleared"`) {
		t.Fatalf("cleared reviewer:\n%s", tbl)
	}
}

// Inbox groups carry counts; only directors get checkboxes and the bulk bar.
func TestInboxGroupsAndBulkBar(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	b := e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String()
	if !strings.Contains(b, `Awaiting my review <span class="qcnt">1</span>`) || !strings.Contains(b, `Open threads on my findings <span class="qcnt zero">0</span>`) || !strings.Contains(b, `<th class="title">Title</th>`) {
		t.Fatalf("group counts:\n%s", b)
	}
	if strings.Count(b, `<a class="on"`) != 1 || !strings.Contains(b, `<a class="on" href="/inbox">`) {
		t.Fatalf("only Inbox is the active nav item:\n%s", b)
	}
	if strings.Contains(b, `class="fbulk"`) || strings.Contains(b, `name="id"`) || strings.Contains(b, "Ready to approve") {
		t.Fatalf("reviewer sees director parts:\n%s", b)
	}
	e.srv.Store.Transition("acme", fdir, workflow.Clear, "", wBob)
	b = e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String()
	for _, want := range []string{`class="fbulk"`, `value="approve"`, `value="report"`, `value="reviewers"`, `name="reviewer" value="carol"`, `name="id" value="acme/F-001-sql-injection"`, `Ready to approve <span class="qcnt">1</span>`} {
		if !strings.Contains(b, want) {
			t.Fatalf("director inbox lacks %s:\n%s", want, b)
		}
	}
}

// An htmx bulk post from the inbox swaps the bar and the queues: rows keep
// their place, a moved row says what it is now, the bar sums up.
func TestInboxBulkSwap(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	e.srv.Store.Transition("acme", fdir, workflow.Clear, "", wBob)
	d2 := e.second(t, "alice")
	hx := map[string]string{"HX-Request": "true"}
	form := url.Values{"action": {"approve"}, "id": {"acme/" + fdir, "acme/" + d2}}
	rec := e.do(t, "dora", "POST", "/inbox/bulk", form, hx)
	b := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, `class="fbulkform"`) || strings.Contains(b, "<html") {
		t.Fatalf("code %d:\n%s", rec.Code, b)
	}
	r := row(b, "acme/"+fdir)
	if !strings.Contains(queue(b, "approve"), `data-key="acme/`+fdir+`"`) || !strings.Contains(r, `class="sel"`) || !strings.Contains(r, "· approved") || !strings.Contains(r, ">Mark reported<") {
		t.Fatalf("approved row %q:\n%s", r, b)
	}
	if !strings.Contains(b, `<span class="mv">1 moved</span> <span class="sk">· 1 skipped</span>`) || strings.Contains(b, "Result</th>") {
		t.Fatalf("summary:\n%s", b)
	}
	if e.status(t) != "complete" {
		t.Fatal("not approved")
	}
	// a bad request is an htmx error (a toast), never swapped over the lists
	rec = e.do(t, "dora", "POST", "/inbox/bulk", url.Values{"action": {"reviewers"}, "id": {"acme/" + fdir}}, hx)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "choose at least one reviewer") {
		t.Fatalf("bad request code %d", rec.Code)
	}
}

// The engagements list is a table with counts per engagement.
func TestHomeTable(t *testing.T) {
	e := setup(t)
	e.second(t, "alice")
	b := e.do(t, "alice", "GET", "/", nil, nil).Body.String()
	r := between(b, `class="table englist"`, "</table>")
	if !strings.Contains(r, `href="/e/acme"`) || !strings.Contains(r, "ACME Web") || !strings.Contains(r, `class="num">2<`) || !strings.Contains(r, "0 of 2") {
		t.Fatalf("home:\n%s", b)
	}
}
