package web

import (
	"html"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

var (
	fidRe  = regexp.MustCompile(`data-fid="([^"]+)"`)
	moreRe = regexp.MustCompile(`id="findings-more"><td colspan="\d+"><button type="button" class="btn secondary w152" hx-get="([^"]+)"`)
)

// fidsOf lists the finding rows of a findings list or Load more answer, and
// the next Load more URL ("" = none).
func fidsOf(b string) ([]string, string) {
	var out []string
	for _, m := range fidRe.FindAllStringSubmatch(b, -1) {
		out = append(out, m[1])
	}
	more := ""
	if m := moreRe.FindStringSubmatch(b); m != nil {
		more = html.UnescapeString(m[1])
	}
	return out, more
}

// After a run that moves rows out of the list's filter (Withdraw hides them
// by default), Load more still shows every other row exactly once.
func TestBulkLoadMoreAfterRun(t *testing.T) {
	e := setup(t)
	dirs := []string{fdir}
	for i := 0; i < 4; i++ {
		dirs = append(dirs, e.second(t, "alice"))
	}
	e.srv.pageSize = 2
	_, b := e.bulkPost(t, "alice", url.Values{"action": {"withdraw"}, "id": {dirs[0], dirs[1]}, "reason": {"dup"}})
	seen, more := fidsOf(b)
	for more != "" {
		var got []string
		got, more = fidsOf(e.do(t, "alice", "GET", more, nil, hxReq).Body.String())
		seen = append(seen, got...)
	}
	slices.Sort(seen)
	if !slices.Equal(seen, dirs) {
		t.Fatalf("rows shown %v, want each of %v once", seen, dirs)
	}
}

// The Progress panel above the list is sent along with the list after a
// run, so its counts agree with the rows.
func TestBulkRefreshesProgress(t *testing.T) {
	e := setup(t)
	e.second(t, "alice")
	page := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String()
	if !strings.Contains(page, `<section class="bars" id="engbars" aria-label="Engagement progress">`) {
		t.Fatalf("no engbars panel:\n%s", page)
	}
	_, b := e.bulkPost(t, "alice", url.Values{"action": {"withdraw"}, "id": {fdir}, "reason": {"dup"}})
	bars := between(b, `id="engbars" hx-swap-oob="true"`, "</section>")
	if bars == "" || !strings.Contains(bars, ">1 finding<") {
		t.Fatalf("progress after run:\n%s", bars)
	}
	// a plain list reload sends no panel
	if b := e.do(t, "alice", "GET", "/e/acme", nil, hxReq).Body.String(); strings.Contains(b, "engbars") {
		t.Fatal("panel sent with a list reload")
	}
}

// Bulk Assign merges with the list as it is when the row changes: a reviewer
// added after the page read the finding (and their sign-off) stays.
func TestBulkAssignKeepsConcurrentAdd(t *testing.T) {
	e := setup(t)
	e.toVerification(t) // bob reviews
	ref, err := e.srv.bulkRef(wDora, "acme", "001")
	if err != nil {
		t.Fatal(err)
	}
	// meanwhile the author adds carol, who signs off
	st := e.srv.Store
	if err := st.SetReviewers("acme", fdir, []string{"bob", "carol"}, wAlice); err != nil {
		t.Fatal(err)
	}
	carol := wBob
	carol.Username = "carol"
	if err := st.TransitionChecked("acme", fdir, "clear", "", carol, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.bulkReviewers(ref, []string{"dora"}, e.srv.Auth.Users(), wDora); err != nil {
		t.Fatal(err)
	}
	now, _ := st.Finding("acme", fdir)
	m := now.F.Meta
	if strings.Join(m.Reviewers, ",") != "bob,carol,dora" || strings.Join(m.ClearedBy, ",") != "carol" {
		t.Fatalf("reviewers %v cleared %v", m.Reviewers, m.ClearedBy)
	}
}

// One picked name that wrote a row is skipped for that row only; the other
// names are still added. A reviewer never assigns themselves, and the
// picker does not offer it.
func TestBulkAssignNames(t *testing.T) {
	e := setup(t)
	d2 := e.second(t, "bob")
	_, b := e.bulkPost(t, "dora", url.Values{"action": {"reviewers"}, "id": {fdir, d2}, "reviewer": {"bob", "carol"}})
	if !strings.Contains(summaryOf(b), "2 moved") {
		t.Fatalf("summary %s", summaryOf(b))
	}
	ref, _ := e.srv.Store.Finding("acme", d2)
	if got := strings.Join(ref.F.Meta.Reviewers, ","); got != "carol" {
		t.Fatalf("bob's finding reviewers %q", got)
	}
	// carol cannot pick herself
	page := e.do(t, "carol", "GET", "/e/acme", nil, nil).Body.String()
	picker := between(page, `class="bplist"`, "</div>")
	if strings.Contains(picker, `value="carol"`) || !strings.Contains(picker, `value="dora"`) {
		t.Fatalf("carol's picker: %s", picker)
	}
	if _, b := e.bulkPost(t, "bob", url.Values{"action": {"reviewers"}, "id": {d2}, "reviewer": {"bob"}}); !strings.Contains(summaryOf(b), "0 moved") {
		t.Fatalf("bob assigned himself to his own: %s", summaryOf(b))
	}
	d3 := e.second(t, "alice")
	if _, b := e.bulkPost(t, "carol", url.Values{"action": {"reviewers"}, "id": {d3}, "reviewer": {"carol"}}); !strings.Contains(summaryOf(b), "0 moved") ||
		!strings.Contains(frow(b, d3), "only the author or a director can make you a reviewer") {
		t.Fatalf("carol self-assign: %s\n%s", summaryOf(b), frow(b, d3))
	}
	if ref, _ := e.srv.Store.Finding("acme", d3); len(ref.F.Meta.Reviewers) != 0 {
		t.Fatalf("reviewers %v", ref.F.Meta.Reviewers)
	}
}

// A run stops starting rows once its time is up: the rest are skipped with
// a reason, so a long selection never outlives the request.
func TestBulkTimeLimit(t *testing.T) {
	e := setup(t)
	d2, d3 := e.second(t, "alice"), e.second(t, "alice")
	e.srv.bulkBudget = time.Nanosecond
	_, b := e.bulkPost(t, "alice", url.Values{"action": {"withdraw"}, "id": {fdir, d2, d3}, "reason": {"dup"}})
	if !strings.Contains(summaryOf(b), "1 moved") || !strings.Contains(summaryOf(b), "2 skipped") || !strings.Contains(frow(b, d3), "time limit") {
		t.Fatalf("time limit: %s\n%s", summaryOf(b), frow(b, d3))
	}
	if e.statusOf(t, "acme", d2) != "draft" {
		t.Fatal("a row past the limit moved")
	}
}

// A take back is marked in the draft colour in chat and history, not in the
// default verification colour.
func TestTakeBackEventColour(t *testing.T) {
	e := setup(t)
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	for _, rule := range []string{".chatev.ev-take_back::before { background: var(--bar-draft); }", ".dot.ev-take_back { background: var(--bar-draft); }"} {
		if !strings.Contains(css, rule) {
			t.Errorf("no rule %q", rule)
		}
	}
}

// The buttons disabled while a run is out are the form's own.
func TestBulkDisabledScoped(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String()
	if !strings.Contains(b, `hx-disabled-elt="find button"`) {
		t.Fatalf("form:\n%s", between(b, `<form class="fbulkform"`, ">"))
	}
}
