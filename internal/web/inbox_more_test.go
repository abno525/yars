package web

import (
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"yars/internal/chat"
	"yars/internal/store"
	"yars/internal/workflow"
)

// toSignedOff brings a new finding of eng, written by alice, to
// verification with bob's sign-off; it returns its folder.
func (e *env) toSignedOff(t *testing.T, eng, title string) string {
	t.Helper()
	st := e.srv.Store
	ref, err := st.CreateFinding(eng, title, e.authorOf(wAlice))
	if err != nil {
		t.Fatal(err)
	}
	st.SetReviewers(eng, ref.Dir, []string{"bob"}, wAlice)
	st.UpdateSeverity(eng, ref.Dir, "high", "", e.authorOf(wAlice))
	if err := st.Transition(eng, ref.Dir, workflow.Submit, "", wAlice); err != nil {
		t.Fatal(err)
	}
	if err := st.Transition(eng, ref.Dir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	return ref.Dir
}

// Two engagements both have F-001: the director's bar keys rows by
// engagement and folder, so a run on one never ticks or tints the other.
func TestInboxSameIDTwoEngagements(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	if err := st.CreateEngagement(store.Engagement{ID: "demo", Name: "Demo"}, e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	st.DB().AddMembers("demo", "alice", "bob")
	e.toVerification(t)
	st.Transition("acme", fdir, workflow.Clear, "", wBob)
	d := e.toSignedOff(t, "demo", "SQL injection")
	b := e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String()
	for _, want := range []string{`name="id" value="acme/` + fdir + `"`, `name="id" value="demo/` + d + `"`} {
		if !strings.Contains(queue(b, "approve"), want) {
			t.Fatalf("approve lacks %s:\n%s", want, queue(b, "approve"))
		}
	}
	b = e.do(t, "dora", "POST", "/inbox/bulk", url.Values{"action": {"report"}, "id": {"demo/" + d}}, map[string]string{"HX-Request": "true"}).Body.String()
	if r := row(b, "demo/"+d); !strings.Contains(r, `class="skip"`) || !strings.Contains(r, " checked") {
		t.Fatalf("demo row %q", r)
	}
	if r := row(b, "acme/"+fdir); strings.Contains(r, `class="skip"`) || strings.Contains(r, `class="sel"`) || strings.Contains(r, " checked") {
		t.Fatalf("acme row ticked or tinted by demo's run %q", r)
	}
}

var titleCell = regexp.MustCompile(`<td class="title"><a href="[^"]*" title="([^"]*)"`)

func titlesIn(b string) []string {
	var out []string
	for _, m := range titleCell.FindAllStringSubmatch(b, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

// moreURL is the queue's Load more link ("" = none).
func moreURL(b, name string) string {
	m := regexp.MustCompile(`id="inbox-more-` + name + `"><td colspan="\d+"><button type="button" class="btn secondary w152" hx-get="([^"]*)"`).FindStringSubmatch(b)
	if m == nil {
		return ""
	}
	return html.UnescapeString(m[1])
}

// Every queue pages with Load more; the rows Load more adds to a pick
// queue have their checkbox and actions.
func TestInboxLoadMoreQueues(t *testing.T) {
	e := setup(t)
	e.srv.pageSize = 1
	e.toVerification(t)
	e.srv.Store.Transition("acme", fdir, workflow.Clear, "", wBob)
	e.toSignedOff(t, "acme", "XSS")
	b := e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String()
	u := moreURL(b, "approve")
	if u == "" {
		t.Fatalf("no Load more on approve:\n%s", queue(b, "approve"))
	}
	next := e.do(t, "dora", "GET", u, nil, map[string]string{"HX-Request": "true"}).Body.String()
	if !strings.Contains(next, `<input type="checkbox" name="id" value="acme/F-002`) || !strings.Contains(next, `data-acts="take_back approve withdraw"`) {
		t.Fatalf("loaded row has no pick:\n%s", next)
	}
	// threads and drafts page too
	e.srv.Store.PostChat("acme", fdir, chat.Message{Text: "one"}, wBob)
	e.srv.Store.PostChat("acme", fdir, chat.Message{Text: "two"}, wBob)
	b = e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String()
	if u := moreURL(b, "threads"); u == "" || !strings.Contains(e.do(t, "alice", "GET", u, nil, map[string]string{"HX-Request": "true"}).Body.String(), "Reply</a>") {
		t.Fatalf("threads Load more %q", u)
	}
}

// After a run, Load more goes on from where the page stops: every row of
// the queue shows exactly once, the ones the run moved included.
func TestInboxLoadMoreAfterRun(t *testing.T) {
	e := setup(t)
	e.srv.pageSize = 2
	e.toVerification(t)
	e.srv.Store.Transition("acme", fdir, workflow.Clear, "", wBob)
	e.toSignedOff(t, "acme", "XSS")
	e.toSignedOff(t, "acme", "CSRF")
	hx := map[string]string{"HX-Request": "true"}
	b := e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String()
	first := titlesIn(queue(b, "approve"))
	if len(first) != 2 {
		t.Fatalf("first page %v", first)
	}
	// approve the first row shown
	key := regexp.MustCompile(`name="id" value="([^"]+)"`).FindStringSubmatch(queue(b, "approve"))[1]
	b = e.do(t, "dora", "POST", "/inbox/bulk", url.Values{"action": {"approve"}, "id": {key}}, hx).Body.String()
	seen := titlesIn(queue(b, "approve"))
	for u := moreURL(b, "approve"); u != ""; {
		next := e.do(t, "dora", "GET", u, nil, hx).Body.String()
		seen = append(seen, titlesIn(next)...)
		u = moreURL(next, "approve")
	}
	got := strings.Join(seen, ",")
	for _, title := range []string{"SQL injection", "XSS", "CSRF"} {
		if strings.Count(got, title) != 1 {
			t.Fatalf("rows after the run: %s", got)
		}
	}
}

// New on team board counts every unseen note, in its header and the badge,
// though it lists only the newest 50.
func TestInboxBoardTotal(t *testing.T) {
	e := setup(t)
	for i := 0; i < boardInboxRows+3; i++ {
		e.lead(t, "alice", fmt.Sprint("lead ", i), "", "open")
	}
	b := e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String()
	if !strings.Contains(b, fmt.Sprintf(`New on team board <span class="qcnt">%d</span>`, boardInboxRows+3)) {
		t.Fatalf("board header:\n%s", queue(b, "board"))
	}
	if n := len(titlesIn(queue(b, "board"))); n != boardInboxRows {
		t.Fatalf("%d board rows", n)
	}
	if !strings.Contains(b, fmt.Sprintf(`Inbox <span class="badge">%d</span>`, boardInboxRows+3)) {
		t.Fatal("badge leaves notes out")
	}
}

// A run another server left "running" is no check in progress: the draft
// says the check failed instead of "Checking" for ever.
func TestInboxDraftStaleRunning(t *testing.T) {
	e := setup(t)
	ref, _ := e.srv.Store.Finding("acme", fdir)
	if _, err := e.srv.Store.DB().StartRun("acme", "F-001", ref.Hash, "alice"); err != nil {
		t.Fatal(err)
	}
	q := queue(e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(), "drafts")
	if !strings.Contains(q, "Check failed") || strings.Contains(q, "Checking") {
		t.Fatalf("draft:\n%s", q)
	}
}

// A brand-new draft with no chat line shows when its file last changed.
func TestInboxNewDraftTime(t *testing.T) {
	e := setup(t)
	q := queue(e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(), "drafts")
	if !strings.Contains(q, "SQL injection") || strings.Contains(q, `<td class="c-age mono">—</td>`) {
		t.Fatalf("draft time:\n%s", q)
	}
}
