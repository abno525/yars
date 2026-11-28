package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

// inReview makes a finding of alice's in eng with the severity sev, bob as
// its reviewer, and submits it. It returns the finding's folder.
func (e *env) inReview(t *testing.T, eng, title, sev string) string {
	t.Helper()
	st := e.srv.Store
	ref, err := st.CreateFinding(eng, title, gitrepo.Author{Name: "alice", Email: "alice@yars.local"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetReviewers(eng, ref.Dir, []string{"bob"}, wAlice); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSeverity(eng, ref.Dir, sev, "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	if err := st.Transition(eng, ref.Dir, workflow.Submit, "", wAlice); err != nil {
		t.Fatal(err)
	}
	return ref.Dir
}

// act posts a workflow action of the finding page as user and returns where
// the answer leads.
func (e *env) act(t *testing.T, user, eng, dir, action string) string {
	t.Helper()
	rec := e.do(t, user, "POST", "/e/"+eng+"/f/"+dir+"/action/"+action, url.Values{}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("%s %s by %s: %d\n%s", action, dir, user, rec.Code, rec.Body.String())
	}
	return rec.Header().Get("Location")
}

// Sign off leads to the next finding of the reviewer's Awaiting my review,
// in the Inbox's order: the one after it, from the end the first, and with
// none left the finding itself.
func TestSignOffOpensNextInQueue(t *testing.T) {
	e := setup(t)
	e.toVerification(t) // F-001, high
	second := e.inReview(t, "acme", "XSS in search", "medium")
	third := e.inReview(t, "acme", "Verbose errors", "low")
	// the order the Inbox shows
	q := queue(e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String(), "review")
	if a, b, c := strings.Index(q, "SQL injection"), strings.Index(q, "XSS in search"), strings.Index(q, "Verbose errors"); a < 0 || !(a < b && b < c) {
		t.Fatalf("the review queue's order: %d %d %d\n%s", a, b, c, q)
	}
	if to := e.act(t, "bob", "acme", second, "clear"); to != "/e/acme/f/003" {
		t.Fatalf("after the second of three: %q, want the third", to)
	}
	if to := e.act(t, "bob", "acme", third, "clear"); to != "/e/acme/f/001" {
		t.Fatalf("after the last: %q, want the first", to)
	}
	if to := e.act(t, "bob", "acme", fdir, "clear"); to != fshort {
		t.Fatalf("none left: %q, want the finding itself", to)
	}
	// each was signed off once, by bob
	for _, d := range []string{fdir, second, third} {
		if ref, _ := e.srv.Store.Finding("acme", d); len(ref.F.Meta.ClearedBy) != 1 {
			t.Errorf("%s: signed off by %v", d, ref.F.Meta.ClearedBy)
		}
	}
}

// Approve leads to the next finding of the director's Ready to approve. A
// finding that is signed off but may not be approved yet (an open check) is
// not in that queue, so it is not the next one.
func TestApproveOpensNextInQueue(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	second := e.inReview(t, "acme", "XSS in search", "medium")
	third := e.inReview(t, "acme", "Verbose errors", "low")
	st := e.srv.Store
	for _, d := range []string{fdir, second, third} {
		if err := st.Transition("acme", d, workflow.Clear, "", wBob); err != nil {
			t.Fatal(err)
		}
	}
	// a director's Sign off of a finding that is not in her review queue
	// stays on the finding
	fourth := e.inReview(t, "acme", "Open redirect", "low")
	if to := e.act(t, "dora", "acme", fourth, "clear"); to != "/e/acme/f/004" {
		t.Fatalf("a sign-off outside the own queue: %q", to)
	}
	if err := st.Transition("acme", fourth, workflow.Return, "not yet", wDora); err != nil {
		t.Fatal(err)
	}
	// rules come on, and every finding is checked: the third has an open
	// warning, so it is not ready to approve
	e.rules(t, "- id: soft\n  target: title\n  regex_forbid: 'Verbose'\n  level: warning\n  message: say which errors\n", nil)
	for _, d := range []string{fdir, second, third} {
		e.checked(t, "acme", d)
	}
	q := queue(e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String(), "approve")
	if !strings.Contains(q, "SQL injection") || !strings.Contains(q, "XSS in search") || strings.Contains(q, "Verbose errors") {
		t.Fatalf("Ready to approve:\n%s", q)
	}
	if to := e.act(t, "dora", "acme", fdir, "approve"); to != "/e/acme/f/002" {
		t.Fatalf("after the first of two: %q, want the second", to)
	}
	if to := e.act(t, "dora", "acme", second, "approve"); to != "/e/acme/f/002" {
		t.Fatalf("the third waits for its check: %q, want the finding itself", to)
	}
	if e.statusOf(t, "acme", fdir) != "complete" || e.statusOf(t, "acme", second) != "complete" || e.statusOf(t, "acme", third) != "verification" {
		t.Fatal("the approvals did not land where they were pressed")
	}
}

// What does not move on: a denied action (its flash is for that finding),
// the other actions, and the reviewer picker.
func TestOtherActionsStayOnTheFinding(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	second := e.inReview(t, "acme", "XSS in search", "medium")
	// a stale page: the sign-off is refused and the page says so
	b := e.denied(t, "bob", fshort+"/action/clear", url.Values{"seen": {"0000"}})
	if !strings.Contains(b, "the finding changed since you opened it") {
		t.Fatal("the refusal is not on the finding's page")
	}
	// Return and the reviewer picker lead back to the finding
	rec := e.do(t, "bob", "POST", fshort+"/action/return", url.Values{"reason": {"add a PoC"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != fshort {
		t.Fatalf("Return: %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	ref, _ := e.srv.Store.Finding("acme", second)
	rec = e.do(t, "alice", "POST", "/e/acme/f/002/reviewers", url.Values{"reviewer": {"bob", "carol"}, "base": {store.ReviewersHash(ref.F.Meta)}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/f/002" {
		t.Fatalf("the reviewer picker: %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	// Submit by the author, who has a second finding of her own waiting nowhere
	if to := e.act(t, "alice", "acme", fdir, "submit"); to != fshort {
		t.Fatalf("Submit: %q", to)
	}
}

// The queue spans the engagements the account sees: a finding of another
// open engagement is a next one, one of an archived engagement is not.
func TestNextInQueueAcrossEngagements(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	st := e.srv.Store
	a := gitrepo.Author{Name: "alice", Email: "alice@yars.local"}
	for _, id := range []string{"beta", "gamma"} {
		if err := st.CreateEngagement(store.Engagement{ID: id, Name: strings.ToUpper(id)}, a); err != nil {
			t.Fatal(err)
		}
		if err := st.DB().AddMembers(id, "alice", "bob"); err != nil {
			t.Fatal(err)
		}
	}
	e.inReview(t, "beta", "Weak cipher", "medium")
	e.inReview(t, "gamma", "Old TLS", "low")
	if err := st.Archive("gamma", wDora); err != nil {
		t.Fatal(err)
	}
	if to := e.act(t, "bob", "acme", fdir, "clear"); to != "/e/beta/f/001" {
		t.Fatalf("the next is in another engagement: %q", to)
	}
	if to := e.act(t, "bob", "beta", "F-001", "clear"); to != "/e/beta/f/001" {
		t.Fatalf("the archived engagement's finding is no next one: %q", to)
	}
}

// The simple workflow has no review and no approve queue: Complete stays.
func TestSimpleCompleteStays(t *testing.T) {
	e := setupSimple(t)
	st := e.srv.Store
	anna := gitrepo.Author{Name: "anna", Email: "anna@yars.local"}
	// two drafts of anna's, each with the severity Complete waits for
	other, err := st.CreateFinding("acme", "XSS in search", anna)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{fdir, other.Dir} {
		if err := st.UpdateSeverity("acme", d, "high", "", anna); err != nil {
			t.Fatal(err)
		}
	}
	rec := e.do(t, "anna", "POST", "/e/acme/f/001/action/complete", url.Values{}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/f/001" || e.status(t) != "complete" {
		t.Fatalf("Complete: %d to %q, status %s", rec.Code, rec.Header().Get("Location"), e.status(t))
	}
}
