package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/workflow"
)

var (
	wAlice = config.User{Username: "alice", Role: "pentester"}
	wBob   = config.User{Username: "bob", Role: "reviewer"}
	wDora  = config.User{Username: "dora", Role: "director"}
)

const fdir = "F-001-sql-injection"

// fshort is the finding's URL as pages link it.
const fshort = "/e/acme/f/001"

func (e *env) status(t *testing.T) string {
	t.Helper()
	ref, err := e.srv.Store.Finding("acme", fdir)
	if err != nil {
		t.Fatal(err)
	}
	return ref.F.Meta.Status
}

// toVerification assigns bob, sets a severity and submits as alice.
func (e *env) toVerification(t *testing.T) {
	t.Helper()
	st := e.srv.Store
	if err := st.SetReviewers("acme", fdir, []string{"bob"}, wAlice); err != nil {
		t.Fatal(err)
	}
	st.UpdateSeverity("acme", fdir, "high", "", e.authorOf(wAlice))
	if err := st.Transition("acme", fdir, workflow.Submit, "", wAlice); err != nil {
		t.Fatal(err)
	}
}

func (e *env) toComplete(t *testing.T) {
	t.Helper()
	e.toVerification(t)
	st := e.srv.Store
	if err := st.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	if err := st.Transition("acme", fdir, workflow.Approve, "", wDora); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowButtonsByRole(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	i := strings.Index(b, "Submit for verification")
	if i < 0 || !strings.Contains(b[max(0, i-200):i], "disabled") || !strings.Contains(b, "assign at least one reviewer") {
		t.Fatalf("alice should see disabled submit with gate problems:\n%s", b)
	}
	if b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String(); strings.Contains(b, "Submit for verification") {
		t.Fatal("bob sees submit")
	}
}

func TestSubmitAndClearFlow(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "alice", "POST", fpath+"/reviewers", url.Values{"reviewer": {"bob"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("reviewers code %d %s", rec.Code, rec.Body.String())
	}
	e.do(t, "alice", "POST", fpath+"/severity", url.Values{"severity": {"high"}}, nil)
	if rec := e.do(t, "alice", "POST", fpath+"/action/submit", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("submit code %d %s", rec.Code, rec.Body.String())
	}
	if e.status(t) != "verification" {
		t.Fatal("not in verification")
	}
	b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, "/e/acme/f/001/action/clear") || !strings.Contains(b, "Return to draft") {
		t.Fatalf("bob lacks review actions:\n%s", b)
	}
	e.do(t, "bob", "POST", fpath+"/action/clear", url.Values{}, nil)
	if b := e.do(t, "dora", "GET", fpath, nil, nil).Body.String(); !strings.Contains(b, `class="rev cleared" title="bob"`) || !strings.Contains(b, "/e/acme/f/001/action/approve") {
		t.Fatalf("dora page:\n%s", b)
	}
	e.do(t, "dora", "POST", fpath+"/action/approve", url.Values{}, nil)
	if e.status(t) != "complete" {
		t.Fatal("not complete")
	}
	if got := e.events(t); got != "alice:submit bob:clear dora:approve" {
		t.Fatalf("events %q", got)
	}
}

// events lists the finding's workflow events as "user:event".
func (e *env) events(t *testing.T) string {
	t.Helper()
	msgs, err := e.srv.Store.Chat("acme", fdir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range msgs {
		if m.Event != "" {
			out = append(out, m.User+":"+m.Event)
		}
	}
	return strings.Join(out, " ")
}

func TestWithdrawAndRestoreWeb(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); !strings.Contains(b, fshort+"/action/withdraw") {
		t.Fatal("author lacks withdraw")
	}
	if b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String(); strings.Contains(b, fshort+"/action/withdraw") {
		t.Fatal("reviewer sees withdraw")
	}
	rec := e.do(t, "alice", "POST", fpath+"/action/withdraw", url.Values{"reason": {" "}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "reason is required") {
		t.Fatalf("withdraw without reason: %d", rec.Code)
	}
	if rec := e.do(t, "bob", "POST", fpath+"/action/withdraw", url.Values{"reason": {"x"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("reviewer withdraw code %d", rec.Code)
	}
	e.do(t, "alice", "POST", fpath+"/action/withdraw", url.Values{"reason": {"Duplicate of F-002"}}, nil)
	if e.status(t) != "withdrawn" {
		t.Fatalf("status %s", e.status(t))
	}
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, fshort+"/action/revise") || !strings.Contains(b, "Restore") || !strings.Contains(b, "Duplicate of F-002") {
		t.Fatalf("withdrawn page:\n%s", b)
	}
	// out of the inbox and the default board, in the Withdrawn filter
	if b := e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String(); strings.Contains(section(b, "Awaiting my review"), "SQL injection") {
		t.Fatal("withdrawn finding in the inbox")
	}
	if b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(); strings.Contains(b, `href="/e/acme/f/001"`) || !strings.Contains(b, "status=withdrawn") {
		t.Fatalf("board:\n%s", b)
	}
	if b := e.do(t, "alice", "GET", "/e/acme?status=withdrawn", nil, nil).Body.String(); !strings.Contains(b, `href="/e/acme/f/001"`) {
		t.Fatal("withdrawn filter empty")
	}
	if rec := e.do(t, "alice", "POST", fpath+"/action/revise", url.Values{}, nil); rec.Code != http.StatusSeeOther || e.status(t) != "draft" {
		t.Fatalf("restore code %d status %s", rec.Code, e.status(t))
	}
}

func TestSignOffAlias(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, ">Sign off<") || !strings.Contains(b, fshort+"/action/clear") {
		t.Fatalf("bob page lacks Sign off:\n%s", b)
	}
	if rec := e.do(t, "bob", "POST", fpath+"/action/sign_off", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("sign_off code %d %s", rec.Code, rec.Body.String())
	}
	if got := e.events(t); got != "alice:submit bob:clear" {
		t.Fatalf("events %q", got)
	}
}

func TestMarkReportedAction(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); strings.Contains(b, fshort+"/action/report") {
		t.Fatal("pentester sees Mark reported")
	}
	if b := e.do(t, "dora", "GET", fpath, nil, nil).Body.String(); !strings.Contains(b, fshort+"/action/report") || !strings.Contains(b, "Mark reported") {
		t.Fatal("director lacks Mark reported")
	}
	if rec := e.do(t, "alice", "POST", fpath+"/action/report", url.Values{}, nil); rec.Code != http.StatusBadRequest || e.status(t) != "complete" {
		t.Fatalf("pentester report code %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", fpath+"/action/report", url.Values{}, nil); rec.Code != http.StatusSeeOther || e.status(t) != "reported" {
		t.Fatalf("report code %d status %s", rec.Code, e.status(t))
	}
}

func TestReturnRequiresReason(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	rec := e.do(t, "bob", "POST", fpath+"/action/return", url.Values{"reason": {" "}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "reason is required") {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
	e.do(t, "bob", "POST", fpath+"/action/return", url.Values{"reason": {"Steps are incomplete"}}, nil)
	if e.status(t) != "draft" {
		t.Fatal("not returned")
	}
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, "Steps are incomplete") || !strings.Contains(b, "Returned by") {
		t.Fatalf("no returned banner:\n%s", b)
	}
}

func TestDeniedActionShowsError(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", fpath+"/action/approve", url.Values{}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `class="error`) {
		t.Fatalf("code %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", fpath+"/action/bogus", url.Values{}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bogus action code %d", rec.Code)
	}
}

func TestLockedEditForbidden(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	before := e.lastCommit(t)
	reqs := []struct{ method, path string }{
		{"GET", fpath + "/s/Impact/edit"},
		{"POST", fpath + "/s/Impact"},
		{"GET", fpath + "/cvss/edit"},
		{"POST", fpath + "/cvss"},
		{"POST", fpath + "/severity"},
		{"GET", fpath + "/details/edit"},
		{"POST", fpath + "/details"},
	}
	for _, r := range reqs {
		var form url.Values
		if r.method == "POST" {
			form = url.Values{"body": {"x"}, "severity": {"low"}, "row:Location": {"x"}, "action": {"clear"}}
		}
		if rec := e.do(t, "alice", r.method, r.path, form, nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: code %d", r.method, r.path, rec.Code)
		}
	}
	if e.lastCommit(t) != before {
		t.Fatal("locked finding changed")
	}
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); strings.Contains(b, "/s/Impact/edit") || strings.Contains(b, "/details/edit") || strings.Contains(b, "/cvss/edit") {
		t.Fatal("edit buttons shown on locked finding")
	}
	if rec := e.do(t, "dora", "GET", fpath+"/s/Impact/edit", nil, nil); rec.Code != 200 {
		t.Fatalf("director edit code %d", rec.Code)
	}
}

// Finding URLs are just the number: /e/acme/f/001.
func TestShortFindingURLs(t *testing.T) {
	e := setup(t)
	if b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(); !strings.Contains(b, `href="/e/acme/f/001"`) || strings.Contains(b, "/f/F-001") {
		t.Fatalf("table links not short:\n%s", b)
	}
	b := e.do(t, "alice", "GET", "/e/acme/f/001", nil, nil).Body.String()
	if !strings.Contains(b, "SQL injection") || !strings.Contains(b, `/e/acme/f/001/details/edit`) || strings.Contains(b, "/f/F-001") {
		t.Fatalf("finding page links not short:\n%s", b)
	}
	e.do(t, "alice", "POST", "/e/acme/f/001/reviewers", url.Values{"reviewer": {"bob"}}, nil)
	e.srv.Store.UpdateSeverity("acme", fdir, "high", "", e.authorOf(wAlice))
	if rec := e.do(t, "alice", "POST", "/e/acme/f/001/action/submit", nil, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/f/001" {
		t.Fatalf("submit code %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"XSS"}}, nil); rec.Header().Get("Location") != "/e/acme/f/002" {
		t.Fatalf("new finding redirect %q", rec.Header().Get("Location"))
	}
}

// One press assigns every reviewer-role account (directors stay as they were).
func TestReviewersAssignAll(t *testing.T) {
	e := setup(t)
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); !strings.Contains(b, `name="all"`) {
		t.Fatal("no assign-all button")
	}
	if rec := e.do(t, "alice", "POST", fpath+"/reviewers", url.Values{"all": {"1"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("code %d", rec.Code)
	}
	ref, err := e.srv.Store.Finding("acme", fdir)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ref.F.Meta.Reviewers, ","); got != "bob,carol" {
		t.Fatalf("reviewers %q", got)
	}
}

func TestReviewersRejectUnknown(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", fpath+"/reviewers", url.Values{"reviewer": {"mallory"}}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d", rec.Code)
	}
	if rec := e.do(t, "bob", "POST", fpath+"/reviewers", url.Values{"reviewer": {"dora"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("non-author assign code %d", rec.Code)
	}
}
