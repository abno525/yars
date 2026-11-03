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
	if !strings.Contains(b, fpath+"/action/clear") || !strings.Contains(b, "Return to draft") {
		t.Fatalf("bob lacks review actions:\n%s", b)
	}
	e.do(t, "bob", "POST", fpath+"/action/clear", url.Values{}, nil)
	if b := e.do(t, "dora", "GET", fpath, nil, nil).Body.String(); !strings.Contains(b, "bob ✓") || !strings.Contains(b, fpath+"/action/approve") {
		t.Fatalf("dora page:\n%s", b)
	}
	e.do(t, "dora", "POST", fpath+"/action/approve", url.Values{}, nil)
	if e.status(t) != "complete" {
		t.Fatal("not complete")
	}
	if got := e.lastCommit(t); got != "dora|F-001: approve" {
		t.Fatalf("commit %q", got)
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
			form = url.Values{"body": {"x"}, "severity": {"low"}, "row_0": {"x"}, "action": {"clear"}}
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
