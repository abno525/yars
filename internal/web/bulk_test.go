package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"yars/internal/gitrepo"
	"yars/internal/store"
	"yars/internal/workflow"
)

// second adds F-002 to acme, written by author.
func (e *env) second(t *testing.T, author string) string {
	t.Helper()
	ref, err := e.srv.Store.CreateFinding("acme", "XSS", gitrepo.Author{Name: author, Email: author + "@yars.local"})
	if err != nil {
		t.Fatal(err)
	}
	return ref.Dir
}

func (e *env) statusOf(t *testing.T, eng, dir string) string {
	t.Helper()
	ref, err := e.srv.Store.Finding(eng, dir)
	if err != nil {
		t.Fatal(err)
	}
	return ref.F.Meta.Status
}

// row returns the bulk result row of a finding ("" when missing).
func row(b, key string) string {
	i := strings.Index(b, `data-key="`+key+`"`)
	if i < 0 {
		return ""
	}
	j := strings.Index(b[i:], "</tr>")
	return b[i : i+j]
}

func TestBulkApproveMixed(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	if err := e.srv.Store.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	d2 := e.second(t, "alice")
	form := url.Values{"action": {"approve"}, "id": {"001", "002"}}
	if rec := e.do(t, "alice", "POST", "/e/acme/bulk", form, nil); rec.Code != http.StatusForbidden || e.status(t) != "verification" {
		t.Fatalf("pentester bulk approve code %d", rec.Code)
	}
	if rec := e.do(t, "bob", "POST", "/e/acme/bulk", url.Values{"action": {"report"}, "id": {"001"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("reviewer bulk report code %d", rec.Code)
	}
	rec := e.do(t, "dora", "POST", "/e/acme/bulk", form, nil)
	b := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, `id="bulk-result"`) {
		t.Fatalf("code %d:\n%s", rec.Code, b)
	}
	if r := row(b, "acme/F-001"); !strings.Contains(r, `class="ok"`) {
		t.Fatalf("F-001 row %q", r)
	}
	// every table has a header row
	if !strings.Contains(b, `<thead><tr><th class="c-id">Finding</th><th class="title">Title</th><th>Result</th></tr></thead>`) {
		t.Fatalf("bulk result has no header row:\n%s", b)
	}
	if r := row(b, "acme/F-002"); !strings.Contains(r, `class="denied"`) || !strings.Contains(r, "only possible in verification") {
		t.Fatalf("F-002 row %q", r)
	}
	if e.status(t) != "complete" || e.statusOf(t, "acme", d2) != "draft" {
		t.Fatal("statuses after bulk approve")
	}
	if !strings.Contains(e.events(t), "dora:approve") {
		t.Fatal("approve not recorded as dora")
	}
}

func TestBulkReport(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	e.second(t, "alice")
	b := e.do(t, "dora", "POST", "/e/acme/bulk", url.Values{"action": {"report"}, "id": {fdir, "002", "999"}}, nil).Body.String()
	if !strings.Contains(row(b, "acme/F-001"), `class="ok"`) || !strings.Contains(row(b, "acme/F-002"), `class="denied"`) {
		t.Fatalf("rows:\n%s", b)
	}
	if r := row(b, "acme/999"); !strings.Contains(r, `class="denied"`) || !strings.Contains(r, "unknown finding") {
		t.Fatalf("unknown row %q", r)
	}
	if e.status(t) != "reported" {
		t.Fatal("not reported")
	}
}

func TestBulkReviewers(t *testing.T) {
	e := setup(t)
	d2 := e.second(t, "bob")
	form := url.Values{"action": {"reviewers"}, "id": {"001", "002"}, "reviewer": {"carol"}}
	// a pentester's bulk bar has no Assign reviewers
	if rec := e.do(t, "alice", "POST", "/e/acme/bulk", form, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pentester bulk assign code %d", rec.Code)
	}
	// a reviewer assigns others on any open finding, never themselves
	b := e.do(t, "carol", "POST", "/e/acme/bulk", url.Values{"action": {"reviewers"}, "id": {"001", "002"}, "reviewer": {"dora"}}, nil).Body.String()
	if !strings.Contains(row(b, "acme/F-001"), `class="ok"`) || !strings.Contains(row(b, "acme/F-002"), `class="ok"`) {
		t.Fatalf("reviewer assign rows:\n%s", b)
	}
	b = e.do(t, "carol", "POST", "/e/acme/bulk", url.Values{"action": {"reviewers"}, "id": {"001"}, "reviewer": {"carol"}}, nil).Body.String()
	if !strings.Contains(row(b, "acme/F-001"), `class="denied"`) {
		t.Fatalf("reviewer self-assign rows:\n%s", b)
	}
	// existing reviewers stay; the author is never a reviewer
	e.srv.Store.SetReviewers("acme", d2, []string{"carol"}, wDora)
	e.srv.Store.SetReviewers("acme", fdir, []string{"carol"}, wDora)
	b = e.do(t, "dora", "POST", "/e/acme/bulk", url.Values{"action": {"reviewers"}, "id": {"001", "002"}, "reviewer": {"bob"}}, nil).Body.String()
	if !strings.Contains(row(b, "acme/F-001"), `class="ok"`) {
		t.Fatalf("dora F-001:\n%s", b)
	}
	if r := row(b, "acme/F-002"); !strings.Contains(r, `class="denied"`) || !strings.Contains(r, "bob") {
		t.Fatalf("author as reviewer row %q", r)
	}
	ref, _ := e.srv.Store.Finding("acme", fdir)
	if got := strings.Join(ref.F.Meta.Reviewers, ","); got != "bob,carol" {
		t.Fatalf("F-001 reviewers %q", got)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/bulk", url.Values{"action": {"reviewers"}, "id": {"001"}, "reviewer": {"mallory"}}, nil); !strings.Contains(row(rec.Body.String(), "acme/F-001"), `class="denied"`) {
		t.Fatal("unknown reviewer accepted")
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/bulk", url.Values{"action": {"reviewers"}, "id": {"001"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("no names code %d", rec.Code)
	}
}

func TestBulkBadRequests(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "dora", "POST", "/e/acme/bulk", url.Values{"action": {"approve"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty selection code %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/bulk", url.Values{"action": {"bogus"}, "id": {"001"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported action code %d", rec.Code)
	}
}

// The director inbox selects across engagements with "eng/fid" ids.
func TestInboxBulk(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	st := e.srv.Store
	st.Transition("acme", fdir, workflow.Clear, "", wBob)
	a := e.authorOf(wAlice)
	if err := st.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, a); err != nil {
		t.Fatal(err)
	}
	ref, err := st.CreateFinding("beta", "CSRF", a)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"action": {"approve"}, "id": {"acme/001", "beta/" + ref.Dir, "nope"}}
	b := e.do(t, "dora", "POST", "/inbox/bulk", form, nil).Body.String()
	if !strings.Contains(row(b, "acme/F-001"), `class="ok"`) || !strings.Contains(row(b, "beta/F-001"), `class="denied"`) {
		t.Fatalf("rows:\n%s", b)
	}
	if r := row(b, "nope"); !strings.Contains(r, `class="denied"`) {
		t.Fatalf("malformed id row %q", r)
	}
	if e.status(t) != "complete" {
		t.Fatal("not approved")
	}
	if rec := e.do(t, "alice", "POST", "/inbox/bulk", form, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pentester inbox bulk code %d", rec.Code)
	}
}
