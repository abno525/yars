package store

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/gitrepo"
	"yars/internal/workflow"
)

var (
	uAlice = config.User{Username: "alice", Role: "pentester"}
	uBob   = config.User{Username: "bob", Role: "reviewer"}
	uCarol = config.User{Username: "carol", Role: "reviewer"}
	uDora  = config.User{Username: "dora", Role: "director"}
)

func denied(err error) bool {
	var d *workflow.Denied
	return errors.As(err, &d)
}

// ready returns a finding by alice with bob as reviewer and a severity.
func ready(t *testing.T) (*Store, string, string) {
	t.Helper()
	s, dir, fd := newFinding(t)
	if err := s.SetReviewers(eng, fd, []string{"bob"}, uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSeverity(eng, fd, "high", "", alice); err != nil {
		t.Fatal(err)
	}
	return s, dir, fd
}

// events returns the workflow events recorded in the finding's chat.
func events(t *testing.T, s *Store, fd string) []string {
	t.Helper()
	msgs, err := s.Chat(eng, fd)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range msgs {
		if m.Event != "" {
			out = append(out, m.User+":"+m.Event+":"+m.Text)
		}
	}
	return out
}

func TestTransitionSubmitGate(t *testing.T) {
	s, _, fd := newFinding(t)
	err := s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if !denied(err) || !strings.Contains(err.Error(), "reviewer") {
		t.Fatalf("err %v", err)
	}
	s, dir, fd := ready(t)
	before := last(t, dir, "%H")
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if load(t, s, fd).F.Meta.Status != "verification" {
		t.Fatal("submit not recorded")
	}
	// workflow state is in the database: no commit, the file is untouched
	if last(t, dir, "%H") != before {
		t.Fatal("a transition made a git commit")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "engagements", eng, "findings", fd, "finding.md")); strings.Contains(string(b), "status") {
		t.Fatalf("state written to the file:\n%s", b)
	}
	if got := events(t, s, fd); !reflect.DeepEqual(got, []string{"alice:submit:"}) {
		t.Fatalf("events %v", got)
	}
}

// A director who reviews without being assigned joins the reviewers, so
// their clearance counts for another director's approval.
func TestDirectorClearsUnassigned(t *testing.T) {
	s, _, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.Transition(eng, fd, workflow.Clear, "", uDora); err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	if !reflect.DeepEqual(m.Reviewers, []string{"bob", "dora"}) || !reflect.DeepEqual(m.ClearedBy, []string{"dora"}) {
		t.Fatalf("reviewers %v cleared %v", m.Reviewers, m.ClearedBy)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); !denied(err) {
		t.Fatalf("director approved own review: %v", err)
	}
	dir2 := config.User{Username: "dir2", Role: "director"}
	if err := s.Transition(eng, fd, workflow.Approve, "", dir2); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionFlow(t *testing.T) {
	s, _, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	if m.Status != "complete" || !reflect.DeepEqual(m.ClearedBy, []string{"bob"}) {
		t.Fatalf("meta %+v", m)
	}
	if err := s.Transition(eng, fd, workflow.Reopen, "", uDora); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "verification" || len(m.ClearedBy) != 0 {
		t.Fatalf("reopen %+v", m)
	}
	want := []string{"alice:submit:", "bob:clear:", "dora:approve:", "dora:reopen:"}
	if got := events(t, s, fd); !reflect.DeepEqual(got, want) {
		t.Fatalf("events %v", got)
	}
}

func TestWithdrawAndRevise(t *testing.T) {
	s, _, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Withdraw, "  ", uAlice); !denied(err) || !strings.Contains(err.Error(), "reason") {
		t.Fatalf("withdraw without reason: %v", err)
	}
	if err := s.Transition(eng, fd, workflow.Withdraw, "dup", uBob); !denied(err) {
		t.Fatalf("reviewer withdrew: %v", err)
	}
	if err := s.Transition(eng, fd, workflow.Withdraw, "duplicate of F-002", uAlice); err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	if m.Status != "withdrawn" || len(m.ClearedBy) != 0 || m.Withdrawn == nil || m.Withdrawn.By != "alice" || m.Withdrawn.Reason != "duplicate of F-002" {
		t.Fatalf("withdrawn meta %+v %+v", m, m.Withdrawn)
	}
	if err := s.Transition(eng, fd, workflow.Revise, "", uBob); !denied(err) {
		t.Fatalf("reviewer restored: %v", err)
	}
	if err := s.Transition(eng, fd, workflow.Revise, "", uAlice); err != nil {
		t.Fatal(err)
	}
	m = load(t, s, fd).F.Meta
	if m.Status != "draft" || m.Withdrawn != nil || len(m.ClearedBy) != 0 {
		t.Fatalf("revised meta %+v", m)
	}
	want := []string{"alice:submit:", "bob:clear:", "alice:withdraw:duplicate of F-002", "alice:revise:"}
	if got := events(t, s, fd); !reflect.DeepEqual(got, want) {
		t.Fatalf("events %v", got)
	}
}

// A returned draft that is withdrawn shows only why it was withdrawn.
func TestWithdrawClearsReturned(t *testing.T) {
	s, _, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.Transition(eng, fd, workflow.Return, "needs impact", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Withdraw, "duplicate", uAlice); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.Returned != nil {
		t.Fatalf("withdrawn finding still returned: %+v", m.Returned)
	}
}

func TestDirectorWithdrawsComplete(t *testing.T) {
	s, _, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Withdraw, "out of scope", uAlice); !denied(err) {
		t.Fatalf("author withdrew a complete finding: %v", err)
	}
	if err := s.Transition(eng, fd, workflow.Withdraw, "out of scope", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Revise, "", uDora); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "draft" {
		t.Fatalf("status %s", m.Status)
	}
	// the old approval doesn't come back: a draft needs review again
	st, _ := s.DB().State(eng, load(t, s, fd).F.Meta.ID)
	if st.ApprovedHash != "" {
		t.Fatal("approval kept")
	}
}

func TestTransitionReturnNeedsReason(t *testing.T) {
	s, _, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.Transition(eng, fd, workflow.Return, "  ", uBob); !denied(err) {
		t.Fatalf("err %v", err)
	}
	if load(t, s, fd).F.Meta.Status != "verification" {
		t.Fatal("returned without a reason")
	}
	if err := s.Transition(eng, fd, workflow.Return, "fix steps", uBob); err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	if m.Status != "draft" || m.Returned == nil || m.Returned.Reason != "fix steps" || m.Returned.By != "bob" {
		t.Fatalf("meta %+v", m)
	}
	if got := events(t, s, fd); got[len(got)-1] != "bob:return:fix steps" {
		t.Fatalf("events %v", got)
	}
	// resubmitting clears the returned marker
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if load(t, s, fd).F.Meta.Returned != nil {
		t.Fatal("returned kept after submit")
	}
}

// A clearance is bound to the content the reviewer saw: any later change —
// through YARS or straight into git (a push) — voids it.
func TestEditVoidsClearances(t *testing.T) {
	s, dir, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	if c := load(t, s, fd).F.Meta.ClearedBy; !reflect.DeepEqual(c, []string{"bob"}) {
		t.Fatalf("cleared %v", c)
	}
	if err := s.UpdateSection(eng, fd, "Impact", "changed after review", "", alice); err != nil {
		t.Fatal(err)
	}
	if c := load(t, s, fd).F.Meta.ClearedBy; len(c) != 0 {
		t.Fatalf("clearance survived an edit: %v", c)
	}
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	// an edit that bypasses the store (as a git push would)
	p := filepath.Join(dir, "engagements", eng, "findings", fd, "finding.md")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, []byte("\npushed text\n")...), 0o644)
	er, _ := s.EngRepo(eng)
	if err := er.Commit([]string{"findings/" + fd + "/finding.md"}, "push", gitrepo.Author{Name: "alice", Email: "alice@yars.local"}); err != nil {
		t.Fatal(err)
	}
	if c := load(t, s, fd).F.Meta.ClearedBy; len(c) != 0 {
		t.Fatalf("clearance survived a pushed edit: %v", c)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); !denied(err) {
		t.Fatalf("approved content nobody reviewed: %v", err)
	}
}

// The edit lock is enforced inside the store (against freshly loaded state),
// not only by the web layer.
func TestContentEditDeniedWhenLocked(t *testing.T) {
	s, dir, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	s.Transition(eng, fd, workflow.Approve, "", uDora)
	before := last(t, dir, "%H")
	if err := s.UpdateSection(eng, fd, "Impact", "late edit", "", uAlice); !denied(err) {
		t.Fatalf("section: %v", err)
	}
	if err := s.UpdateDetails(eng, fd, map[string]string{"Location": "x"}, "", uAlice); !denied(err) {
		t.Fatalf("details: %v", err)
	}
	if err := s.UpdateCVSS(eng, fd, "", nil, "", uAlice); !denied(err) {
		t.Fatalf("cvss: %v", err)
	}
	if err := s.UpdateSeverity(eng, fd, "low", "", uAlice); !denied(err) {
		t.Fatalf("severity: %v", err)
	}
	if last(t, dir, "%H") != before {
		t.Fatal("locked finding changed")
	}
	if err := s.UpdateSection(eng, fd, "Impact", "director fix", "", uDora); err != nil {
		t.Fatalf("director edit: %v", err)
	}
}

func TestSetReviewersDropsClearance(t *testing.T) {
	s, _, fd := ready(t)
	s.SetReviewers(eng, fd, []string{"bob", "carol"}, uAlice)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	s.Transition(eng, fd, workflow.Clear, "", uCarol)
	if err := s.SetReviewers(eng, fd, []string{"carol"}, uAlice); err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	if !reflect.DeepEqual(m.Reviewers, []string{"carol"}) || !reflect.DeepEqual(m.ClearedBy, []string{"carol"}) {
		t.Fatalf("meta %+v", m)
	}
}

func TestSetReviewersDropsAuthor(t *testing.T) {
	s, _, fd := newFinding(t)
	if err := s.SetReviewers(eng, fd, []string{"carol", "alice", "bob", "bob"}, uAlice); err != nil {
		t.Fatal(err)
	}
	if r := load(t, s, fd).F.Meta.Reviewers; !reflect.DeepEqual(r, []string{"bob", "carol"}) {
		t.Fatalf("reviewers %v", r)
	}
	if err := s.SetReviewers(eng, fd, []string{"bob"}, config.User{Username: "pen2", Role: "pentester"}); !denied(err) {
		t.Fatalf("non-author assigned: %v", err)
	}
}

// A new finding never reuses the number of a deleted one, or it would
// inherit that finding's status, reviewers and chat.
func TestNewFindingSkipsUsedIDs(t *testing.T) {
	s, dir, fd := ready(t)
	s.PostChat(eng, fd, chatMsg("old discussion"), uBob)
	ed := filepath.Join(dir, "engagements", eng)
	git(t, ed, "rm", "-rq", "findings/"+fd)
	git(t, ed, "commit", "-qm", "delete F-001")
	ref, err := s.CreateFinding(eng, "New issue", alice)
	if err != nil {
		t.Fatal(err)
	}
	if ref.F.Meta.ID == "F-001" {
		t.Fatal("deleted finding's number reused")
	}
	if msgs, _ := s.Chat(eng, ref.Dir); len(msgs) != 0 {
		t.Fatal("new finding inherited chat")
	}
}

// An engagement created under the name of a deleted one starts clean.
func TestRecreatedEngagementStartsClean(t *testing.T) {
	s, dir, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	s.PostChat(eng, fd, chatMsg("old"), uBob)
	git(t, dir, "rm", "-rq", "engagements/"+eng)
	git(t, dir, "commit", "-qm", "delete engagement")
	if err := s.CreateEngagement(Engagement{ID: eng, Name: "again"}, alice); err != nil {
		t.Fatal(err)
	}
	ref, _ := s.CreateFinding(eng, "Fresh", alice)
	m := load(t, s, ref.Dir).F.Meta
	if m.Status != "draft" || len(m.Reviewers) != 0 {
		t.Fatalf("inherited state %+v", m)
	}
	if msgs, _ := s.Chat(eng, ref.Dir); len(msgs) != 0 {
		t.Fatal("inherited chat")
	}
}

// Approval is bound to the approved content: if the text changes behind
// the store's back (a push racing the approve), the finding is back in
// verification. A director's own edit through YARS keeps it complete.
func TestApprovalBoundToContent(t *testing.T) {
	s, dir, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSection(eng, fd, "Impact", "director polish", "", uDora); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "complete" {
		t.Fatalf("director edit reopened the finding: %s", m.Status)
	}
	p := filepath.Join(dir, "engagements", eng, "findings", fd, "finding.md")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, []byte("\nsneaked in\n")...), 0o644)
	git(t, filepath.Join(dir, "engagements", eng), "commit", "-qam", "push that raced the approve")
	if m := load(t, s, fd).F.Meta; m.Status != "verification" || len(m.ClearedBy) != 0 {
		t.Fatalf("unreviewed change stayed complete: %+v", m)
	}
}

// Changing a retest result during review voids the clearances: reviewers
// cleared a different outcome.
func TestRetestResultChangeVoidsClearance(t *testing.T) {
	s, _ := srcFixture(t)
	s.CreateRetest(Engagement{ID: "rt", Name: "RT"}, eng, []string{"F-001-sql-injection"}, "", uDora)
	rt := "F-001-sql-injection"
	s.SetReviewers("rt", rt, []string{"bob"}, uAlice)
	s.SetRetestResult("rt", rt, "fixed", uAlice)
	s.UpdateSeverity("rt", rt, "high", "", alice)
	if err := s.Transition("rt", rt, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	s.Transition("rt", rt, workflow.Clear, "", uBob)
	if err := s.SetRetestResult("rt", rt, "not_fixed", uAlice); err != nil {
		t.Fatal(err)
	}
	ref, _ := s.Finding("rt", rt)
	if len(ref.F.Meta.ClearedBy) != 0 {
		t.Fatalf("clearance kept after the result changed: %v", ref.F.Meta.ClearedBy)
	}
}

// State is keyed by finding ID, so renaming the folder (e.g. by a push)
// keeps it.
func TestStateSurvivesRename(t *testing.T) {
	s, dir, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	base := filepath.Join(dir, "engagements", eng, "findings")
	if err := os.Rename(filepath.Join(base, fd), filepath.Join(base, "F-001-renamed")); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, "F-001-renamed").F.Meta; m.Status != "verification" || !reflect.DeepEqual(m.Reviewers, []string{"bob"}) {
		t.Fatalf("state lost on rename: %+v", m)
	}
}

// Without a database (a local clone used through stdio MCP) content can be
// read and edited, but workflow and chat say where to go instead.
func TestNoDatabase(t *testing.T) {
	dir := t.TempDir()
	r, _ := gitrepo.Init(dir)
	s := New(r, config.Default(), nil)
	s.CreateEngagement(Engagement{ID: eng, Name: "x"}, alice)
	ref, err := s.CreateFinding(eng, "SQLi", alice)
	if err != nil {
		t.Fatal(err)
	}
	if got := load(t, s, ref.Dir).F.Meta.Status; got != "draft" {
		t.Fatalf("status %q", got)
	}
	if err := s.Transition(eng, ref.Dir, workflow.Submit, "", uAlice); !errors.Is(err, ErrNoDB) {
		t.Fatalf("transition: %v", err)
	}
	if _, err := s.PostChat(eng, ref.Dir, chatMsg("hi"), uAlice); !errors.Is(err, ErrNoDB) {
		t.Fatalf("chat: %v", err)
	}
	if err := s.UpdateSection(eng, ref.Dir, "Impact", "x", "", alice); err != nil {
		t.Fatalf("content edit: %v", err)
	}
}
