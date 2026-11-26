package store

import (
	"errors"
	"image/color"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/workflow"
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

// Q25: a director signs off their own finding and joins its reviewers;
// approving it still needs a sign-off by another assigned reviewer.
func TestDirectorSignsOffOwnFinding(t *testing.T) {
	s, _ := withEngagement(t)
	f, err := s.CreateFinding(eng, "XSS", uDora.GitAuthor())
	if err != nil {
		t.Fatal(err)
	}
	s.SetReviewers(eng, f.Dir, []string{"bob"}, uDora)
	s.UpdateSeverity(eng, f.Dir, "high", "", uDora)
	if err := s.Transition(eng, f.Dir, workflow.Submit, "", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, f.Dir, workflow.Clear, "", uDora); err != nil {
		t.Fatalf("own sign-off: %v", err)
	}
	m := load(t, s, f.Dir).F.Meta
	if !reflect.DeepEqual(m.Reviewers, []string{"bob", "dora"}) || !reflect.DeepEqual(m.ClearedBy, []string{"dora"}) {
		t.Fatalf("reviewers %v cleared %v", m.Reviewers, m.ClearedBy)
	}
	if err := s.Transition(eng, f.Dir, workflow.Approve, "", uDora); !denied(err) {
		t.Fatalf("approved on her own sign-off: %v", err)
	}
	if err := s.Transition(eng, f.Dir, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, f.Dir, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
}

// Q25: the director's own sign-off is kept when the reviewer list is saved
// (no list can name her): a reviewer still only adds, and her list without
// her keeps it. Once a return took the sign-off, the next list drops her.
func TestSetReviewersKeepsOwnSignOff(t *testing.T) {
	s, _ := withEngagement(t)
	f, err := s.CreateFinding(eng, "XSS", uDora.GitAuthor())
	if err != nil {
		t.Fatal(err)
	}
	s.SetReviewers(eng, f.Dir, []string{"bob"}, uDora)
	s.UpdateSeverity(eng, f.Dir, "high", "", uDora)
	s.Transition(eng, f.Dir, workflow.Submit, "", uDora)
	if err := s.Transition(eng, f.Dir, workflow.Clear, "", uDora); err != nil {
		t.Fatal(err)
	}
	check := func(reviewers, cleared []string) {
		t.Helper()
		if m := load(t, s, f.Dir).F.Meta; !reflect.DeepEqual(m.Reviewers, reviewers) || !reflect.DeepEqual(m.ClearedBy, cleared) {
			t.Fatalf("reviewers %v cleared %v", m.Reviewers, m.ClearedBy)
		}
	}
	if err := s.SetReviewers(eng, f.Dir, []string{"bob", "carol"}, uBob); err != nil {
		t.Fatalf("a reviewer adds: %v", err)
	}
	check([]string{"bob", "carol", "dora"}, []string{"dora"})
	if err := s.SetReviewers(eng, f.Dir, []string{"carol"}, uDora); err != nil {
		t.Fatal(err)
	}
	check([]string{"carol", "dora"}, []string{"dora"})
	if err := s.SetReviewers(eng, f.Dir, nil, uDora); !denied(err) {
		t.Fatalf("her own entry kept a finding in verification reviewed: %v", err)
	}
	if err := s.Transition(eng, f.Dir, workflow.Return, "again", uCarol); err != nil {
		t.Fatal(err)
	}
	if err := s.SetReviewers(eng, f.Dir, []string{"carol"}, uDora); err != nil {
		t.Fatal(err)
	}
	check([]string{"carol"}, nil)
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
	if err := s.Transition(eng, fd, workflow.Reopen, "wrong host", uDora); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "verification" || len(m.ClearedBy) != 0 {
		t.Fatalf("reopen %+v", m)
	}
	want := []string{"alice:submit:", "bob:clear:", "dora:approve:", "dora:reopen:wrong host"}
	if got := events(t, s, fd); !reflect.DeepEqual(got, want) {
		t.Fatalf("events %v", got)
	}
}

// completed returns a finding by alice that bob signed off and dora
// approved.
func completed(t *testing.T) (*Store, string) {
	t.Helper()
	s, _, fd := ready(t)
	for _, step := range []struct {
		a workflow.Action
		u config.User
	}{{workflow.Submit, uAlice}, {workflow.Clear, uBob}, {workflow.Approve, uDora}} {
		if err := s.Transition(eng, fd, step.a, "", step.u); err != nil {
			t.Fatal(err)
		}
	}
	return s, fd
}

// R4: reverting Reported asks for no new approval: the approval and the
// sign-offs stay.
func TestUnreportKeepsApproval(t *testing.T) {
	s, fd := completed(t)
	before, _ := s.DB().State(eng, "F-001")
	if err := s.Transition(eng, fd, workflow.Report, "", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Unreport, "sent too early", uDora); err != nil {
		t.Fatal(err)
	}
	after, _ := s.DB().State(eng, "F-001")
	if after.Status != "complete" || after.ApprovedHash == "" || after.ApprovedHash != before.ApprovedHash || !reflect.DeepEqual(after.Reviewers, before.Reviewers) {
		t.Fatalf("after unreport %+v, before %+v", after, before)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "complete" {
		t.Fatalf("shown as %s", m.Status)
	}
}

// R4, Review focus 1: a finding sent to Confluence or Jira keeps its page
// through a revert, so the next send updates the same page.
func TestUnreportKeepsRemoteLink(t *testing.T) {
	s, fd := completed(t)
	if err := s.DB().SetExportRemote(db.ExportRemote{Destination: "wiki", Eng: eng, Finding: "F-001", Target: "SPACE", RemoteID: "42", Version: 3, URL: "https://wiki.example/42"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Report, "", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Unreport, "sent too early", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Reopen, "wrong host", uDora); err != nil {
		t.Fatal(err)
	}
	if r, ok, err := s.DB().ExportRemote("wiki", eng, "F-001"); err != nil || !ok || r.RemoteID != "42" || r.Version != 3 {
		t.Fatalf("remote link %+v %v %v", r, ok, err)
	}
}

// R4, Review focus 3: a blank reason is refused for both reverts.
func TestRevertNeedsReasonInStore(t *testing.T) {
	s, fd := completed(t)
	if err := s.Transition(eng, fd, workflow.Reopen, "  ", uDora); !denied(err) || !strings.Contains(err.Error(), "a reason is required") {
		t.Fatalf("reopen without a reason: %v", err)
	}
	if err := s.Transition(eng, fd, workflow.Report, "", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Unreport, "  ", uDora); !denied(err) || !strings.Contains(err.Error(), "a reason is required") {
		t.Fatalf("unreport without a reason: %v", err)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "reported" {
		t.Fatalf("a refused revert moved it to %s", m.Status)
	}
}

// R4: the revert is in the history with its reason: the chat's event and
// the domain event.
func TestRevertEventCarriesReason(t *testing.T) {
	s, fd := completed(t)
	rec := &recorder{}
	s.OnEvent(rec.add)
	if err := s.Transition(eng, fd, workflow.Report, "", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Unreport, " sent too early ", uAlice); err != nil {
		t.Fatal(err)
	}
	got := events(t, s, fd)
	if got[len(got)-1] != "alice:unreport:sent too early" {
		t.Fatalf("events %v", got)
	}
	if e := rec.last(EventStatus); e.Action != "unreport" || e.From != "reported" || e.To != "complete" || e.Reason != "sent too early" {
		t.Fatalf("event %+v", e)
	}
	if err := s.Transition(eng, fd, workflow.Reopen, "wrong host", uAlice); err != nil {
		t.Fatal(err)
	}
	if e := rec.last(EventStatus); e.Action != "reopen" || e.From != "complete" || e.To != "verification" || e.Reason != "wrong host" {
		t.Fatalf("reopen event %+v", e)
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

// A sign-off covers the attachments too: an upload or a redaction while the
// finding is in verification drops the sign-offs, as a text change does. An
// approved finding keeps its sign-offs (and its approval) when a director
// adds one.
func TestAttachmentChangeVoidsClearances(t *testing.T) {
	s, _, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	signed := func(before string) {
		t.Helper()
		if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
			t.Fatal(err)
		}
		if c := load(t, s, fd).F.Meta.ClearedBy; !reflect.DeepEqual(c, []string{"bob"}) {
			t.Fatalf("before %s: cleared %v", before, c)
		}
	}
	signed("an upload")
	if _, err := s.AddAttachment(eng, fd, "shot.png", pngBytes(t, color.White), uAlice); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "verification" || len(m.ClearedBy) != 0 {
		t.Fatalf("after an upload: %s, cleared %v", m.Status, m.ClearedBy)
	}
	signed("a redaction")
	if err := s.ReplaceAttachment(eng, fd, "shot.png", pngBytes(t, color.Black), uBob); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "verification" || len(m.ClearedBy) != 0 {
		t.Fatalf("after a redaction: %s, cleared %v", m.Status, m.ClearedBy)
	}
	signed("the approval")
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAttachment(eng, fd, "more.png", pngBytes(t, color.White), uDora); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "complete" || !reflect.DeepEqual(m.ClearedBy, []string{"bob"}) {
		t.Fatalf("approved finding after an upload: %s, cleared %v", m.Status, m.ClearedBy)
	}
}

// A sign-off is for the attachments the page showed too: one sent with the
// attachments as they were before an upload is refused, as one after a text
// edit is; with them as they are now it counts.
func TestSignOffBindsToViewedAttachments(t *testing.T) {
	s, _, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	seen := load(t, s, fd).Full
	files, err := s.AttachmentsHash(eng, fd)
	if err != nil || files == "" {
		t.Fatalf("attachments hash %q: %v", files, err)
	}
	if _, err := s.AddAttachment(eng, fd, "shot.png", pngBytes(t, color.White), uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.TransitionSeen(eng, fd, workflow.Clear, "", seen, files, uBob); !errors.Is(err, ErrConflict) {
		t.Fatalf("a sign-off for the attachments before the upload: %v", err)
	}
	if c := load(t, s, fd).F.Meta.ClearedBy; len(c) != 0 {
		t.Fatalf("bob signed off attachments he did not see: %v", c)
	}
	now, err := s.AttachmentsHash(eng, fd)
	if err != nil || now == files {
		t.Fatalf("the upload left the attachments hash %q: %v", now, err)
	}
	if err := s.TransitionSeen(eng, fd, workflow.Clear, "", seen, now, uBob); err != nil {
		t.Fatal(err)
	}
	if c := load(t, s, fd).F.Meta.ClearedBy; !reflect.DeepEqual(c, []string{"bob"}) {
		t.Fatalf("a sign-off on the current attachments: %v", c)
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

// A finding in verification keeps at least one reviewer, or nobody could
// sign it off: emptying the list is refused, for the author and a director
// alike; in draft the list may be empty (backlog, M3).
func TestReviewersNotEmptiedInVerification(t *testing.T) {
	s, _, fd := ready(t)
	if err := s.SetReviewers(eng, fd, nil, uAlice); err != nil {
		t.Fatalf("draft: %v", err)
	}
	s.SetReviewers(eng, fd, []string{"bob"}, uAlice)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	for _, u := range []config.User{uAlice, uDora} {
		if err := s.SetReviewers(eng, fd, nil, u); !denied(err) || !strings.Contains(err.Error(), "at least one reviewer") {
			t.Fatalf("%s emptied the list: %v", u.Username, err)
		}
	}
	if r := load(t, s, fd).F.Meta.Reviewers; !reflect.DeepEqual(r, []string{"bob"}) {
		t.Fatalf("reviewers %v", r)
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
