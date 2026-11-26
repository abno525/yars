package workflow

import (
	"slices"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
)

var (
	alice = config.User{Username: "alice", Role: "pentester"}
	pen2  = config.User{Username: "pen2", Role: "pentester"}
	bob   = config.User{Username: "bob", Role: "reviewer"}
	rev2  = config.User{Username: "rev2", Role: "reviewer"}
	dora  = config.User{Username: "dora", Role: "director"}
	adm   = config.User{Username: "dir2", Role: "director"} // a second director
)

func meta(status string, cleared ...string) finding.Meta {
	return finding.Meta{ID: "F-001", Title: "T", Status: status, Severity: "high", Author: "alice",
		Reviewers: []string{"bob"}, ClearedBy: cleared}
}

func TestCheckMatrix(t *testing.T) {
	cases := []struct {
		u    config.User
		m    finding.Meta
		a    Action
		want bool
	}{
		{alice, meta("draft"), Submit, true},
		{pen2, meta("draft"), Submit, false},
		{dora, meta("draft"), Submit, true},
		{adm, meta("draft"), Submit, true},
		{alice, meta("verification"), Submit, false},

		{bob, meta("verification"), Return, true},
		{rev2, meta("verification"), Return, false},
		{alice, meta("verification"), Return, false},
		{dora, meta("verification"), Return, true},
		{bob, meta("draft"), Return, false},

		{bob, meta("verification"), Clear, true},
		{bob, meta("verification", "bob"), Clear, false},
		{rev2, meta("verification"), Clear, false},
		{alice, meta("verification"), Clear, false},
		{dora, meta("verification"), Clear, true}, // roles only add power: a director may review unassigned
		{adm, meta("verification"), Clear, true},
		{dora, meta("verification", "dora"), Clear, false},
		{bob, meta("draft"), Clear, false},

		{dora, meta("verification", "bob"), Approve, true},
		{dora, meta("verification", "dora"), Approve, false}, // own clearance doesn't count
		{dora, meta("verification", "rev2"), Approve, false}, // clearance by a non-reviewer doesn't count
		{dora, meta("verification"), Approve, false},
		{bob, meta("verification", "bob"), Approve, false},
		{adm, meta("verification", "bob"), Approve, true},

		{dora, meta("complete"), Reopen, true},
		{alice, meta("complete"), Reopen, true}, // R4: the author reverts their own finding
		{dora, meta("verification"), Reopen, false},

		{dora, meta("complete"), Report, true},
		{bob, meta("complete"), Report, false},
		{dora, meta("verification"), Report, false},
	}
	for _, c := range cases {
		err := Check(c.u, c.m, c.a)
		if (err == nil) != c.want {
			t.Errorf("%s %s on %s: err=%v want allowed=%v", c.u.Username, c.a, c.m.Status, err, c.want)
		}
	}
	// Q25: a director signs off their own finding; their sign-off alone
	// does not let them approve it
	m := meta("verification")
	m.Author = "dora"
	if err := Check(dora, m, Clear); err != nil {
		t.Errorf("director signs off own finding: %v", err)
	}
	m.Reviewers, m.ClearedBy = []string{"bob", "dora"}, []string{"dora"}
	if Check(dora, m, Approve) == nil {
		t.Error("the author approved on her own sign-off")
	}
	// another director approves on it, as on any director's sign-off
	if err := Check(adm, m, Approve); err != nil || Pending(adm, m) != InboxApprove {
		t.Errorf("a second director on the author's sign-off: %v %q", err, Pending(adm, m))
	}
	// any other author still can't, even assigned (a hand edit)
	own := meta("verification")
	own.Author, own.Reviewers = "bob", []string{"bob"}
	if err := Check(bob, own, Clear); err == nil || err.Error() != "only a director can sign off their own finding" {
		t.Errorf("reviewer signs off own finding: %v", err)
	}
	// every role from reviewer up can be assigned as a reviewer
	for _, u := range []config.User{bob, dora, adm} {
		if !ReviewerCandidate(u, meta("draft")) {
			t.Errorf("%s (%s) should be a reviewer candidate", u.Username, u.Role)
		}
	}
	if ReviewerCandidate(pen2, meta("draft")) {
		t.Error("pentester is a reviewer candidate")
	}
	if !AtLeast(adm, "director") || !AtLeast(dora, "reviewer") || AtLeast(bob, "director") || AtLeast(config.User{Role: "bogus"}, "pentester") {
		t.Error("AtLeast ladder wrong")
	}
	// a director assigned as reviewer may clear
	m = meta("verification")
	m.Reviewers = []string{"dora"}
	if err := Check(dora, m, Clear); err != nil {
		t.Errorf("assigned director clear: %v", err)
	}
}

func TestWithdrawRevise(t *testing.T) {
	cases := []struct {
		u    config.User
		m    finding.Meta
		a    Action
		want bool
	}{
		{alice, meta("draft"), Withdraw, true},
		{alice, meta("verification"), Withdraw, true},
		{alice, meta("complete"), Withdraw, false}, // the author only while open
		{alice, meta("reported"), Withdraw, false},
		{pen2, meta("draft"), Withdraw, false},
		{bob, meta("verification"), Withdraw, false}, // a reviewer is not the author
		{dora, meta("draft"), Withdraw, true},
		{dora, meta("verification"), Withdraw, true},
		{dora, meta("complete"), Withdraw, true},
		{dora, meta("reported"), Withdraw, true},
		{dora, meta("withdrawn"), Withdraw, false},

		{alice, meta("withdrawn"), Revise, true},
		{dora, meta("withdrawn"), Revise, true},
		{pen2, meta("withdrawn"), Revise, false},
		{bob, meta("withdrawn"), Revise, false},
		{alice, meta("draft"), Revise, false},

		{dora, meta("withdrawn"), Submit, false},
		{dora, meta("withdrawn"), Report, false},
		{dora, meta("withdrawn"), Approve, false},
	}
	for _, c := range cases {
		err := Check(c.u, c.m, c.a)
		if (err == nil) != c.want {
			t.Errorf("%s %s on %s: err=%v want allowed=%v", c.u.Username, c.a, c.m.Status, err, c.want)
		}
	}
	if _, to := Target(Withdraw); to != "withdrawn" {
		t.Errorf("withdraw goes to %q", to)
	}
	if from, to := Target(Revise); to != "draft" || len(from) != 1 || from[0] != "withdrawn" {
		t.Errorf("revise %v -> %q", from, to)
	}
	if !NeedsReason(Withdraw) || !NeedsReason(Return) || NeedsReason(Revise) || NeedsReason(Clear) {
		t.Error("NeedsReason")
	}
	// withdrawn findings: locked for non-directors, no reviewers, never pending
	w := meta("withdrawn", "bob")
	if CanEdit(alice, w) || !CanEdit(dora, w) || CanAssign(alice, w) || CanAssign(dora, w) {
		t.Error("withdrawn edit/assign rights")
	}
	w.Returned = &finding.Returned{By: "bob", Reason: "x"}
	for _, u := range []config.User{alice, bob, dora} {
		if Pending(u, w) != InboxNone {
			t.Errorf("withdrawn pending for %s", u.Username)
		}
	}
	if !slices.Contains(AllStatuses, "withdrawn") || slices.Contains(Statuses, "withdrawn") {
		t.Error("withdrawn is a status but not a workflow step")
	}
}

// R4: reported goes back to complete, by the author or a director.
func TestUnreportTargetAndWho(t *testing.T) {
	if from, to := Target(Unreport); to != "complete" || !slices.Equal(from, []string{"reported"}) {
		t.Fatalf("unreport %v -> %q", from, to)
	}
	for _, c := range []struct {
		u    config.User
		want bool
	}{{alice, true}, {dora, true}, {adm, true}, {bob, false}, {pen2, false}} {
		if err := Check(c.u, meta("reported"), Unreport); (err == nil) != c.want {
			t.Errorf("%s: %v", c.u.Username, err)
		}
	}
	if err := Check(bob, meta("reported"), Unreport); err == nil || err.Error() != "only the author or a director can revert a finding" {
		t.Errorf("reviewer: %v", err)
	}
	for _, st := range []string{"draft", "verification", "complete", "withdrawn"} {
		if err := Check(dora, meta(st), Unreport); err == nil || !strings.Contains(err.Error(), "only possible in reported") {
			t.Errorf("unreport on %s: %v", st, err)
		}
	}
	if !slices.Contains(Actions, Unreport) || slices.Index(Actions, Unreport) != slices.Index(Actions, Report)+1 {
		t.Errorf("Actions %v", Actions)
	}
}

// R4: the author may revert their own complete finding to verification;
// another pentester and a reviewer may not.
func TestReopenByAuthor(t *testing.T) {
	if err := Check(alice, meta("complete"), Reopen); err != nil {
		t.Fatalf("author: %v", err)
	}
	for _, u := range []config.User{pen2, bob} {
		if err := Check(u, meta("complete"), Reopen); err == nil || err.Error() != "only the author or a director can revert a finding" {
			t.Errorf("%s: %v", u.Username, err)
		}
	}
}

func TestRevertNeedsReason(t *testing.T) {
	if !NeedsReason(Reopen) || !NeedsReason(Unreport) {
		t.Fatal("a revert needs a reason")
	}
}

func TestRevertOf(t *testing.T) {
	for st, want := range map[string]Action{"complete": Reopen, "reported": Unreport} {
		if a, ok := RevertOf(st); !ok || a != want {
			t.Errorf("RevertOf(%s) = %q, %v", st, a, ok)
		}
	}
	for _, st := range []string{"draft", "verification", "withdrawn"} {
		if _, ok := RevertOf(st); ok {
			t.Errorf("RevertOf(%s) is ok", st)
		}
	}
}

func TestRevertLabel(t *testing.T) {
	if Label(Reopen) != "Revert" || Label(Unreport) != "Revert" {
		t.Fatalf("labels %q %q", Label(Reopen), Label(Unreport))
	}
	// both are "Revert": a refusal for the wrong status says which one
	if err := Check(dora, meta("reported"), Reopen); err == nil || err.Error() != "Revert to verification is only possible in complete (finding is reported)" {
		t.Errorf("reopen on reported: %v", err)
	}
	if err := Check(dora, meta("complete"), Unreport); err == nil || err.Error() != "Revert to complete is only possible in reported (finding is complete)" {
		t.Errorf("unreport on complete: %v", err)
	}
}

func TestParseAction(t *testing.T) {
	for in, want := range map[string]Action{"clear": Clear, "sign_off": Clear, "Sign_Off": Clear, " submit ": Submit,
		"report": Report, "withdraw": Withdraw, "revise": Revise, "unreport": Unreport, "reopen": Reopen} {
		if got, ok := ParseAction(in); !ok || got != want {
			t.Errorf("ParseAction(%q) = %q, %v", in, got, ok)
		}
	}
	// revert is resolved by callers (RevertOf), not parsed
	for _, in := range []string{"", "bogus", "signoff2", "revert"} {
		if _, ok := ParseAction(in); ok {
			t.Errorf("ParseAction(%q) accepted", in)
		}
	}
	if Label(Clear) != "Sign off" || Label(Report) != "Mark reported" || Label(Withdraw) != "Withdraw" || Label(Revise) != "Restore" {
		t.Errorf("labels: %q %q %q %q", Label(Clear), Label(Report), Label(Withdraw), Label(Revise))
	}
}

func TestApproveGate(t *testing.T) {
	m := meta("verification", "bob")
	m.Severity, m.CVSS = "", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"
	if err := CheckWithGate(dora, m, Approve, config.Default()); err == nil || !strings.Contains(err.Error(), "Attack Complexity") {
		t.Fatalf("approve with unexplained CVSS: %v", err)
	}
	m.CVSSReasons = map[string]string{"AC": "race"}
	if err := CheckWithGate(dora, m, Approve, config.Default()); err != nil {
		t.Fatalf("approve: %v", err)
	}
}

func TestGate(t *testing.T) {
	cfg := config.Default()
	ok := meta("draft")
	if p := Gate(ok, cfg); len(p) != 0 {
		t.Fatalf("valid meta blocked: %v", p)
	}
	m := ok
	m.Reviewers = nil
	if p := strings.Join(Gate(m, cfg), ";"); !strings.Contains(p, "reviewer") {
		t.Errorf("no reviewers: %q", p)
	}
	m = ok
	m.Title = " "
	if p := strings.Join(Gate(m, cfg), ";"); !strings.Contains(p, "title") {
		t.Errorf("empty title: %q", p)
	}
	m = ok
	m.Severity = ""
	if p := strings.Join(Gate(m, cfg), ";"); !strings.Contains(p, "severity") {
		t.Errorf("no severity: %q", p)
	}
	m = ok
	m.Severity, m.CVSS = "", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"
	if p := strings.Join(Gate(m, cfg), ";"); !strings.Contains(p, "Attack Complexity") || strings.Contains(p, "severity") {
		t.Errorf("missing explanation: %q", p)
	}
	m.CVSSReasons = map[string]string{"AC": "race"}
	if p := Gate(m, cfg); len(p) != 0 {
		t.Errorf("explained vector blocked: %v", p)
	}
}

func TestGateNeedsRetestResult(t *testing.T) {
	m := meta("draft")
	m.Retest = &finding.Retest{Source: "old/F-001-x"}
	if p := strings.Join(Gate(m, config.Default()), ";"); !strings.Contains(p, "retest result") {
		t.Fatalf("got %q", p)
	}
	m.Retest.Result = "partially_fixed"
	if p := Gate(m, config.Default()); len(p) != 0 {
		t.Fatalf("got %v", p)
	}
	if RetestLabel("not_fixed") != "Not fixed" || len(RetestResults) != 3 {
		t.Fatal("labels")
	}
}

func TestCanEdit(t *testing.T) {
	if !CanEdit(pen2, meta("draft")) || !CanEdit(bob, meta("verification")) {
		t.Error("open statuses should be editable")
	}
	if CanEdit(alice, meta("complete")) || CanEdit(bob, meta("reported")) {
		t.Error("locked statuses editable by non-director")
	}
	if !CanEdit(dora, meta("complete")) || !CanEdit(adm, meta("reported")) {
		t.Error("directors should edit locked findings")
	}
}

func TestCanAssign(t *testing.T) {
	if !CanAssign(alice, meta("draft")) || !CanAssign(dora, meta("verification")) {
		t.Error("author/director should assign")
	}
	if CanAssign(pen2, meta("draft")) || CanAssign(alice, meta("complete")) {
		t.Error("assign allowed wrongly")
	}
	if !ReviewerCandidate(bob, meta("draft")) || ReviewerCandidate(pen2, meta("draft")) {
		t.Error("candidate roles wrong")
	}
	m := meta("draft")
	m.Author = "bob"
	if ReviewerCandidate(bob, m) {
		t.Error("author as own reviewer")
	}
}

func TestPending(t *testing.T) {
	if Pending(bob, meta("verification")) != InboxReview {
		t.Error("review")
	}
	if Pending(bob, meta("verification", "bob")) != InboxNone {
		t.Error("cleared reviewer still pending")
	}
	if Pending(dora, meta("verification", "bob")) != InboxApprove {
		t.Error("approve")
	}
	m := meta("draft")
	m.Returned = &finding.Returned{By: "bob", Reason: "x"}
	if Pending(alice, m) != InboxReturned || Pending(pen2, m) != InboxNone {
		t.Error("returned")
	}
}
