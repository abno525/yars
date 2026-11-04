package workflow

import (
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/finding"
)

var (
	alice = config.User{Username: "alice", Role: "pentester"}
	pen2  = config.User{Username: "pen2", Role: "pentester"}
	bob   = config.User{Username: "bob", Role: "reviewer"}
	rev2  = config.User{Username: "rev2", Role: "reviewer"}
	dora  = config.User{Username: "dora", Role: "director"}
	adm   = config.User{Username: "adm", Role: "admin"}
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
		{alice, meta("complete"), Reopen, false},
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
	// author who is director still can't clear own finding
	m := meta("verification")
	m.Author = "dora"
	if Check(dora, m, Clear) == nil {
		t.Error("author cleared own finding")
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
		t.Error("director/admin should edit locked findings")
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
