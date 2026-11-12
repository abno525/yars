package workflow

import (
	"slices"
	"testing"

	"yars/internal/config"
	"yars/internal/finding"
)

// The bulk Set state menu of each role, in board order.
func TestBulkOptions(t *testing.T) {
	cases := map[string][]Action{
		"pentester": {Submit, TakeBack, Report, Reopen, Unreport, Withdraw},
		"reviewer":  {Clear, Return},
		"director":  {TakeBack, Submit, Approve, Report, Reopen, Unreport, Withdraw},
	}
	for role, want := range cases {
		var got []Action
		for _, o := range BulkOptions(config.User{Username: "x", Role: role}) {
			got = append(got, o.Action)
			if o.To == "" {
				t.Errorf("%s %s: no target", role, o.Action)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s menu %v, want %v", role, got, want)
		}
	}
	if o := BulkOptions(dora)[0]; o.Label != "Draft" || o.Verb != "take back" {
		t.Errorf("director first option %+v", o)
	}
	if o := BulkOptions(bob)[0]; o.Label != "Signed off" || o.Verb != "sign off" {
		t.Errorf("reviewer first option %+v", o)
	}
	if o := BulkOptions(alice)[5]; o.Label != "Withdrawn" || o.Verb != "" {
		t.Errorf("pentester withdraw option %+v", o)
	}
	// R4: the reverts, after Reported
	if o := BulkOptions(alice)[3]; o.Label != "Verification" || o.Verb != "revert" || o.To != "verification" {
		t.Errorf("pentester revert option %+v", o)
	}
	if o := BulkOptions(dora)[5]; o.Label != "Complete" || o.Verb != "revert" || o.To != "complete" {
		t.Errorf("director revert option %+v", o)
	}
	if BulkOptions(config.User{Username: "x", Role: "bogus"}) != nil {
		t.Error("unknown role has a menu")
	}
	// reviewers are assigned in bulk by reviewers and directors
	if BulkAssign(alice) || !BulkAssign(bob) || !BulkAssign(dora) {
		t.Error("BulkAssign by role")
	}
}

// Every allow and deny of the per-role bulk table: BulkCheck is the role's
// menu plus the per-finding Check.
func TestBulkCheckMatrix(t *testing.T) {
	signed := meta("verification", "bob")
	others := meta("draft")
	others.Author = "pen2"
	ownByBob := meta("verification")
	ownByBob.Author, ownByBob.Reviewers = "bob", []string{"rev2"}
	selfCleared := meta("verification", "dora")
	selfCleared.Reviewers = []string{"bob", "dora"}
	cases := []struct {
		u    config.User
		m    finding.Meta
		a    Action
		want bool
	}{
		// pentester, own findings only
		{alice, meta("draft"), Submit, true},
		{alice, others, Submit, false},
		{alice, meta("verification"), Submit, false},
		{alice, meta("verification"), TakeBack, true},
		{alice, signed, TakeBack, true},
		{alice, meta("draft"), TakeBack, false},
		{alice, meta("complete"), TakeBack, false},
		{pen2, meta("verification"), TakeBack, false},
		{alice, meta("complete"), Report, true},
		{alice, meta("verification"), Report, false},
		{alice, meta("reported"), Report, false},
		{pen2, meta("complete"), Report, false},
		{alice, meta("draft"), Withdraw, true},
		{pen2, meta("draft"), Withdraw, false},
		{alice, meta("complete"), Withdraw, false},
		// the bulk menu withdraws drafts only
		{alice, meta("verification"), Withdraw, false},
		{alice, meta("verification", "bob"), Approve, false}, // not on the menu
		{alice, meta("verification"), Clear, false},
		{alice, meta("verification"), Return, false},

		// reviewer, any finding they review
		{bob, meta("verification"), Clear, true},
		{bob, signed, Clear, false}, // already signed off
		{rev2, meta("verification"), Clear, false},
		{bob, meta("draft"), Clear, false},
		{bob, meta("verification"), Return, true},
		{bob, signed, Return, true},
		{rev2, meta("verification"), Return, false},
		{bob, meta("draft"), Return, false},
		{bob, meta("verification"), TakeBack, false}, // not on the menu
		{bob, meta("complete"), Report, false},
		{bob, signed, Approve, false},
		{bob, meta("draft"), Submit, false},
		{bob, meta("draft"), Withdraw, false},
		// a reviewer who wrote the finding: no sign-off, and the reviewer
		// menu has no submit
		{bob, ownByBob, Clear, false},
		{bob, ownByBob, Submit, false},

		// director, any finding
		{dora, meta("verification"), TakeBack, true},
		{dora, meta("draft"), TakeBack, false},
		{dora, meta("draft"), Submit, true},
		{dora, meta("verification"), Submit, false},
		{dora, signed, Approve, true},
		{dora, meta("verification"), Approve, false},
		{dora, selfCleared, Approve, false}, // only the director's own sign-off
		{dora, meta("verification", "bob"), Withdraw, true},
		{dora, meta("complete"), Report, true},
		{dora, meta("verification"), Report, false},
		{dora, meta("draft"), Withdraw, true},
		{dora, meta("reported"), Withdraw, true},
		{dora, meta("withdrawn"), Withdraw, false},
		{dora, meta("verification"), Clear, false}, // not on the menu
		{dora, meta("verification"), Return, false},
	}
	for _, c := range cases {
		err := BulkCheck(c.u, c.m, c.a)
		if (err == nil) != c.want {
			t.Errorf("%s %s on %s (author %s): err=%v want allowed=%v", c.u.Username, c.a, c.m.Status, c.m.Author, err, c.want)
		}
	}
}

// Take back and the author's mark reported are workflow transitions of
// their own, also on the finding page and the API.
func TestTakeBackAndAuthorReport(t *testing.T) {
	if from, to := Target(TakeBack); to != "draft" || !slices.Equal(from, []string{"verification"}) {
		t.Errorf("take back %v -> %q", from, to)
	}
	if a, ok := ParseAction("take_back"); !ok || a != TakeBack {
		t.Error("ParseAction take_back")
	}
	if Label(TakeBack) != "Take back" || NeedsReason(TakeBack) || Gated(TakeBack) {
		t.Error("take back label, reason, gate")
	}
	cases := []struct {
		u    config.User
		m    finding.Meta
		a    Action
		want bool
	}{
		{alice, meta("verification"), TakeBack, true},
		{pen2, meta("verification"), TakeBack, false},
		{bob, meta("verification"), TakeBack, false},
		{dora, meta("verification"), TakeBack, true},
		{alice, meta("complete"), Report, true},
		{pen2, meta("complete"), Report, false},
		{bob, meta("complete"), Report, false},
		{dora, meta("complete"), Report, true},
	}
	for _, c := range cases {
		if err := Check(c.u, c.m, c.a); (err == nil) != c.want {
			t.Errorf("%s %s on %s: err=%v want allowed=%v", c.u.Username, c.a, c.m.Status, err, c.want)
		}
	}
	// a reviewer may add reviewers while the finding is open; changing the
	// list (removing someone) stays with the author and directors
	if !CanAddReviewers(bob, meta("draft")) || !CanAddReviewers(rev2, meta("verification")) || !CanAddReviewers(alice, meta("draft")) ||
		!CanAddReviewers(dora, meta("verification")) || CanAddReviewers(bob, meta("complete")) || CanAddReviewers(pen2, meta("draft")) {
		t.Error("reviewer add rights")
	}
	if CanAssign(bob, meta("draft")) || CanAssign(rev2, meta("verification")) {
		t.Error("a reviewer may replace the reviewer list")
	}
	// a reviewer adds others, never themselves; a director joins freely
	if CanAddReviewer(rev2, meta("draft"), rev2.Username) || !CanAddReviewer(rev2, meta("draft"), "carol") ||
		!CanAddReviewer(dora, meta("verification"), dora.Username) || CanAddReviewer(pen2, meta("draft"), "carol") {
		t.Error("CanAddReviewer")
	}
}

// Who may tick which row of the bulk bar: a pentester own findings only, a
// reviewer or director any finding (a reviewer not assigned still picks a
// row to assign reviewers).
func TestBulkPick(t *testing.T) {
	others := meta("verification")
	others.Author = "pen2"
	cases := []struct {
		u    config.User
		m    finding.Meta
		want bool
	}{
		{alice, meta("draft"), true},
		{alice, meta("reported"), true},
		{alice, others, false},
		{pen2, meta("draft"), false},
		{bob, others, true},
		{rev2, meta("verification"), true},
		{dora, others, true},
		{config.User{Username: "x", Role: "bogus"}, meta("draft"), false},
	}
	for _, c := range cases {
		if got := BulkPick(c.u, c.m); got != c.want {
			t.Errorf("%s picks %s's %s: %v", c.u.Username, c.m.Author, c.m.Status, got)
		}
	}
}
