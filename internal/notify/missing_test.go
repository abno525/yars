package notify

import (
	"slices"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/store"
)

// nobody checks that none of the users got a notice.
func nobody(t *testing.T, d *db.DB, names ...string) {
	t.Helper()
	for _, u := range names {
		if got := list(t, d, u); got != "" {
			t.Errorf("%s: %s", u, got)
		}
	}
}

// The author hears of a new thread on their finding: not of a reply, not of
// their own thread, and once when the thread also mentions them.
func TestNewThreadTellsTheAuthor(t *testing.T) {
	n, d, _ := newNotifier(t)
	e := ev(store.EventChat)
	e.Actor, e.Text, e.MsgID = "rev1", "which roles?", "m-1"
	n.Handle(e)
	e.Actor, e.Text, e.MsgID = "pen1", "note to self", "m-2" // the author's own thread
	n.Handle(e)
	e.Actor, e.Text, e.MsgID = "rev2", "@pen1 and this?", "m-3" // a mention says it already
	n.Handle(e)
	e.Actor, e.Text, e.MsgID, e.Reply, e.ReplyTo = "rev2", "admins only", "m-4", "m-1", "rev1" // a reply in rev1's thread
	n.Handle(e)
	n.Wait()
	if got := list(t, d, "pen1"); got != "thread:rev1:which roles?,mentioned:rev2:@pen1 and this?" {
		t.Fatalf("pen1: %s", got)
	}
	if got := list(t, d, "rev1"); got != "reply:rev2:admins only" {
		t.Fatalf("rev1: %s", got)
	}
	l, _ := d.Notifications("pen1", 10)
	if Target(l[1]) != "/e/demo/f/005#t-m-1" {
		t.Fatalf("the notice leads to %q", Target(l[1]))
	}
	nobody(t, d, "rev2", "out", "gone", "dir1")
}

// A sign-off tells the author; a withdrawal, a restore and a report tell the
// author and the reviewers. Never the one who did it.
func TestStatusNotices(t *testing.T) {
	n, d, _ := newNotifier(t)
	e := ev(store.EventStatus)
	e.Reviewers = []string{"rev1", "rev2", "out", "gone"}
	e.Actor, e.Action = "rev1", "clear"
	n.Handle(e)
	e.Actor, e.Action, e.Reason = "dir1", "withdraw", "duplicate of F-002"
	n.Handle(e)
	e.Actor, e.Action, e.Reason = "pen1", "revise", ""
	n.Handle(e)
	e.Actor, e.Action = "rev2", "report"
	n.Handle(e)
	n.Wait()
	if got := list(t, d, "pen1"); got != "signed_off:rev1:,withdrawn:dir1:duplicate of F-002,reported:rev2:" {
		t.Errorf("pen1: %s", got)
	}
	if got := list(t, d, "rev1"); got != "withdrawn:dir1:duplicate of F-002,reverted:pen1:,reported:rev2:" {
		t.Errorf("rev1: %s", got)
	}
	if got := list(t, d, "rev2"); got != "withdrawn:dir1:duplicate of F-002,reverted:pen1:" {
		t.Errorf("rev2: %s", got)
	}
	nobody(t, d, "out", "gone", "dir1")
}

// A reviewer whose sign-off an edit voided is asked to review again; one
// taken off the list of a finding in verification is told.
func TestVoidedAndRemovedReviewers(t *testing.T) {
	n, d, _ := newNotifier(t)
	e := ev(store.EventUpdated)
	e.Actor, e.Changed, e.Voided = "pen1", []string{"Impact"}, []string{"rev1", "rev2", "out", "gone", "pen1"}
	n.Handle(e)
	e.Voided = nil // an edit that voids nothing tells nobody
	n.Handle(e)
	e = ev(store.EventReviewers)
	e.Actor, e.Removed, e.State = "pen1", []string{"rev2", "out"}, "verification"
	n.Handle(e)
	e.Removed, e.State = []string{"rev1"}, "draft" // nothing was asked of them yet
	n.Handle(e)
	n.Wait()
	if got := list(t, d, "rev1"); got != "review:pen1:sign-off voided" {
		t.Errorf("rev1: %s", got)
	}
	if got := list(t, d, "rev2"); got != "review:pen1:sign-off voided,unassigned:pen1:" {
		t.Errorf("rev2: %s", got)
	}
	nobody(t, d, "pen1", "out", "gone", "dir1")
}

// The retester of a new retest is told, with a notice that has no finding;
// its mail and its link lead to the retest.
func TestRetestAssignee(t *testing.T) {
	n, d, m := newNotifier(t)
	d.SetNotify("pen1", "retest", "app", true)
	d.SetNotify("pen1", "retest", "email", true)
	e := store.Event{Kind: store.EventRetest, Actor: "dir1", Eng: "demo-rt", Title: "Demo retest", Assignee: "pen1"}
	n.Handle(e)
	e.Actor, e.Assignee = "dir1", "dir1" // made for oneself
	n.Handle(e)
	e.Assignee = "out" // not on the team
	n.Handle(e)
	n.Wait()
	l, _ := d.Notifications("pen1", 10)
	if len(l) != 1 || l[0].Event != "retest" || l[0].Eng != "demo-rt" || l[0].Fid != "" || l[0].Title != "Demo retest" || l[0].Actor != "dir1" {
		t.Fatalf("pen1: %+v", l)
	}
	if Target(l[0]) != "/e/demo-rt" || Label("retest") != "Retest assigned" {
		t.Fatalf("target %q label %q", Target(l[0]), Label("retest"))
	}
	nobody(t, d, "dir1", "out")
	if len(m.sent) != 1 || m.sent[0].subject != "[YARS] Retest assigned: Demo retest" ||
		!strings.Contains(m.sent[0].body, "https://yars.example.com/e/demo-rt\n") || strings.Contains(m.sent[0].body, "/f/") {
		t.Fatalf("mail %+v", m.sent)
	}
}

// @name in a message on the team board tells that person; the notice leads
// to the lead.
func TestBoardMention(t *testing.T) {
	n, d, m := newNotifier(t)
	d.SetNotify("pen1", Mentioned, "app", true)
	d.SetNotify("pen1", Mentioned, "email", true)
	e := store.Event{Kind: store.EventBoard, Actor: "rev1", Eng: "demo", Note: "L-003", Title: "Odd header on /login", Text: "@pen1 can you look? cc @out @rev1"}
	n.Handle(e)
	n.Wait()
	l, _ := d.Notifications("pen1", 10)
	if len(l) != 1 || l[0].Event != Mentioned || l[0].Ref != "L-003" || l[0].Fid != "" || l[0].Dir != "" || l[0].Title != "Odd header on /login" ||
		l[0].Text != "@pen1 can you look? cc @out @rev1" {
		t.Fatalf("pen1: %+v", l)
	}
	if Target(l[0]) != "/e/demo/board?n=L-003" {
		t.Fatalf("target %q", Target(l[0]))
	}
	nobody(t, d, "rev1", "out", "gone")
	if len(m.sent) != 1 || m.sent[0].subject != "[YARS] Mentioned: L-003 Odd header on /login" || !strings.Contains(m.sent[0].body, "https://yars.example.com/e/demo/board?n=L-003\n") {
		t.Fatalf("mail %+v", m.sent)
	}
	// a lead's id that is no id leads to the engagement
	if got := Target(db.Notification{Event: Mentioned, Eng: "demo", Ref: "L-1/../x"}); got != "/e/demo" {
		t.Fatalf("target of a bad id: %q", got)
	}
}

// A check the author started tells nobody: they are on the page. A run
// someone else started tells the author.
func TestOwnCheckRunTellsNobody(t *testing.T) {
	n, d, m := newNotifier(t)
	d.SetNotify("pen1", Check, "app", true)
	d.SetNotify("pen1", Check, "email", true)
	e := ev(store.EventCheck)
	e.Actor, e.State, e.Errors = "pen1", "done", 1
	n.Handle(e)
	n.Wait()
	if got := list(t, d, "pen1"); got != "" || len(m.sent) != 0 {
		t.Fatalf("the author was told of their own run: %q, %d mails", got, len(m.sent))
	}
	e.Actor = "dir1"
	n.Handle(e)
	n.Wait()
	if got := list(t, d, "pen1"); got != "check:dir1:1 error · 0 warnings" || len(m.sent) != 1 {
		t.Fatalf("another's run: %q, %d mails", got, len(m.sent))
	}
}

// Every notice that came after the first nine is one the database switched
// on for the accounts that had saved choices (migration 030): a key missing
// there would be off for them without a word.
func TestLaterKeysHaveTheirDefault(t *testing.T) {
	first := []string{Returned, Review, Reply, Approved, Mentioned, Check, Token, TakenBack, Reverted}
	var later []string
	for _, e := range Events {
		if !slices.Contains(first, e.Key) {
			later = append(later, e.Key)
		}
	}
	slices.Sort(later)
	want := slices.Sorted(slices.Values(db.LaterNoticeKeys))
	if !slices.Equal(later, want) {
		t.Fatalf("later keys %v, the migration has %v: a new key needs a migration that gives it to the accounts with saved choices", later, want)
	}
}

// The simple workflow lists the notices it can send: no sign-off, no
// unassigned reviewer.
func TestNewEventsInTheSettings(t *testing.T) {
	keys := func(simple bool) string {
		var out []string
		for _, e := range EventsFor(simple) {
			out = append(out, e.Key)
		}
		return strings.Join(out, ",")
	}
	if got := keys(false); got != "returned,review,taken_back,unassigned,reply,thread,signed_off,approved,reverted,withdrawn,reported,mentioned,check,retest,token" {
		t.Errorf("standard: %s", got)
	}
	if got := keys(true); got != "reply,thread,approved,reverted,withdrawn,reported,mentioned,check,retest,token" {
		t.Errorf("simple: %s", got)
	}
}
