package workflow

import (
	"slices"
	"testing"

	"yars/internal/config"
	"yars/internal/finding"
)

// A complete finding waits for a director to mark it reported; an own
// draft that was not returned is one of the author's drafts.
func TestPendingReportAndDrafts(t *testing.T) {
	if Pending(dora, meta("complete")) != InboxReport || Pending(alice, meta("complete")) != InboxNone || Pending(bob, meta("complete")) != InboxNone {
		t.Error("report")
	}
	if Pending(alice, meta("draft")) != InboxDraft || Pending(pen2, meta("draft")) != InboxNone {
		t.Error("draft")
	}
	m := meta("draft")
	m.Returned = &finding.Returned{By: "bob", Reason: "x"}
	if Pending(alice, m) != InboxReturned {
		t.Error("a returned draft is in Returned, not in the drafts")
	}
	if Pending(dora, meta("reported")) != InboxNone || Pending(dora, meta("withdrawn")) != InboxNone {
		t.Error("reported or withdrawn pending")
	}
	// a director assigned as a reviewer: once someone else signed off, the
	// finding is hers to approve (her role's queue), not to review
	m = meta("verification", "bob")
	m.Reviewers = []string{"bob", "dora"}
	if Pending(dora, m) != InboxApprove {
		t.Errorf("director as reviewer: %q", Pending(dora, m))
	}
	m.ClearedBy = nil
	if Pending(dora, m) != InboxReview {
		t.Errorf("director as reviewer, nobody signed off: %q", Pending(dora, m))
	}
}

// The queues come in one fixed order; each role has its own set.
func TestQueues(t *testing.T) {
	cases := []struct {
		u    config.User
		want []Inbox
	}{
		{alice, []Inbox{InboxReturned, InboxThreads, InboxBoard, InboxNotes, InboxDraft}},
		{bob, []Inbox{InboxReview, InboxThreads, InboxBoard, InboxNotes}},
		{dora, []Inbox{InboxApprove, InboxReport, InboxBoard, InboxNotes}},
		{config.User{Username: "root", Role: "pentester", IsAdmin: true}, []Inbox{InboxReturned, InboxThreads, InboxBoard, InboxNotes, InboxDraft}},
		{config.User{Username: "x", Role: "nobody"}, []Inbox{InboxBoard, InboxNotes}},
	}
	for _, c := range cases {
		if got := Queues(c.u); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.u.Username, got, c.want)
		}
	}
	// every role's set follows QueueOrder
	for _, u := range []config.User{alice, bob, dora} {
		last := -1
		for _, q := range Queues(u) {
			i := slices.Index(QueueOrder, q)
			if i <= last {
				t.Errorf("%s: %s out of order", u.Username, q)
			}
			last = i
		}
	}
	if len(QueueOrder) != 8 {
		t.Errorf("%d queues", len(QueueOrder))
	}
}
