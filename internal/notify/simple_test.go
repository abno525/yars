package notify

import (
	"reflect"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/store"
)

// Complete tells the author, as Approve does (the Approved event); one who
// completes their own finding hears nothing.
func TestRecipientsComplete(t *testing.T) {
	e := ev(store.EventStatus)
	e.Actor, e.Action = "dir1", "complete"
	if got := recipients(e); !reflect.DeepEqual(got, map[string]string{"pen1": Approved}) {
		t.Fatalf("recipients %v", got)
	}
	n, d, _ := newNotifier(t)
	n.Handle(e)
	e.Actor = "pen1"
	n.Handle(e)
	n.Wait()
	if got := list(t, d, "pen1"); got != "approved:dir1:" {
		t.Fatalf("pen1: %q", got)
	}
	if got := list(t, d, "dir1"); got != "" {
		t.Fatalf("dir1: %q", got)
	}
}

// Email of the simple workflow names the events as it does: Completed.
func TestSimpleMailLabel(t *testing.T) {
	n, d, m := newNotifier(t)
	n.Simple = func() bool { return true }
	d.SetNotify("pen1", Approved, "email", true)
	e := ev(store.EventStatus)
	e.Actor, e.Action = "dir1", "complete"
	n.Handle(e)
	n.Wait()
	if len(m.sent) != 1 || m.sent[0].subject != "[YARS] Completed: F-005 SQL injection" || !strings.HasPrefix(m.sent[0].body, "Completed · dir1\n") {
		t.Fatalf("mail %+v", m.sent)
	}
}

// The simple workflow's settings list leaves out the review events, and
// names Approved "Completed".
func TestEventsForSimple(t *testing.T) {
	if !reflect.DeepEqual(EventsFor(false), Events) {
		t.Fatalf("standard %v", EventsFor(false))
	}
	var keys, labels []string
	for _, e := range EventsFor(true) {
		keys, labels = append(keys, e.Key), append(labels, e.Label)
	}
	if strings.Join(keys, ",") != "reply,approved,reverted,mentioned,check,token" {
		t.Fatalf("simple keys %v", keys)
	}
	if strings.Join(labels, ",") != "Reply in my thread,Completed,Reverted,Mentioned,Check finished,Token expiring" {
		t.Fatalf("simple labels %v", labels)
	}
	for _, c := range []struct {
		key    string
		simple bool
		want   string
	}{
		{Approved, true, "Completed"}, {Approved, false, "Approved"}, {Reply, true, "Reply in my thread"},
		{Returned, true, "Returned to me"}, {"bogus", true, "bogus"},
	} {
		if got := LabelFor(c.key, c.simple); got != c.want {
			t.Errorf("LabelFor(%s, %v) = %q", c.key, c.simple, got)
		}
	}
	if Label(Approved) != "Approved" {
		t.Error("Label changed")
	}
}
