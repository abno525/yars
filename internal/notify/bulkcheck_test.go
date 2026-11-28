package notify

import (
	"testing"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/store"
)

// A check started with many others by one press (Check stale) tells the
// author only when it left an open error: there is something to do then. A
// check someone started for the one finding tells the author as before.
func TestBulkCheckTellsOnlyErrors(t *testing.T) {
	n, d, m := newNotifier(t)
	for _, ch := range []string{"app", "email"} {
		if err := d.SetNotify("pen1", Check, ch, true); err != nil {
			t.Fatal(err)
		}
	}
	e := ev(store.EventCheck)
	e.Actor, e.State, e.Bulk = "dir1", db.RunDone, true
	n.Handle(e) // nothing found
	e.Warnings = 2
	n.Handle(e) // warnings hold nothing
	e.State, e.Warnings = db.RunFailed, 0
	n.Handle(e) // a failed run is the starter's to see
	n.Wait()
	if got := list(t, d, "pen1"); got != "" || len(m.sent) != 0 {
		t.Fatalf("pen1 after bulk checks with nothing to do: %q, %d mails", got, len(m.sent))
	}
	e.State, e.Errors = db.RunDone, 1
	n.Handle(e)
	e.Bulk, e.Errors = false, 0
	n.Handle(e)
	n.Wait()
	if got := list(t, d, "pen1"); got != "check:dir1:1 error · 0 warnings,check:dir1:0 errors · 0 warnings" || len(m.sent) != 2 {
		t.Fatalf("pen1: %q, %d mails", got, len(m.sent))
	}
}
