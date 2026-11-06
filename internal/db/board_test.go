package db

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newNote(t *testing.T, d *DB, eng, by, title string) Note {
	t.Helper()
	n, err := d.CreateNote(Note{Eng: eng, Title: title, Host: "app.acme.test", Author: by, State: "open"}, "first "+title)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestBoardNotesNumberedPerEngagement(t *testing.T) {
	d, _ := open(t)
	a := newNote(t, d, "acme", "alice", "one")
	b := newNote(t, d, "acme", "bob", "two")
	c := newNote(t, d, "beta", "alice", "other")
	if a.Num != 1 || b.Num != 2 || c.Num != 1 {
		t.Fatalf("numbers %d %d %d", a.Num, b.Num, c.Num)
	}
	if _, err := d.PostNote("acme", 1, "bob", "reply"); err != nil {
		t.Fatal(err)
	}
	ns, err := d.Notes("acme")
	if err != nil {
		t.Fatal(err)
	}
	// the most recent activity first; replies leave the first message out
	if len(ns) != 2 || ns[0].Num != 1 || ns[0].Replies != 1 || ns[1].Replies != 0 || ns[0].Author != "alice" {
		t.Fatalf("notes %+v", ns)
	}
	if _, err := d.Note("acme", 3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing note: %v", err)
	}
	// another engagement's number is not this engagement's note
	if n, err := d.Note("beta", 1); err != nil || n.Title != "other" {
		t.Fatalf("beta note %+v %v", n, err)
	}
	msgs, older, err := d.NoteMessages("acme", 1, 50)
	if err != nil || older != 0 || len(msgs) != 2 || msgs[0].Text != "first one" || msgs[1].User != "bob" || msgs[1].Kind != KindMsg {
		t.Fatalf("messages %+v %d %v", msgs, older, err)
	}
}

func TestBoardThreadCap(t *testing.T) {
	d, _ := open(t)
	newNote(t, d, "acme", "alice", "long")
	for i := 0; i < 10; i++ {
		if _, err := d.PostNote("acme", 1, "bob", fmt.Sprint("m", i)); err != nil {
			t.Fatal(err)
		}
	}
	msgs, older, err := d.NoteMessages("acme", 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	// the first message stays, then the newest
	if len(msgs) != 4 || older != 7 || msgs[0].Text != "first long" || msgs[1].Text != "m7" || msgs[3].Text != "m9" {
		t.Fatalf("capped %+v older %d", msgs, older)
	}
}

func TestBoardStateRules(t *testing.T) {
	d, _ := open(t)
	newNote(t, d, "acme", "alice", "x")
	if err := d.SetNoteState("acme", 1, "bob", "analyzing", "confirmed", ""); !errors.Is(err, ErrBoardStale) {
		t.Fatalf("stale from: %v", err)
	}
	if err := d.SetNoteState("acme", 1, "bob", "open", "dismissed", "gateway strips it"); err != nil {
		t.Fatal(err)
	}
	n, _ := d.Note("acme", 1)
	if n.State != "dismissed" || n.DismissReason != "gateway strips it" {
		t.Fatalf("dismissed %+v", n)
	}
	// back to open clears the reason; the event stays in the thread
	if err := d.SetNoteState("acme", 1, "alice", "dismissed", "open", ""); err != nil {
		t.Fatal(err)
	}
	n, _ = d.Note("acme", 1)
	msgs, _, _ := d.NoteMessages("acme", 1, 50)
	if n.DismissReason != "" || len(msgs) != 3 || msgs[1].Kind != KindDismiss || msgs[1].Text != "gateway strips it" || msgs[2].Kind != KindState || msgs[2].Text != "open" {
		t.Fatalf("reopened %+v %+v", n, msgs)
	}
	if err := d.SetNoteSeverity("acme", 1, "bob", "high"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetNoteDup("acme", 1, "bob", "F-002"); err != nil {
		t.Fatal(err)
	}
	n, _ = d.Note("acme", 1)
	if n.Severity != "high" || n.DupOf != "F-002" {
		t.Fatalf("analysis %+v", n)
	}
	// the same value again is no event
	d.SetNoteSeverity("acme", 1, "bob", "high")
	if msgs, _, _ := d.NoteMessages("acme", 1, 50); len(msgs) != 5 || msgs[3].Kind != KindSeverity || msgs[4].Kind != KindDup {
		t.Fatalf("events %+v", msgs)
	}
}

func TestBoardMakeFindingClaim(t *testing.T) {
	d, _ := open(t)
	newNote(t, d, "acme", "alice", "x")
	if err := d.ClaimNote("acme", 1); !errors.Is(err, ErrBoardStale) {
		t.Fatalf("claim of an open note: %v", err)
	}
	d.SetNoteState("acme", 1, "bob", "open", "confirmed", "")
	// two at once: exactly one claim
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); errs[i] = d.ClaimNote("acme", 1) }(i)
	}
	wg.Wait()
	won := 0
	for _, err := range errs {
		if err == nil {
			won++
		} else if !errors.Is(err, ErrBoardLocked) {
			t.Fatalf("claim: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d claims won", won)
	}
	if err := d.LinkNote("acme", 1, "alice", "F-007"); err != nil {
		t.Fatal(err)
	}
	n, _ := d.Note("acme", 1)
	if n.Finding != "F-007" {
		t.Fatalf("linked %+v", n)
	}
	// a note with a finding takes no more writes
	for name, err := range map[string]error{
		"post":     func() error { _, err := d.PostNote("acme", 1, "bob", "late"); return err }(),
		"state":    d.SetNoteState("acme", 1, "bob", "confirmed", "open", ""),
		"severity": d.SetNoteSeverity("acme", 1, "bob", "low"),
		"dup":      d.SetNoteDup("acme", 1, "bob", "L-002"),
		"claim":    d.ClaimNote("acme", 1),
	} {
		if !errors.Is(err, ErrBoardLocked) {
			t.Errorf("%s on a linked note: %v", name, err)
		}
	}
	// a failed creation gives the claim back
	newNote(t, d, "acme", "alice", "y")
	d.SetNoteState("acme", 2, "bob", "open", "info", "")
	if err := d.ClaimNote("acme", 2); err != nil {
		t.Fatal(err)
	}
	if err := d.UnclaimNote("acme", 2); err != nil {
		t.Fatal(err)
	}
	if err := d.ClaimNote("acme", 2); err != nil {
		t.Fatalf("claim after unclaim: %v", err)
	}
}

func TestBoardPendingResetOnOpen(t *testing.T) {
	d, p := open(t)
	newNote(t, d, "acme", "alice", "x")
	d.SetNoteState("acme", 1, "bob", "open", "confirmed", "")
	if err := d.ClaimNote("acme", 1); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if n, _ := d2.Note("acme", 1); n.Finding != "" {
		t.Fatalf("pending left after a restart: %+v", n)
	}
}

func TestBoardArchivedReadOnly(t *testing.T) {
	d, _ := open(t)
	newNote(t, d, "acme", "alice", "x")
	if err := d.Archive("acme", "dora"); err != nil {
		t.Fatal(err)
	}
	_, createErr := d.CreateNote(Note{Eng: "acme", Title: "t", Author: "a", State: "open"}, "x")
	for name, err := range map[string]error{
		"create":   createErr,
		"post":     func() error { _, err := d.PostNote("acme", 1, "bob", "late"); return err }(),
		"state":    d.SetNoteState("acme", 1, "bob", "open", "analyzing", ""),
		"severity": d.SetNoteSeverity("acme", 1, "bob", "low"),
		"dup":      d.SetNoteDup("acme", 1, "bob", "L-002"),
		"claim":    d.ClaimNote("acme", 1),
	} {
		if !errors.Is(err, ErrArchived) {
			t.Errorf("%s on an archived engagement: %v", name, err)
		}
	}
	// what a user saw is their own read state: allowed
	if err := d.SeeNote("bob", "acme", 1); err != nil {
		t.Fatal(err)
	}
}

func TestBoardWritesMoveNoChangeCounter(t *testing.T) {
	d, _ := open(t)
	s0, _ := d.Seq()
	e0, _ := d.SeqFor("acme")
	newNote(t, d, "acme", "alice", "x")
	d.PostNote("acme", 1, "bob", "y")
	d.SeeNote("bob", "acme", 1)
	if s, _ := d.Seq(); s != s0 {
		t.Fatalf("global counter moved %d -> %d", s0, s)
	}
	if e, _ := d.SeqFor("acme"); e != e0 {
		t.Fatalf("engagement counter moved %d -> %d", e0, e)
	}
}

func TestBoardUnseen(t *testing.T) {
	d, _ := open(t)
	d.AddMembers("acme", "alice", "bob")
	newNote(t, d, "acme", "alice", "x")
	// alice's own note is nothing new to her
	if u, _ := d.UnseenNotes("alice"); len(u) != 0 {
		t.Fatalf("own note unseen: %+v", u)
	}
	u, err := d.UnseenNotes("bob")
	if err != nil || len(u) != 1 || u[0].Num != 1 || u[0].LastUser != "alice" || u[0].LastText != "first x" {
		t.Fatalf("bob %+v %v", u, err)
	}
	if n, _ := d.UnseenCount("bob", "acme"); n != 1 {
		t.Fatalf("count %d", n)
	}
	if err := d.SeeNote("bob", "acme", 1); err != nil {
		t.Fatal(err)
	}
	if u, _ := d.UnseenNotes("bob"); len(u) != 0 {
		t.Fatalf("seen note still new: %+v", u)
	}
	// a reply in the same second as the view still counts (seq, not time)
	d.PostNote("acme", 1, "alice", "more")
	if u, _ := d.UnseenNotes("bob"); len(u) != 1 || u[0].LastText != "more" {
		t.Fatalf("reply not new: %+v", u)
	}
	// bob's own reply marks the note seen for him
	d.PostNote("acme", 1, "bob", "ok")
	if u, _ := d.UnseenNotes("bob"); len(u) != 0 {
		t.Fatalf("after own reply: %+v", u)
	}
	// a new member is not flooded with what came before joining
	d.now = func() time.Time { return time.Now().Add(time.Hour) }
	d.AddMembers("acme", "carol")
	if u, _ := d.UnseenNotes("carol"); len(u) != 0 {
		t.Fatalf("new member flooded: %+v", u)
	}
	d.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	d.PostNote("acme", 1, "alice", "after carol joined")
	if u, _ := d.UnseenNotes("carol"); len(u) != 1 {
		t.Fatalf("new member misses new replies: %+v", u)
	}
	// off the team: the read state goes with the membership
	d.SeeNote("carol", "acme", 1)
	if err := d.RemoveMember("acme", "carol"); err != nil {
		t.Fatal(err)
	}
	var n int
	d.QueryRow("SELECT count(*) FROM board_seen WHERE username = 'carol'").Scan(&n)
	if n != 0 {
		t.Fatalf("%d seen rows left", n)
	}
}

func TestBoardPurged(t *testing.T) {
	d, _ := open(t)
	newNote(t, d, "acme", "alice", "x")
	d.SeeNote("bob", "acme", 1)
	if err := d.TxFor("acme", func(tx *Tx) error { return tx.Purge("acme") }); err != nil {
		t.Fatal(err)
	}
	for _, tb := range []string{"board_notes", "board_messages", "board_seen"} {
		var n int
		d.QueryRow("SELECT count(*) FROM " + tb).Scan(&n)
		if n != 0 {
			t.Fatalf("%s: %d rows left", tb, n)
		}
	}
}

func TestMigrateV11Board(t *testing.T) {
	p := filepath.Join(t.TempDir(), "yars.db")
	sdb, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations[:11] {
		if _, err := sdb.Exec(m); err != nil {
			t.Fatal(err)
		}
	}
	sdb.Exec("PRAGMA user_version = 11")
	sdb.Exec("INSERT INTO engagement_members(eng, username) VALUES ('acme', 'bob')")
	sdb.Close()
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if ok, _ := d.IsMember("acme", "bob"); !ok {
		t.Fatal("member lost")
	}
	newNote(t, d, "acme", "alice", "x")
	// a member from before the board sees what is new
	if u, _ := d.UnseenNotes("bob"); len(u) != 1 {
		t.Fatalf("unseen after upgrade %+v", u)
	}
}
