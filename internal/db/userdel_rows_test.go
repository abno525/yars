package db

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/config"
)

// reviewersOf is the names on a finding's reviewer list.
func reviewersOf(t *testing.T, d *DB, eng, fid string) []string {
	t.Helper()
	s, err := d.State(eng, fid)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range s.Reviewers {
		out = append(out, r.Name)
	}
	return out
}

// userdelData is a database where bob, a reviewer, has every kind of row an
// account leaves: assignments with and without a sign-off on findings in
// each state, chat, a dismissal, a board message, a check run and a hidden
// thread. beta holds a pending assignment only; bob is not on its team.
func userdelData(t *testing.T) *DB {
	t.Helper()
	d, _ := open(t)
	for _, u := range []config.User{{Username: "ann", Role: "director", IsAdmin: true}, {Username: "bob", Role: "reviewer"}, {Username: "cy", Role: "reviewer"}} {
		if err := d.AddUser(u); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.AddMembers("acme", "bob", "cy"); err != nil {
		t.Fatal(err)
	}
	pending, signed := Reviewer{Name: "bob"}, Reviewer{Name: "bob", ClearedHash: "h1"}
	cy := Reviewer{Name: "cy"}
	states := map[string]State{
		"F-001": {Status: "draft", Reviewers: []Reviewer{pending, cy}},
		"F-002": {Status: "verification", Reviewers: []Reviewer{cy, pending}},
		"F-003": {Status: "verification", Reviewers: []Reviewer{signed}},
		"F-004": {Status: "complete", ApprovedHash: "h1", Reviewers: []Reviewer{signed}},
		"F-005": {Status: "verification", Reviewers: []Reviewer{pending}},
		"F-006": {Status: "complete", ApprovedHash: "h1", Reviewers: []Reviewer{pending, cy}},
		"F-007": {Status: "withdrawn", Reviewers: []Reviewer{pending}},
	}
	if err := d.TxFor("acme", func(tx *Tx) error {
		for fid, s := range states {
			if err := tx.PutState("acme", fid, s); err != nil {
				return err
			}
		}
		if err := tx.AddMessage("acme", "F-002", chat.Message{ID: "m1", TS: time.Unix(1, 0), User: "bob", Text: "see the header"}); err != nil {
			return err
		}
		return tx.Dismiss(Dismissal{Eng: "acme", Fid: "F-004", Rule: "todo", QuoteHash: "q", Level: "warning", By: "bob"})
	}); err != nil {
		t.Fatal(err)
	}
	// a reviewer row without a state row: a draft
	if _, err := d.Exec("INSERT INTO reviewers(eng, fid, username) VALUES ('acme', 'F-008', 'bob')"); err != nil {
		t.Fatal(err)
	}
	if err := d.TxFor("beta", func(tx *Tx) error {
		return tx.PutState("beta", "F-001", State{Status: "verification", Reviewers: []Reviewer{pending, cy}})
	}); err != nil {
		t.Fatal(err)
	}
	newNote(t, d, "acme", "bob", "lead")
	if _, err := d.StartRun("acme", "F-002", "h", "bob", ""); err != nil {
		t.Fatal(err)
	}
	if err := d.SetChatHidden("bob", "acme", "F-002", "m1", true); err != nil {
		t.Fatal(err)
	}
	if err := d.SetChatHidden("cy", "acme", "F-002", "m1", true); err != nil {
		t.Fatal(err)
	}
	return d
}

// Deleting an account takes it off the findings it was still to review: its
// reviewer rows without a sign-off on drafts and findings in verification,
// and the threads it hid. What it did stays under its name: its sign-offs,
// its place on finished findings, chat, dismissals, board messages and check
// runs. Each engagement that lost a row is marked changed, also one where
// the account was on no team, and the findings in verification left with no
// reviewer are named.
func TestDeleteUserTakesPendingReviews(t *testing.T) {
	d := userdelData(t)
	acme, _ := d.SeqFor("acme")
	beta, _ := d.SeqFor("beta")
	other, _ := d.SeqFor("other")
	got, err := d.DeleteUserReport("bob")
	if err != nil {
		t.Fatal(err)
	}
	for fid, want := range map[string][]string{
		"F-001": {"cy"},        // a draft: gone
		"F-002": {"cy"},        // in verification, no sign-off: gone
		"F-003": {"bob"},       // in verification, signed off: stays
		"F-004": {"bob"},       // complete, signed off: stays
		"F-005": nil,           // in verification, the only reviewer: gone
		"F-006": {"bob", "cy"}, // complete: the list is history
		"F-007": {"bob"},       // withdrawn: history
		"F-008": nil,           // no state row is a draft: gone
	} {
		if have := reviewersOf(t, d, "acme", fid); !slices.Equal(have, want) {
			t.Errorf("acme/%s: reviewers %v, want %v", fid, have, want)
		}
	}
	if have := reviewersOf(t, d, "beta", "F-001"); !slices.Equal(have, []string{"cy"}) {
		t.Errorf("beta/F-001: reviewers %v", have)
	}
	if s, _ := d.State("acme", "F-003"); len(s.Reviewers) != 1 || s.Reviewers[0].ClearedHash != "h1" {
		t.Errorf("the sign-off on acme/F-003: %+v", s.Reviewers)
	}
	if got.Assignments != 5 || !slices.Equal(got.Unreviewed, []string{"acme/F-005"}) {
		t.Errorf("report %+v", got)
	}
	for q, want := range map[string]int{
		"SELECT count(*) FROM chat WHERE username = 'bob'":           1,
		"SELECT count(*) FROM dismissals WHERE by_user = 'bob'":      1,
		"SELECT count(*) FROM board_messages WHERE username = 'bob'": 1,
		"SELECT count(*) FROM check_runs WHERE by_user = 'bob'":      1,
		"SELECT count(*) FROM chat_hidden WHERE username = 'bob'":    0,
		"SELECT count(*) FROM chat_hidden WHERE username = 'cy'":     1,
	} {
		var n int
		if err := d.QueryRow(q).Scan(&n); err != nil || n != want {
			t.Errorf("%s: %d %v, want %d", q, n, err, want)
		}
	}
	if s, _ := d.SeqFor("acme"); s <= acme {
		t.Errorf("acme was not marked changed: %d, was %d", s, acme)
	}
	// bob was on no team of beta: the mark comes from the reviewer row
	if s, _ := d.SeqFor("beta"); s <= beta {
		t.Errorf("beta was not marked changed: %d, was %d", s, beta)
	}
	if s, _ := d.SeqFor("other"); s != other {
		t.Errorf("an engagement without a row of the account was marked changed")
	}
}

// A delete that is refused (the last admin) takes nothing off any finding.
func TestRefusedDeleteKeepsPendingReviews(t *testing.T) {
	d, _ := open(t)
	if err := d.AddUser(config.User{Username: "ann", Role: "director", IsAdmin: true}); err != nil {
		t.Fatal(err)
	}
	if err := d.TxFor("acme", func(tx *Tx) error {
		return tx.PutState("acme", "F-001", State{Status: "verification", Reviewers: []Reviewer{{Name: "ann"}}})
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetChatHidden("ann", "acme", "F-001", "m1", true); err != nil {
		t.Fatal(err)
	}
	seq, _ := d.Seq()
	if got, err := d.DeleteUserReport("ann"); !errors.Is(err, ErrLastAdmin) || got.Assignments != 0 || len(got.Unreviewed) != 0 {
		t.Fatalf("delete of the last admin: %+v %v", got, err)
	}
	if have := reviewersOf(t, d, "acme", "F-001"); !slices.Equal(have, []string{"ann"}) {
		t.Fatalf("reviewers %v", have)
	}
	if count(t, d, "chat_hidden") != 1 {
		t.Fatal("the refusal removed a hidden thread")
	}
	if again, _ := d.Seq(); again != seq {
		t.Fatalf("the refusal wrote: seq %d, was %d", again, seq)
	}
}
