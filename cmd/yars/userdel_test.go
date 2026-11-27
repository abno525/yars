package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/db"
)

// yars userdel keeps the name: yars useradd of it fails with the reason,
// also in another case of its letters.
func TestUseraddAfterUserdel(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := cmdUseradd([]string{"--data", dir, "bob"}, strings.NewReader("password-1\n"), &out); err != nil {
		t.Fatal(err)
	}
	if err := cmdUserdel([]string{"--data", dir, "bob"}, &out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bob", "Bob"} {
		err := cmdUseradd([]string{"--data", dir, name}, strings.NewReader("password-1\n"), &out)
		if err == nil || !strings.Contains(err.Error(), "user bob was deleted: the name stays taken") {
			t.Fatalf("useradd %s after userdel bob: %v", name, err)
		}
	}
	if us, _ := openDB(t, dir).Users(); len(us) != 0 {
		t.Fatalf("accounts %+v", us)
	}
	if err := cmdUseradd([]string{"--data", dir, "bobby"}, strings.NewReader("password-1\n"), &out); err != nil {
		t.Fatal(err)
	}
}

// yars userdel takes the account off the findings it was still to review,
// says how many, names (by ID) the findings in verification it left without
// a reviewer, and writes the count to the audit row. A delete that took
// nothing prints its one line, as before.
func TestUserdelNamesPendingReviews(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, name := range []string{"bob", "cy"} {
		if err := cmdUseradd([]string{"--data", dir, "--role", "reviewer", name}, strings.NewReader("password-1\n"), &out); err != nil {
			t.Fatal(err)
		}
	}
	d := openDB(t, dir)
	bob, cy := db.Reviewer{Name: "bob"}, db.Reviewer{Name: "cy"}
	if err := d.TxFor("acme", func(tx *db.Tx) error {
		if err := tx.PutState("acme", "F-001", db.State{Status: "verification", Reviewers: []db.Reviewer{bob}}); err != nil {
			return err
		}
		if err := tx.PutState("acme", "F-002", db.State{Status: "verification", Reviewers: []db.Reviewer{bob, cy}}); err != nil {
			return err
		}
		return tx.PutState("acme", "F-003", db.State{Status: "verification", Reviewers: []db.Reviewer{{Name: "bob", ClearedHash: "h"}}})
	}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := cmdUserdel([]string{"--data", dir, "bob"}, &out); err != nil {
		t.Fatal(err)
	}
	want := "deleted bob (their sessions and API tokens too)\nreview assignments removed: 2\nin verification without a reviewer: acme/F-001\n"
	if out.String() != want {
		t.Fatalf("userdel printed:\n%s", out.String())
	}
	l, _, err := d.AuditQuery(db.AuditFilter{Action: "user.delete", Limit: 5})
	if err != nil || len(l) != 1 || l[0].Actor != "cli" || l[0].Target != "bob" || l[0].Detail != "review assignments removed: 2" {
		t.Fatalf("audit %+v %v", l, err)
	}
	// the sign-off stays under the name, which no account gets again
	if s, err := d.State("acme", "F-003"); err != nil || len(s.Reviewers) != 1 || s.Reviewers[0].ClearedHash != "h" {
		t.Fatalf("the sign-off: %+v %v", s, err)
	}
	out.Reset()
	if err := cmdUserdel([]string{"--data", dir, "cy"}, &out); err != nil {
		t.Fatal(err)
	}
	// cy was still to review F-002
	if out.String() != "deleted cy (their sessions and API tokens too)\nreview assignments removed: 1\nin verification without a reviewer: acme/F-002\n" {
		t.Fatalf("userdel printed:\n%s", out.String())
	}
	if err := cmdUseradd([]string{"--data", dir, "--role", "reviewer", "dee"}, strings.NewReader("password-1\n"), &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := cmdUserdel([]string{"--data", dir, "dee"}, &out); err != nil || out.String() != "deleted dee (their sessions and API tokens too)\n" {
		t.Fatalf("userdel of an account with no review: %v\n%s", err, out.String())
	}
}
