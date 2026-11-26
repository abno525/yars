package db

import (
	"testing"

	"github.com/abno525/yars/internal/config"
)

// Deleting an account takes its board read state with it: a new account of
// the same name follows nothing the old one opened.
func TestDeleteUserBoardSeen(t *testing.T) {
	d, _ := open(t)
	if err := d.AddUser(config.User{Username: "dora", Role: "director", PasswordHash: "x"}); err != nil {
		t.Fatal(err)
	}
	newNote(t, d, "acme", "alice", "x")
	if err := d.SeeNote("dora", "acme", 1); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteUser("dora"); err != nil {
		t.Fatal(err)
	}
	var n int
	d.QueryRow("SELECT count(*) FROM board_seen WHERE username = 'dora'").Scan(&n)
	if n != 0 {
		t.Fatalf("%d seen rows left", n)
	}
}
