package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

// exportFixture is a data folder with engagement acme: F-001 complete,
// F-002 draft; dora is a director and bob a reviewer.
func exportFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	d := openDB(t, dir)
	d.AddUser(config.User{Username: "dora", Role: "director"})
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	r, _ := gitrepo.Open(dir)
	st := store.New(r, config.Default(), d)
	a := gitrepo.Author{Name: "t", Email: "t@t"}
	st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a)
	st.CreateFinding("acme", "SQL injection", a)
	st.CreateFinding("acme", "Open redirect", a)
	if err := d.TxFor("acme", func(tx *db.Tx) error { return tx.PutState("acme", "F-001", db.State{Status: "complete"}) }); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A finding that could not be marked reported makes the command fail (exit
// 1), after the export is written and the others are marked (backlog, M8).
func TestExportCLIMarkFailureExits1(t *testing.T) {
	dir := exportFixture(t)
	out := filepath.Join(t.TempDir(), "r.html")
	var log bytes.Buffer
	code, _ := cmdExport([]string{"--data", dir, "--exporter", "confluence", "--out", out, "--mark", "--as", "bob", "acme", "F-001-sql-injection"}, &log)
	if code != 1 || !strings.Contains(log.String(), "not marked F-001") {
		t.Fatalf("code %d: %s", code, log.String())
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal("the export was not written")
	}
}

// --mark and --as are checked before anything is exported: a mistake in
// them writes nothing (backlog, M8).
func TestExportCLIMarkCheckedFirst(t *testing.T) {
	dir := exportFixture(t)
	out := filepath.Join(t.TempDir(), "r.html")
	for _, args := range [][]string{{"--mark"}, {"--mark", "--as", "nobody"}} {
		var log bytes.Buffer
		all := append(append([]string{"--data", dir, "--exporter", "confluence", "--out", out}, args...), "acme", "F-001-sql-injection")
		if code, err := cmdExport(all, &log); code != 2 || err == nil || !strings.Contains(err.Error(), "--as") {
			t.Errorf("%v: code %d err %v", args, code, err)
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatalf("%v: the export was written", args)
		}
	}
}
