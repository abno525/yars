package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/store"
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
	d := openDB(t, dir)
	for _, when := range []string{"INSERT", "UPDATE"} { // the database refuses the mark
		if _, err := d.Exec("CREATE TRIGGER boom" + when + " BEFORE " + when + " ON finding_state WHEN NEW.status = 'reported' BEGIN SELECT RAISE(ABORT, 'disk full'); END"); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "r.html")
	var log bytes.Buffer
	code, _ := cmdExport([]string{"--data", dir, "--exporter", "confluence", "--out", out, "--mark", "--as", "dora", "acme", "F-001-sql-injection"}, &log)
	if code != 1 || !strings.Contains(log.String(), "not marked F-001") {
		t.Fatalf("code %d: %s", code, log.String())
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal("the export was not written")
	}
}

// Named findings leave YARS only when finished, as on the website (R10): a
// draft named on the command line is refused (found in the M34 triage).
func TestExportCLINamedDraftRefused(t *testing.T) {
	dir := exportFixture(t)
	out := filepath.Join(t.TempDir(), "r.html")
	var log bytes.Buffer
	code, err := cmdExport([]string{"--data", dir, "--exporter", "confluence", "--out", out, "acme", "F-001", "F-002"}, &log)
	if code != 2 || err == nil || err.Error() != "F-002 is draft: only complete and reported findings are exported" {
		t.Fatalf("code %d err %v", code, err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("exported anyway")
	}
}

// A named finding must be one the exporter takes, as on the website: a
// reported finding is refused by an exporter of complete findings.
func TestExportCLINamedOutsideStatuses(t *testing.T) {
	dir := exportFixture(t)
	if err := os.WriteFile(filepath.Join(dir, ".yars", "exporters", "done.yaml"), []byte("name: Done\ntype: confluence\nstatuses: [complete]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := openDB(t, dir)
	if err := d.TxFor("acme", func(tx *db.Tx) error { return tx.PutState("acme", "F-001", db.State{Status: "reported"}) }); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "r.html")
	var log bytes.Buffer
	code, err := cmdExport([]string{"--data", dir, "--exporter", "done", "--out", out, "acme", "F-001"}, &log)
	if code != 2 || err == nil || err.Error() != "F-001 is reported: done exports complete findings only" {
		t.Fatalf("code %d err %v", code, err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("exported anyway")
	}
}

// An exporter whose file does not load says why, not "unknown exporter"
// (backlog, M8).
func TestExportCLIBrokenExporter(t *testing.T) {
	dir := exportFixture(t)
	if err := os.WriteFile(filepath.Join(dir, ".yars", "exporters", "word.yaml"), []byte("type: pandoc\nformat: \"docx;rm\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	code, err := cmdExport([]string{"--data", dir, "--exporter", "word", "acme"}, &log)
	if code != 2 || err == nil || !strings.HasPrefix(err.Error(), "word.yaml: ") || strings.Contains(err.Error(), "unknown exporter") {
		t.Fatalf("code %d err %v", code, err)
	}
	if _, err := cmdExport([]string{"--data", dir, "--exporter", "nope", "acme"}, &log); err == nil || err.Error() != `unknown exporter "nope"` {
		t.Fatalf("a missing exporter: %v", err)
	}
}

// A named finding is found by its folder, ID or number; a name that matches
// none is an error that lists it, not silently dropped (backlog, M8).
func TestExportCLIUnknownFinding(t *testing.T) {
	dir := exportFixture(t)
	out := filepath.Join(t.TempDir(), "r.html")
	var log bytes.Buffer
	code, err := cmdExport([]string{"--data", dir, "--exporter", "confluence", "--out", out, "acme", "F-001", "nope", "F-009"}, &log)
	if code != 2 || err == nil || err.Error() != "no finding matches nope, F-009" {
		t.Fatalf("code %d err %v", code, err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("exported anyway")
	}
	for _, name := range []string{"F-001", "1", "F-001-sql-injection"} {
		if code, err := cmdExport([]string{"--data", dir, "--exporter", "confluence", "--out", out, "acme", name}, &log); code != 0 || err != nil {
			t.Errorf("%s: code %d err %v", name, code, err)
		}
	}
}

// Flags go before the engagement: one after it is refused, not taken for
// a finding (backlog, M8).
func TestExportCLIFlagAfterEngagement(t *testing.T) {
	dir := exportFixture(t)
	var log bytes.Buffer
	code, err := cmdExport([]string{"--data", dir, "--exporter", "confluence", "acme", "F-001-sql-injection", "--out", "x.html"}, &log)
	if code != 2 || err == nil || !strings.Contains(err.Error(), `flags go before the engagement; "--out" is after it`) {
		t.Fatalf("code %d err %v", code, err)
	}
}

// --mark and --as are checked before anything is exported: a mistake in
// them (no account, an unknown one, one that is not a director's) writes
// nothing (backlog, M8).
func TestExportCLIMarkCheckedFirst(t *testing.T) {
	dir := exportFixture(t)
	out := filepath.Join(t.TempDir(), "r.html")
	for _, args := range [][]string{{"--mark"}, {"--mark", "--as", "nobody"}, {"--mark", "--as", "bob"}} {
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
