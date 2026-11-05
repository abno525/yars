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

func TestSeedCommand(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	var out bytes.Buffer
	if err := cmdSeed([]string{"--data", dir, "--engagements", "2", "--findings", "4", "--messages", "10"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "seeded") {
		t.Errorf("output %q", out.String())
	}
	// a normal, initialised data directory
	if _, err := os.Stat(config.ConfigPath(dir)); err != nil {
		t.Fatal(err)
	}
	r, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(db.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	st := store.New(r, config.Default(), d)
	refs, err := st.ListFindings("e002")
	if err != nil || len(refs) != 4 {
		t.Fatalf("findings %d %v", len(refs), err)
	}
	if users, _ := d.Users(); len(users) != 3 {
		t.Errorf("users %v", users)
	}
	// never over an existing directory
	if err := cmdSeed([]string{"--data", dir, "--engagements", "1"}, &out); err == nil {
		t.Fatal("seeded an existing data directory")
	}
}
