package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/store"
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

var seedPassword = regexp.MustCompile(`\(password ([^)\s]+)\)\n$`)

// yars seed prints a random password, another one each run; every seeded
// account logs in with it and none with "password". Without the size flags
// the folder is small.
func TestSeedPasswordAndDefaultSize(t *testing.T) {
	printed := map[string]bool{}
	for _, c := range []struct {
		args  []string
		users []string
	}{
		{nil, []string{"dir1", "rev1", "pen1"}},
		{[]string{"--simple"}, []string{"dir1", "dir2"}},
	} {
		dir := filepath.Join(t.TempDir(), "data")
		var out bytes.Buffer
		if err := cmdSeed(append(c.args, "--data", dir), &out); err != nil {
			t.Fatal(err)
		}
		m := seedPassword.FindStringSubmatch(out.String())
		if m == nil || m[1] == "password" || auth.PasswordProblem(m[1]) != "" || printed[m[1]] {
			t.Fatalf("%v: output %q", c.args, out.String())
		}
		printed[m[1]] = true
		if !strings.Contains(out.String(), "2 engagements × 20 findings, 50 messages") {
			t.Errorf("%v: default size: %q", c.args, out.String())
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
		users, _ := d.Users()
		if len(users) != len(c.users) {
			t.Fatalf("%v: users %v", c.args, users)
		}
		a := auth.New(d)
		for _, u := range c.users {
			if _, ok := a.Check(u, "password"); ok {
				t.Errorf("%v: %s logs in with \"password\"", c.args, u)
			}
			if _, ok := a.Check(u, m[1]); !ok {
				t.Errorf("%v: %s does not log in with the printed password", c.args, u)
			}
		}
		st := store.New(r, config.Default(), d)
		engs, err := st.ListEngagements()
		if err != nil || len(engs) != 2 {
			t.Fatalf("%v: engagements %v %v", c.args, engs, err)
		}
		for _, e := range engs {
			if refs, err := st.ListFindings(e.ID); err != nil || len(refs) != 20 {
				t.Fatalf("%v: %s has %d findings %v", c.args, e.ID, len(refs), err)
			}
		}
	}
}
