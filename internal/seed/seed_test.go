package seed

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/store"
)

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestFill(t *testing.T) {
	dir := t.TempDir()
	r, err := gitrepo.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := Fill(dir, Options{Engagements: 3, Findings: 7, Messages: 40}); err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(db.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	st := store.New(r, config.Default(), d)
	engs, err := st.ListEngagements()
	if err != nil || len(engs) != 3 {
		t.Fatalf("engagements %v %v", engs, err)
	}
	statuses, total, msgs := map[string]int{}, 0, 0
	for _, e := range engs {
		refs, err := st.ListFindings(e.ID)
		if err != nil || len(refs) != 7 {
			t.Fatalf("%s: %d findings %v", e.ID, len(refs), err)
		}
		for _, ref := range refs {
			statuses[ref.F.Meta.Status]++
			total++
		}
		all, err := d.AllMessages(e.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range all {
			msgs += len(m)
		}
		// one commit per engagement repo
		if n := gitOut(t, filepath.Join(dir, "engagements", e.ID), "rev-list", "--count", "HEAD"); n != "1" {
			t.Errorf("%s: %s commits", e.ID, n)
		}
	}
	if msgs != 40 {
		t.Errorf("messages %d, want 40", msgs)
	}
	if len(statuses) < 2 {
		t.Errorf("statuses not varied: %v", statuses)
	}
	// the main repo records every engagement and is clean
	if s := gitOut(t, dir, "status", "--porcelain"); s != "" {
		t.Errorf("main repo dirty:\n%s", s)
	}
	links, err := r.Gitlinks("HEAD", "engagements")
	if err != nil || len(links) != 3 {
		t.Errorf("gitlinks %v %v", links, err)
	}
	a := auth.New(d)
	for _, u := range []string{"dir1", "rev1", "pen1"} {
		if _, ok := a.Check(u, "password"); !ok {
			t.Errorf("login %s failed", u)
		}
	}
}

func TestFillRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	if _, err := gitrepo.Init(dir); err != nil {
		t.Fatal(err)
	}
	if err := Fill(dir, Options{Engagements: 1, Findings: 1}); err != nil {
		t.Fatal(err)
	}
	if err := Fill(dir, Options{Engagements: 1, Findings: 1}); err == nil {
		t.Fatal("second fill succeeded")
	}
}
