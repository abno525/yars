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
	pw, err := Fill(dir, Options{Engagements: 3, Findings: 7, Messages: 40})
	if err != nil {
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
	// every account has the password Fill made and returned; the old fixed
	// one opens nothing
	if auth.PasswordProblem(pw) != "" || pw == "password" {
		t.Fatalf("password %q: %s", pw, auth.PasswordProblem(pw))
	}
	a := auth.New(d)
	for _, u := range []string{"dir1", "rev1", "pen1"} {
		if _, ok := a.Check(u, "password"); ok {
			t.Errorf("%s logs in with \"password\"", u)
		}
		if _, ok := a.Check(u, pw); !ok {
			t.Errorf("login %s with the returned password failed", u)
		}
	}
}

// The password is made anew for each fill, never drawn from the data's
// repeatable generator: the same Seed gives the same findings and another
// password. A password given in Options is the one used.
func TestFillPassword(t *testing.T) {
	fill := func(o Options) (string, string) {
		t.Helper()
		dir := t.TempDir()
		if _, err := gitrepo.Init(dir); err != nil {
			t.Fatal(err)
		}
		pw, err := Fill(dir, o)
		if err != nil {
			t.Fatal(err)
		}
		return pw, dir
	}
	o := Options{Engagements: 1, Findings: 3, Seed: 7}
	pw1, dir1 := fill(o)
	pw2, dir2 := fill(o)
	if pw1 == pw2 {
		t.Fatalf("two fills with one seed made the same password %q", pw1)
	}
	tree := func(dir string) string {
		return gitOut(t, filepath.Join(dir, "engagements", "e001"), "rev-parse", "HEAD^{tree}")
	}
	if tree(dir1) != tree(dir2) {
		t.Fatal("the same seed made other findings")
	}
	o.Password = "a password of the test"
	pw, dir := fill(o)
	if pw != o.Password {
		t.Fatalf("returned %q", pw)
	}
	d, err := db.Open(db.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, ok := auth.New(d).Check("dir1", o.Password); !ok {
		t.Fatal("the given password does not log in")
	}
	// a password the website would refuse is refused here too
	bad := t.TempDir()
	if _, err := gitrepo.Init(bad); err != nil {
		t.Fatal(err)
	}
	if _, err := Fill(bad, Options{Engagements: 1, Password: "short"}); err == nil {
		t.Fatal("a short password was taken")
	}
}

func TestFillRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	if _, err := gitrepo.Init(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Fill(dir, Options{Engagements: 1, Findings: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := Fill(dir, Options{Engagements: 1, Findings: 1}); err == nil {
		t.Fatal("second fill succeeded")
	}
}
