package seed

import (
	"slices"
	"testing"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

// A simple-workflow seed has two directors (dir1 the admin) and the simple
// workflow's states only: draft, complete, reported and withdrawn, with no
// reviewers. Its findings, chat and teams are the two directors'.
func TestFillSimple(t *testing.T) {
	dir := t.TempDir()
	r, err := gitrepo.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := Fill(dir, Options{Engagements: 3, Findings: 20, Messages: 60, Simple: true}); err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(db.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	users, err := d.Users()
	if err != nil || len(users) != 2 {
		t.Fatalf("users %+v %v", users, err)
	}
	for _, u := range users {
		if u.Role != "director" || u.IsAdmin != (u.Username == "dir1") || (u.Username != "dir1" && u.Username != "dir2") {
			t.Errorf("user %+v", u)
		}
	}
	a := auth.New(d)
	for _, u := range []string{"dir1", "dir2"} {
		if _, ok := a.Check(u, Password); !ok {
			t.Errorf("login %s failed", u)
		}
	}
	c := config.Default()
	c.Workflow = config.WorkflowSimple
	st := store.New(r, c, d)
	engs, err := st.ListEngagements()
	if err != nil || len(engs) != 3 {
		t.Fatalf("engagements %v %v", engs, err)
	}
	seen := map[string]int{}
	for _, e := range engs {
		states, err := d.States(e.ID)
		if err != nil {
			t.Fatal(err)
		}
		for fid, s := range states {
			if len(s.Reviewers) != 0 || s.ReturnedBy != "" || !slices.Contains([]string{"draft", "complete", "reported", "withdrawn"}, s.Status) {
				t.Errorf("%s/%s: %+v", e.ID, fid, s)
			}
			seen[s.Status]++
		}
		refs, err := st.ListFindings(e.ID)
		if err != nil || len(refs) != 20 {
			t.Fatalf("%s: %d findings %v", e.ID, len(refs), err)
		}
		for _, ref := range refs {
			if a := ref.F.Meta.Author; a != "dir1" && a != "dir2" {
				t.Errorf("%s: author %s", ref.F.Meta.ID, a)
			}
			if s := ref.F.Meta.Status; s != states[ref.F.Meta.ID].Status {
				t.Errorf("%s reads %s, stored %s (approval not bound to the content)", ref.F.Meta.ID, s, states[ref.F.Meta.ID].Status)
			}
		}
		all, err := d.AllMessages(e.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, ms := range all {
			for _, m := range ms {
				if m.User != "dir1" && m.User != "dir2" {
					t.Errorf("message by %s", m.User)
				}
			}
		}
		if ok, _ := d.IsMember(e.ID, "dir2"); !ok {
			t.Errorf("%s: dir2 not on the team", e.ID)
		}
	}
	for _, s := range []string{"draft", "complete", "reported", "withdrawn"} {
		if seen[s] == 0 {
			t.Errorf("no %s finding: %v", s, seen)
		}
	}
}
