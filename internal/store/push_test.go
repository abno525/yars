package store

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"yars/internal/finding"
)

// A content edit through YARS tells what changed (finding.updated).
func TestUpdatedEvent(t *testing.T) {
	s, _ := withEngagement(t)
	ref, err := s.CreateFinding(eng, "SQL injection", alice)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	s.OnEvent(rec.add)
	if err := s.UpdateSection(eng, ref.Dir, "Impact", "Full read.", "", uAlice); err != nil {
		t.Fatal(err)
	}
	e := rec.last(EventUpdated)
	if e.Actor != "alice" || e.Fid != "F-001" || e.Dir != ref.Dir || !slices.Equal(e.Changed, []string{"Impact"}) {
		t.Fatalf("updated %+v", e)
	}
	s.UpdateSeverity(eng, ref.Dir, "high", "", alice)
	if e := rec.last(EventUpdated); !slices.Equal(e.Changed, []string{"Severity"}) || e.Severity != "high" {
		t.Fatalf("severity %+v", e)
	}
	// nothing changed: no event
	n := len(rec.kinds())
	s.UpdateSection(eng, ref.Dir, "Impact", "Full read.", "", uAlice)
	if len(rec.kinds()) != n {
		t.Fatalf("event for a no-op: %v", rec.kinds())
	}
	if _, err := s.AddAttachment(eng, ref.Dir, "shot.png", []byte("png"), uAlice); err != nil {
		t.Fatal(err)
	}
	if e := rec.last(EventUpdated); !slices.Contains(e.Changed, "Attachments") {
		t.Fatalf("attachment %+v", e)
	}
}

// A push into the main repo runs under the main repo's lock (no settings
// commit can land between the hook's check and git's checkout), and a push
// that checked its tree out without moving the branch leaves HEAD's tree.
func TestReceivePushMainRepo(t *testing.T) {
	s, dir := withEngagement(t)
	s.ReceivePush("", uBob, func() {
		if s.mainMu.TryLock() {
			s.mainMu.Unlock()
			t.Error("main repo push served without the main repo lock")
		}
		os.WriteFile(filepath.Join(dir, "README.md"), []byte("rejected push"), 0o644)
		exec.Command("git", "-C", dir, "add", "README.md").Run()
	})
	if st, _ := exec.Command("git", "-C", dir, "status", "--porcelain", "--untracked-files=no", "--ignore-submodules=all").Output(); len(st) != 0 {
		t.Fatalf("main tree dirty after a push that did not land:\n%s", st)
	}
}

// A push (commits that land outside the store) emits the events the same
// changes made through YARS would: created for a new finding, updated with
// what changed for an edited one, attributed to the pusher.
func TestReceivePushEvents(t *testing.T) {
	s, dir := withEngagement(t)
	ref, err := s.CreateFinding(eng, "SQL injection", alice)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	s.OnEvent(rec.add)
	ed := filepath.Join(dir, "engagements", eng)
	s.ReceivePush(eng, uBob, func() {
		p := filepath.Join(ed, "findings", ref.Dir, "finding.md")
		b, _ := os.ReadFile(p)
		f, _ := finding.Parse(b)
		f.SetSection("Impact", "Pushed impact.")
		f.SetMeta("title", "SQL injection in login")
		os.WriteFile(p, f.Bytes(), 0o644)
		nf := finding.New("F-002", "XSS", "bob", s.Config().Sections)
		os.MkdirAll(filepath.Join(ed, "findings", "F-002-xss"), 0o755)
		os.WriteFile(filepath.Join(ed, "findings", "F-002-xss", "finding.md"), nf.Bytes(), 0o644)
		git(t, ed, "add", "-A")
		git(t, ed, "-c", "user.name=bob", "-c", "user.email=bob@x", "commit", "-qm", "push")
	})
	c := rec.last(EventCreated)
	if c.Fid != "F-002" || c.Dir != "F-002-xss" || c.Actor != "bob" || c.Title != "XSS" || c.Eng != eng {
		t.Fatalf("created %+v", c)
	}
	u := rec.last(EventUpdated)
	if u.Fid != "F-001" || u.Actor != "bob" || u.Title != "SQL injection in login" || !slices.Equal(u.Changed, []string{"Title", "Impact"}) {
		t.Fatalf("updated %+v", u)
	}
	if got := rec.kinds(); len(got) != 2 {
		t.Fatalf("kinds %v", got)
	}
	// the HEAD cache follows the push
	if h, _ := s.EngHead(eng); h != git(t, ed, "rev-parse", "HEAD") {
		t.Fatal("stale HEAD after push")
	}
	// a push that changes nothing (rejected) tells nothing
	s.ReceivePush(eng, uBob, func() {})
	if got := rec.kinds(); len(got) != 2 {
		t.Fatalf("kinds after empty push %v", got)
	}
}
