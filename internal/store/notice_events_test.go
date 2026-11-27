package store

import (
	"bytes"
	"image"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/workflow"
)

// signedOffFinding is a finding in verification that bob signed off, with a
// recorder on the store's events.
func signedOffFinding(t *testing.T) (*Store, string, *recorder) {
	t.Helper()
	s, _, fd := ready(t)
	if err := s.UpdateSection(eng, fd, "Impact", "DB read", "", alice); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		act workflow.Action
		by  int
	}{{workflow.Submit, 0}, {workflow.Clear, 1}} {
		u := uAlice
		if step.by == 1 {
			u = uBob
		}
		if err := s.Transition(eng, fd, step.act, "", u); err != nil {
			t.Fatalf("%s: %v", step.act, err)
		}
	}
	rec := &recorder{}
	s.OnEvent(rec.add)
	return s, fd, rec
}

// An edit of a finding in verification says whose sign-off it voided; the
// next edit voids nobody again.
func TestEditVoidsSignOff(t *testing.T) {
	s, fd, rec := signedOffFinding(t)
	if err := s.UpdateSection(eng, fd, "Impact", "DB read and write", "", alice); err != nil {
		t.Fatal(err)
	}
	if e := rec.last(EventUpdated); !slices.Equal(e.Voided, []string{"bob"}) || e.Actor != "alice" {
		t.Fatalf("after the edit: %+v", e)
	}
	if err := s.UpdateSection(eng, fd, "Impact", "DB read, write and delete", "", alice); err != nil {
		t.Fatal(err)
	}
	if e := rec.last(EventUpdated); len(e.Voided) != 0 {
		t.Fatalf("the second edit voided again: %+v", e)
	}
}

// A new attachment drops the sign-offs and says whose.
func TestAttachmentVoidsSignOff(t *testing.T) {
	s, fd, rec := signedOffFinding(t)
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAttachment(eng, fd, "shot.png", b.Bytes(), alice); err != nil {
		t.Fatal(err)
	}
	if e := rec.last(EventUpdated); !slices.Equal(e.Voided, []string{"bob"}) {
		t.Fatalf("after the attachment: %+v", e)
	}
}

// A pushed text change voids the sign-off too, and its event says whose.
func TestPushVoidsSignOff(t *testing.T) {
	s, fd, rec := signedOffFinding(t)
	ed := filepath.Join(s.Repo().Dir, "engagements", eng)
	p := filepath.Join(ed, "findings", fd, "finding.md")
	s.ReceivePush(eng, uAlice, func() {
		b, _ := os.ReadFile(p)
		f, err := finding.Parse(b)
		if err != nil {
			t.Error(err)
			return
		}
		f.SetSection("Impact", "pushed text")
		os.WriteFile(p, f.Bytes(), 0o644)
		for _, args := range [][]string{{"add", "-A"}, {"-c", "user.name=alice", "-c", "user.email=alice@acme.example", "commit", "-q", "-m", "F-001: pushed"}} {
			if out, err := exec.Command("git", append([]string{"-C", ed}, args...)...).CombinedOutput(); err != nil {
				t.Errorf("git %v: %v\n%s", args, err, out)
			}
		}
	})
	if e := rec.last(EventUpdated); !slices.Equal(e.Voided, []string{"bob"}) || !slices.Contains(e.Changed, "Impact") {
		t.Fatalf("after the push: %+v", e)
	}
}

// A rename in Admin › Structure moves the sign-offs with the text: nobody's
// is voided, and no event says so.
func TestRenameVoidsNoSignOff(t *testing.T) {
	s, fd, rec := signedOffFinding(t)
	if _, err := s.RenameNames("section", toBusiness, System); err != nil {
		t.Fatal(err)
	}
	for _, e := range rec.evs {
		if len(e.Voided) != 0 {
			t.Fatalf("a rename voided a sign-off: %+v", e)
		}
	}
	// the sign-off still counts: the next edit voids it
	if err := s.UpdateSection(eng, fd, "Business impact", "DB read and write", "", alice); err != nil {
		t.Fatal(err)
	}
	if e := rec.last(EventUpdated); !slices.Equal(e.Voided, []string{"bob"}) {
		t.Fatalf("an edit after the rename: %+v", e)
	}
}

// A reviewer list that only loses someone is an event too, with who left.
func TestRemovedReviewerEvent(t *testing.T) {
	s, _, fd := ready(t)
	if err := s.SetReviewers(eng, fd, []string{"bob", "carol"}, uAlice); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	s.OnEvent(rec.add)
	if err := s.SetReviewers(eng, fd, []string{"bob"}, uAlice); err != nil {
		t.Fatal(err)
	}
	e := rec.last(EventReviewers)
	if !slices.Equal(e.Removed, []string{"carol"}) || len(e.Added) != 0 || e.Actor != "alice" || !slices.Equal(e.Reviewers, []string{"bob"}) {
		t.Fatalf("after the removal: %+v", e)
	}
	// the same list again: nothing happened
	n := len(rec.kinds())
	s.SetReviewers(eng, fd, []string{"bob"}, uAlice)
	if len(rec.kinds()) != n {
		t.Fatalf("an event for an unchanged list: %v", rec.kinds())
	}
}

// A new retest tells of its retester, once the retest exists.
func TestRetestAssignedEvent(t *testing.T) {
	s, _ := srcFixture(t)
	if _, ok, _ := s.DB().User("bob"); !ok {
		if err := s.DB().AddUser(uBob); err != nil {
			t.Fatal(err)
		}
	}
	rec := &recorder{}
	s.OnEvent(rec.add)
	seen := false
	s.OnEvent(func(e Event) {
		if e.Kind == EventRetest {
			// the retest is there and the retester on its team
			_, err := s.Engagement(e.Eng)
			on, _ := s.DB().IsMember(e.Eng, e.Assignee)
			seen = err == nil && on
		}
	})
	if err := s.CreateRetest(Engagement{ID: "acme-rt", Name: "Acme retest"}, eng, []string{"F-001"}, "bob", uDora); err != nil {
		t.Fatal(err)
	}
	if e := rec.last(EventRetest); e.Assignee != "bob" || e.Actor != "dora" || e.Eng != "acme-rt" || e.Title != "Acme retest" || !seen {
		t.Fatalf("retest event %+v (retest there: %v)", e, seen)
	}
	// without a retester, and for a retest that is refused: no event
	n := len(rec.kinds())
	if err := s.CreateRetest(Engagement{ID: "acme-rt2", Name: "Second"}, eng, []string{"F-001"}, "", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRetest(Engagement{ID: "acme-rt3", Name: "Third"}, eng, []string{"F-002"}, "bob", uDora); err == nil {
		t.Fatal("a draft was retested")
	}
	if got := rec.kinds(); len(got) != n {
		t.Fatalf("events %v", got[n:])
	}
}

// A message on the team board that names someone is an event; one that
// names nobody is not.
func TestBoardMentionEvent(t *testing.T) {
	s, _ := withEngagement(t)
	rec := &recorder{}
	s.OnEvent(rec.add)
	n, err := s.CreateNote(eng, "Odd header", "", "open", "seen on /login, @bob knows", uAlice)
	if err != nil {
		t.Fatal(err)
	}
	e := rec.last(EventBoard)
	if e.Note != "L-001" || e.Actor != "alice" || e.Eng != eng || e.Title != "Odd header" || e.Text != "seen on /login, @bob knows" {
		t.Fatalf("new lead: %+v", e)
	}
	if err := s.PostNote(eng, n.Num, "cc @carol", uBob); err != nil {
		t.Fatal(err)
	}
	if e := rec.last(EventBoard); e.Note != "L-001" || e.Actor != "bob" || e.Text != "cc @carol" || e.Title != "Odd header" {
		t.Fatalf("a message: %+v", e)
	}
	k := len(rec.kinds())
	if err := s.PostNote(eng, n.Num, "nobody named", uBob); err != nil {
		t.Fatal(err)
	}
	if len(rec.kinds()) != k {
		t.Fatalf("an event without a mention: %v", rec.kinds())
	}
}
