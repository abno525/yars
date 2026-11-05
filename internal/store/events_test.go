package store

import (
	"slices"
	"strings"
	"sync"
	"testing"

	"yars/internal/chat"
	"yars/internal/workflow"
)

// recorder collects the store's domain events.
type recorder struct {
	mu  sync.Mutex
	evs []Event
}

func (r *recorder) add(e Event) { r.mu.Lock(); r.evs = append(r.evs, e); r.mu.Unlock() }

func (r *recorder) kinds() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.evs {
		out = append(out, e.Kind)
	}
	return out
}

func (r *recorder) last(kind string) Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.evs) - 1; i >= 0; i-- {
		if r.evs[i].Kind == kind {
			return r.evs[i]
		}
	}
	return Event{}
}

func TestDomainEvents(t *testing.T) {
	s, _ := withEngagement(t)
	rec := &recorder{}
	s.OnEvent(rec.add)
	ref, err := s.CreateFinding(eng, "SQL injection", alice)
	if err != nil {
		t.Fatal(err)
	}
	fd := ref.Dir
	if e := rec.last(EventCreated); e.Fid != "F-001" || e.Dir != fd || e.Actor != "alice" || e.Title != "SQL injection" || e.Eng != eng {
		t.Fatalf("created %+v", e)
	}
	if err := s.SetReviewers(eng, fd, []string{"bob"}, uAlice); err != nil {
		t.Fatal(err)
	}
	if e := rec.last(EventReviewers); !slices.Equal(e.Added, []string{"bob"}) || e.Actor != "alice" {
		t.Fatalf("reviewers %+v", e)
	}
	// keeping bob and adding carol: only carol is new
	s.SetReviewers(eng, fd, []string{"bob", "carol"}, uAlice)
	if e := rec.last(EventReviewers); !slices.Equal(e.Added, []string{"carol"}) {
		t.Fatalf("reviewers %+v", e)
	}
	s.UpdateSeverity(eng, fd, "high", "", alice)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Return, "add a PoC", uBob); err != nil {
		t.Fatal(err)
	}
	e := rec.last(EventStatus)
	if e.From != "verification" || e.To != "draft" || e.Action != "return" || e.Reason != "add a PoC" || e.Actor != "bob" ||
		e.Author != "alice" || e.Severity != "high" || !slices.Equal(e.Reviewers, []string{"bob", "carol"}) {
		t.Fatalf("status %+v", e)
	}
	// a denied transition sends nothing
	n := len(rec.kinds())
	s.Transition(eng, fd, workflow.Approve, "", uBob)
	if len(rec.kinds()) != n {
		t.Fatal("event for a denied transition")
	}

	root, err := s.PostChat(eng, fd, chat.Message{Text: "Which roles? @alice @nobody", Section: "Impact"}, uBob)
	if err != nil {
		t.Fatal(err)
	}
	e = rec.last(EventChat)
	if e.MsgID != root.ID || e.Text != "Which roles? @alice @nobody" || e.Section != "Impact" || e.Actor != "bob" || e.ReplyTo != "" {
		t.Fatalf("chat %+v", e)
	}
	if !slices.Equal(Mentions(e.Text), []string{"alice", "nobody"}) {
		t.Fatalf("mentions %v", Mentions(e.Text))
	}
	s.PostChat(eng, fd, chat.Message{Text: "admins only", Reply: root.ID}, uAlice)
	if e := rec.last(EventChat); e.ReplyTo != "bob" || e.Reply != root.ID {
		t.Fatalf("reply %+v", e)
	}
	// resolving is not a message
	n = len(rec.kinds())
	s.PostChat(eng, fd, chat.Message{Resolves: root.ID}, uBob)
	if len(rec.kinds()) != n {
		t.Fatalf("event for a resolve: %v", rec.kinds())
	}
	s.Emit(Event{Kind: EventExport, Eng: eng, Actor: "dora", Destination: "jira"})
	if e := rec.last(EventExport); e.Destination != "jira" || e.At.IsZero() {
		t.Fatalf("export %+v", e)
	}
	if got := strings.Join(rec.kinds(), ","); !strings.HasPrefix(got, "finding.created,finding.reviewers,finding.reviewers,finding.updated,finding.status_changed") {
		t.Fatalf("kinds %s", got)
	}
}

func TestCheckFinishedEvent(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, checkRules)
	s.UpdateSection(eng, fd, "Impact", "a foo here", "", alice)
	rec := &recorder{}
	s.OnEvent(rec.add)
	checked(t, s, fd)
	e := rec.last(EventCheck)
	if e.State != "done" || e.Errors != 1 || e.Warnings != 1 || e.Actor != "alice" || e.Author != "alice" || e.Fid != "F-001" {
		t.Fatalf("check %+v", e)
	}
}

func TestMentions(t *testing.T) {
	got := Mentions("ping @rev1, @pen-2 and @rev1 again; mail a@b.example `@code` @")
	if !slices.Equal(got, []string{"rev1", "pen-2"}) {
		t.Fatalf("%v", got)
	}
}
