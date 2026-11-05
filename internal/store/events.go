package store

import (
	"regexp"
	"slices"
	"time"
)

// Domain events: what happened to a finding, for webhooks and notifications.
// They are told after the change committed.
const (
	EventStatus    = "finding.status_changed"
	EventCreated   = "finding.created"
	EventChat      = "chat.posted"
	EventExport    = "export.sent"
	EventCheck     = "check.finished"
	EventReviewers = "finding.reviewers" // reviewers added (notifications only)
)

// Event is one domain event. Which fields are set depends on Kind.
type Event struct {
	Kind  string
	At    time.Time
	Actor string // who did it
	Eng   string
	// the finding
	Dir, Fid, Title, Severity, Author string
	Reviewers                         []string
	// finding.status_changed
	Action, From, To, Reason string
	// finding.reviewers: who was added
	Added []string
	// chat.posted: the message; ReplyTo is the author of the thread it
	// answers ("" for a new thread)
	MsgID, Text, Section, Reply, ReplyTo string
	// export.sent
	Destination, URL, Error string
	OK                      bool
	Findings                []string
	// check.finished
	State            string
	Errors, Warnings int
}

// OnEvent registers fn to be told about every domain event. fn runs on the
// writer's goroutine: it must be quick (queue work, don't do it).
func (s *Store) OnEvent(fn func(Event)) {
	s.subsMu.Lock()
	s.evSubs = append(s.evSubs, fn)
	s.subsMu.Unlock()
}

// Emit tells the subscribers about e (At is set when zero). Callers outside
// the store use it for what happens elsewhere (exports).
func (s *Store) Emit(e Event) {
	if e.At.IsZero() {
		e.At = time.Now().UTC().Truncate(time.Second)
	}
	s.subsMu.RLock()
	subs := s.evSubs
	s.subsMu.RUnlock()
	for _, fn := range subs {
		fn(e)
	}
}

// findingEvent is an event about ref's finding.
func findingEvent(kind, actor string, ref FindingRef) Event {
	m := ref.F.Meta
	return Event{Kind: kind, Actor: actor, Eng: ref.EngID, Dir: ref.Dir, Fid: m.ID, Title: m.Title,
		Severity: m.Severity, Author: m.Author, Reviewers: slices.Clone(m.Reviewers)}
}

var mentionRe = regexp.MustCompile(`(?:^|[\s(\[{>,;])@([A-Za-z0-9][A-Za-z0-9._-]*)`)

// Mentions lists the @user names in a chat text, once each, in order.
func Mentions(text string) []string {
	var out []string
	for _, m := range mentionRe.FindAllStringSubmatch(text, -1) {
		n := m[1]
		for len(n) > 0 && (n[len(n)-1] == '.' || n[len(n)-1] == '-') {
			n = n[:len(n)-1]
		}
		if n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}
