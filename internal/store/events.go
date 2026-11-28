package store

import (
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/abno525/yars/internal/config"
)

// Domain events: what happened to a finding, for webhooks and notifications.
// They are told after the change committed.
const (
	EventStatus    = "finding.status_changed"
	EventCreated   = "finding.created"
	EventUpdated   = "finding.updated" // content changed (Changed tells what)
	EventChat      = "chat.posted"
	EventExport    = "export.sent"
	EventCheck     = "check.finished"
	EventReviewers = "finding.reviewers" // reviewers added or removed (notifications only)
	EventRetest    = "retest.assigned"   // a retest was made for Assignee (notifications only)
	EventBoard     = "board.posted"      // a message on a lead of the team board (notifications only; no webhook takes it)
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
	// finding.reviewers: who was added and who was taken off the list (State
	// is the finding's status)
	Added, Removed []string
	// finding.updated: the reviewers whose sign-off the change voided (the
	// finding is in verification and they had signed off what it replaced)
	Voided []string
	// retest.assigned: the retester
	Assignee string
	// board.posted: the lead's id (L-001); Text is the message, Title the
	// lead's title
	Note string
	// finding.updated: the parts that changed ("Title", "Severity", "CVSS",
	// "Details", "Assets", section names, "Attachments")
	Changed []string
	// chat.posted: the message; ReplyTo is the author of the thread it
	// answers ("" for a new thread)
	MsgID, Text, Section, Reply, ReplyTo string
	// export.sent
	Destination, URL, Error string
	OK                      bool
	Findings                []string
	// check.finished: the run's state; finding.reviewers: the status
	State            string
	Errors, Warnings int
	// check.finished: the run was one of many started with one press (Check
	// stale on the Inbox)
	Bulk bool
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

// Unheard lists the names text mentions (@name, in order) that get no notice
// of a message in eng: no account of that name, a disabled one, or one that
// cannot see the engagement: the rule the notifier applies to every notice.
// The writer is told, with one wording for all three: who has an account is
// not for every member to learn. The writer's own name is left out (nobody is
// told of what they did themselves). Without a database nobody is told of
// anything, and the list is empty.
func (s *Store) Unheard(eng, text string, by config.User) []string {
	if s.db == nil {
		return nil
	}
	var out []string
	for _, name := range Mentions(text) {
		if name == by.Username {
			continue
		}
		if u, ok, err := s.db.User(name); err != nil || !ok || u.Disabled || !s.CanSee(u, eng) {
			out = append(out, name)
		}
	}
	return out
}

// UnheardLine is the line a page shows the writer for names (Unheard): "Not
// notified: @out @nobody", five names at most and then the count of the
// rest; "" for none.
func UnheardLine(names []string) string {
	if len(names) == 0 {
		return ""
	}
	const most = 5
	line := "Not notified:"
	for _, n := range names[:min(len(names), most)] {
		line += " @" + n
	}
	if len(names) > most {
		line += " and " + strconv.Itoa(len(names)-most) + " more"
	}
	return line
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
