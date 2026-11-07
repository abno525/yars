// Package chat models a finding's append-only chat.jsonl: threaded
// messages, optional section anchors, resolve/reopen markers and workflow
// event lines.
package chat

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxText = 10000

type Message struct {
	ID       string    `json:"id"`
	TS       time.Time `json:"ts"`
	User     string    `json:"user"`
	Text     string    `json:"text,omitempty"`
	Section  string    `json:"section,omitempty"`
	Reply    string    `json:"reply,omitempty"`
	Resolves string    `json:"resolves,omitempty"`
	Reopens  string    `json:"reopens,omitempty"`
	Event    string    `json:"event,omitempty"`
	// Kind marks a thread opened by YARS itself: KindCheck for a violation
	// a check run found ("" = a person's message).
	Kind string `json:"kind,omitempty"`
}

// KindCheck is the Kind of a thread a check run opened for a violation.
const KindCheck = "check"

// Parse decodes JSONL, skipping blank, invalid and id-less lines.
func Parse(b []byte) []Message {
	var out []Message
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var m Message
		if json.Unmarshal(line, &m) != nil || m.ID == "" {
			continue
		}
		out = append(out, m)
	}
	return out
}

// Line encodes one message as a JSONL line.
func Line(m Message) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func NewID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type Thread struct {
	Root       Message
	Replies    []Message
	Resolved   bool
	ResolvedBy string
}

// Item is one entry of the timeline: an event line or a thread.
type Item struct {
	Event  *Message
	Thread *Thread
}

// Timeline folds messages into events and threads, ordered by first message.
func Timeline(msgs []Message) []Item {
	var items []Item
	threads := map[string]*Thread{}
	for _, m := range msgs {
		switch {
		case m.Event != "":
			m := m
			items = append(items, Item{Event: &m})
		case m.Reply != "":
			if t := threads[m.Reply]; t != nil {
				t.Replies = append(t.Replies, m)
			}
		case m.Resolves != "":
			if t := threads[m.Resolves]; t != nil {
				t.Resolved, t.ResolvedBy = true, m.User
			}
		case m.Reopens != "":
			if t := threads[m.Reopens]; t != nil {
				t.Resolved, t.ResolvedBy = false, ""
			}
		default:
			t := &Thread{Root: m}
			threads[m.ID] = t
			items = append(items, Item{Thread: t})
		}
	}
	return items
}

// OpenCount counts unresolved threads, in total and per section ("" = general).
func OpenCount(msgs []Message) (int, map[string]int) {
	by := map[string]int{}
	total := 0
	for _, it := range Timeline(msgs) {
		if it.Thread != nil && !it.Thread.Resolved {
			total++
			by[it.Thread.Root.Section]++
		}
	}
	return total, by
}

// Validate checks a new message against the existing ones.
func Validate(existing []Message, m Message) error {
	refs := 0
	for _, r := range []string{m.Reply, m.Resolves, m.Reopens} {
		if r != "" {
			refs++
		}
	}
	if refs > 1 {
		return errors.New("a message can reply, resolve or reopen — only one")
	}
	if m.Resolves == "" && m.Reopens == "" {
		text := strings.TrimSpace(m.Text)
		if text == "" {
			return errors.New("message is empty")
		}
		if utf8.RuneCountInString(text) > MaxText {
			return errors.New("message is longer than 10000 characters")
		}
	}
	ref := m.Reply + m.Resolves + m.Reopens
	if ref == "" {
		return nil
	}
	for _, e := range existing {
		if e.ID == ref {
			if e.Event != "" || e.Reply != "" || e.Resolves != "" || e.Reopens != "" {
				return errors.New("can only reply to, resolve or reopen a thread")
			}
			if m.Resolves != "" {
				// resolving again would change nothing
				for _, it := range Timeline(existing) {
					if t := it.Thread; t != nil && t.Root.ID == ref && t.Resolved {
						return errors.New("thread already resolved")
					}
				}
			}
			return nil
		}
	}
	return errors.New("unknown thread " + ref)
}
