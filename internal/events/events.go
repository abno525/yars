// Package events is an in-process publish/subscribe hub: the store and the
// git server publish what changed, and open browser tabs (server-sent
// events) hear about the engagement or finding they show.
package events

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
)

// Kinds of change.
const (
	Chat     = "chat"     // a chat message
	Workflow = "workflow" // workflow state: status, reviewers, clearances
	Content  = "content"  // the finding's content (a commit by YARS)
	Push     = "push"     // a git push to an engagement ("" = the main repo)
	Check    = "check"    // a check run started, progressed or ended; a dismissal
	Presence = "presence" // someone started, kept or stopped editing a section
	// Board is a team board change; it is also the Fid of its events, which
	// reach only subscribers of that Fid (the board page), never streams of
	// a whole engagement.
	Board = "board"
	// Notice says an account's inbox may hold something new: sent once the
	// notices of a change are written (the change itself is published before
	// them), and for a team board change, whose own event streams of a whole
	// engagement never get. It carries the engagement and nothing else.
	Notice = "notice"
)

// Event says what changed. ID is set by the hub (increasing, from 1); Seq
// is the engagement's change counter when the store knows it. An empty Fid
// concerns the whole engagement, an empty Eng everything.
type Event struct {
	ID       uint64
	Eng, Fid string
	Kind     string
	Seq      int64
}

// ringSize is how many recent events the hub keeps to answer Missed.
const ringSize = 512

// Hub fans events out to subscribers. Publishing never blocks: a
// subscriber whose buffer is full loses the event and is told so (Lost).
type Hub struct {
	mu   sync.Mutex
	boot string // random per hub: part of a stream's id (StreamID)
	last uint64
	subs map[*Sub]struct{}
	ring [ringSize]Event // ring[id % ringSize]
}

// Sub is one subscription; read events from C.
type Sub struct {
	eng, fid string
	c        chan Event
	lost     chan struct{}
}

// New makes a hub with a random boot value. It is no secret: it only tells
// this hub's ids from those of the hub before a restart.
func New() *Hub {
	var b [8]byte
	rand.Read(b[:]) // never fails (crypto/rand)
	return &Hub{subs: map[*Sub]struct{}{}, boot: hex.EncodeToString(b[:])}
}

// C delivers the subscription's events.
func (s *Sub) C() <-chan Event { return s.c }

// Lost is signalled when an event was dropped because C was full; the
// subscriber should then refetch everything it shows.
func (s *Sub) Lost() <-chan struct{} { return s.lost }

func (s *Sub) wants(e Event) bool {
	if e.Fid == Board && s.fid != Board {
		return false
	}
	return (s.eng == "" || e.Eng == "" || e.Eng == s.eng) && (s.fid == "" || e.Fid == "" || e.Fid == s.fid)
}

// Subscribe listens to one engagement ("" = all) and one finding in it
// ("" = all), with room for buf undelivered events.
func (h *Hub) Subscribe(eng, fid string, buf int) *Sub {
	if buf < 1 {
		buf = 1
	}
	s := &Sub{eng: eng, fid: fid, c: make(chan Event, buf), lost: make(chan struct{}, 1)}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

// Unsubscribe stops deliveries to s (its channel is not closed).
func (h *Hub) Unsubscribe(s *Sub) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
}

// Publish numbers e and delivers it to every matching subscriber without
// waiting for any of them. It returns e with its ID.
func (h *Hub) Publish(e Event) Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.last++
	e.ID = h.last
	h.ring[e.ID%ringSize] = e
	for s := range h.subs {
		if !s.wants(e) {
			continue
		}
		select {
		case s.c <- e:
		default:
			select {
			case s.lost <- struct{}{}:
			default:
			}
		}
	}
	return e
}

// Last is the ID of the latest event (0 before the first).
func (h *Hub) Last() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last
}

// StreamID is the id an event stream carries for event number n:
// "<boot>-<n>". Event numbers start at 1 again after a restart, so the
// number alone does not say which events a client saw.
func (h *Hub) StreamID(n uint64) string {
	return h.boot + "-" + strconv.FormatUint(n, 10)
}

// maxStreamID bounds what MissedID reads of a client's id.
const maxStreamID = 64

// MissedID is Missed for the id a client gives back (Last-Event-ID). An id
// of another hub (a restart), a plain number (a page loaded before ids
// named the hub) and anything that does not read count as missed.
func (h *Hub) MissedID(id, eng, fid string) bool {
	if len(id) > maxStreamID {
		return true
	}
	boot, num, ok := strings.Cut(id, "-")
	if !ok || boot != h.boot {
		return true
	}
	n, err := strconv.ParseUint(num, 10, 64)
	return err != nil || h.Missed(n, eng, fid)
}

// Missed reports whether a subscriber of (eng, fid) that saw events up to
// ID since may have missed one: a matching event came after it, older events
// are no longer known, or since is not from this hub (a restart).
func (h *Hub) Missed(since uint64, eng, fid string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if since > h.last {
		return true
	}
	if h.last-since > ringSize {
		return true
	}
	probe := Sub{eng: eng, fid: fid}
	for id := since + 1; id <= h.last; id++ {
		if probe.wants(h.ring[id%ringSize]) {
			return true
		}
	}
	return false
}
