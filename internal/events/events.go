// Package events is an in-process publish/subscribe hub: the store and the
// git server publish what changed, and open browser tabs (server-sent
// events) hear about the engagement or finding they show.
package events

import "sync"

// Kinds of change.
const (
	Chat     = "chat"     // a chat message
	Workflow = "workflow" // workflow state: status, reviewers, clearances
	Content  = "content"  // the finding's content (a commit by YARS)
	Push     = "push"     // a git push to an engagement ("" = the main repo)
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

func New() *Hub { return &Hub{subs: map[*Sub]struct{}{}} }

// C delivers the subscription's events.
func (s *Sub) C() <-chan Event { return s.c }

// Lost is signalled when an event was dropped because C was full; the
// subscriber should then refetch everything it shows.
func (s *Sub) Lost() <-chan struct{} { return s.lost }

func (s *Sub) wants(e Event) bool {
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
