package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/events"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/store"
)

// defaultHeartbeat keeps idle event streams (and proxies) alive.
const defaultHeartbeat = 25 * time.Second

// eventKind maps the store's change kinds to event names.
var eventKind = map[string]string{
	store.ChangeChat:    events.Chat,
	store.ChangeState:   events.Workflow,
	store.ChangeContent: events.Content,
	store.ChangeCheck:   events.Check,
}

// publishChange forwards a committed store write to the event hub.
func (s *Server) publishChange(c store.Change) {
	k := eventKind[c.Kind]
	if k == "" {
		k = c.Kind
	}
	s.Events.Publish(events.Event{Eng: c.Eng, Fid: c.Fid, Kind: k, Seq: c.Seq})
}

// events streams changes to one engagement (eng) or one finding in it (f,
// the finding's ID) as server-sent events: chat, workflow, content, push.
// A client reconnecting with a Last-Event-ID older than a matching event
// gets one "resync" event instead of the ones it missed.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	eng, fid := q.Get("eng"), q.Get("f")
	if (eng != "" && !store.ValidID(eng)) || (fid != "" && !store.ValidID(fid)) {
		http.Error(w, "bad engagement or finding", http.StatusBadRequest)
		return
	}
	u := auth.UserFrom(r.Context())
	if !s.streamOpen(u.Username) {
		http.Error(w, "Too many open event streams", http.StatusTooManyRequests)
		return
	}
	defer s.streamClosed(u.Username)
	// still reports whether the stream may go on, and keeps u the account as
	// it is now: the session holds, the account is active and has no
	// temporary password, and it is still on the engagement's team. The
	// gates in front of this handler ask the same once, at the start.
	still := func() bool {
		now, ok := s.Auth.Still(r)
		if !ok || now.MustChange || (eng != "" && !s.Store.CanSee(now, eng)) {
			return false
		}
		u = now
		return true
	}
	clearDeadlines(w)
	sub := s.Events.Subscribe(eng, fid, 16)
	defer s.Events.Unsubscribe(sub)
	rc := http.NewResponseController(w)

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	send := func(format string, args ...any) bool {
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	resync := func() bool {
		return send("id: %s\nevent: resync\ndata: {}\n\n", s.Events.StreamID(s.Events.Last()))
	}
	// the starting id: a client that reconnects later says what it saw. The
	// id names this server's hub (events.StreamID), so an id from before a
	// restart reads as missed whatever its number.
	ok := true
	if last := r.Header.Get("Last-Event-ID"); last != "" && s.Events.MissedID(last, eng, fid) {
		ok = resync()
	} else {
		ok = send("retry: 5000\nid: %s\n\n", s.Events.StreamID(s.Events.Last()))
	}

	beat := s.heartbeat
	if beat <= 0 {
		beat = defaultHeartbeat
	}
	tick := time.NewTicker(beat)
	defer tick.Stop()
	for ok {
		select {
		case <-r.Context().Done():
			return
		case <-s.stop: // the server is stopping: the page reconnects to the next one
			return
		case <-tick.C:
			// the heartbeat is also when the stream is checked again: it
			// outlives a logout, a disabled account or a lost session by one
			// beat at most (25 s). The headers are sent, so it just ends.
			if !still() {
				return
			}
			ok = send(": ping\n\n")
			// the stream's one request line is written when it ends
			s.log().Debug("event stream heartbeat", "req", logs.ReqID(r.Context()), "user", u.Username)
		case <-sub.Lost():
			ok = resync()
		case e := <-sub.C():
			// the team as it is now, for every event (the account as of the
			// last beat)
			if e.Eng != "" && !s.Store.CanSee(u, e.Eng) {
				if eng != "" {
					return // this engagement's stream, and no longer on its team
				}
				continue // another team's engagement (a stream of every engagement)
			}
			data, _ := json.Marshal(struct {
				Eng string `json:"eng"`
				F   string `json:"f"`
				Seq int64  `json:"seq"`
			}{e.Eng, e.Fid, e.Seq})
			ok = send("id: %s\nevent: %s\ndata: %s\n\n", s.Events.StreamID(e.ID), e.Kind, data)
		}
	}
}

// defaultMaxStreams is how many event streams one account may hold at once.
// A browser opens one per visible tab and closes it when the tab is hidden,
// so a person stays far below it; each stream holds a goroutine and a
// connection without deadlines.
const defaultMaxStreams = 20

// streamOpen counts one more event stream of user; false when the account
// holds as many as it may (nothing is counted then).
func (s *Server) streamOpen(user string) bool {
	limit := s.maxStreams
	if limit <= 0 {
		limit = defaultMaxStreams
	}
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	if s.streams[user] >= limit {
		return false
	}
	if s.streams == nil {
		s.streams = map[string]int{}
	}
	s.streams[user]++
	return true
}

// streamClosed takes back streamOpen's count.
func (s *Server) streamClosed(user string) {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	if s.streams[user]--; s.streams[user] <= 0 {
		delete(s.streams, user)
	}
}

// workflowBar is the workflow bar alone, for live refreshes.
func (s *Server) workflowBar(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	wf, _ := s.wfGated(r, ref)
	s.exec(w, "finding.html", "workflow_bar", wf)
}
