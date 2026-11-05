package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"yars/internal/events"
	"yars/internal/store"
)

// defaultHeartbeat keeps idle event streams (and proxies) alive.
const defaultHeartbeat = 25 * time.Second

// eventKind maps the store's change kinds to event names.
var eventKind = map[string]string{
	store.ChangeChat:    events.Chat,
	store.ChangeState:   events.Workflow,
	store.ChangeContent: events.Content,
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
		return send("id: %d\nevent: resync\ndata: {}\n\n", s.Events.Last())
	}
	// the starting id: a client that reconnects later says what it saw
	ok := true
	if last := r.Header.Get("Last-Event-ID"); last != "" {
		id, err := strconv.ParseUint(last, 10, 64)
		if err != nil || s.Events.Missed(id, eng, fid) {
			ok = resync()
		} else {
			ok = send("retry: 5000\nid: %d\n\n", s.Events.Last())
		}
	} else {
		ok = send("retry: 5000\nid: %d\n\n", s.Events.Last())
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
		case <-tick.C:
			ok = send(": ping\n\n")
		case <-sub.Lost():
			ok = resync()
		case e := <-sub.C():
			data, _ := json.Marshal(struct {
				Eng string `json:"eng"`
				F   string `json:"f"`
				Seq int64  `json:"seq"`
			}{e.Eng, e.Fid, e.Seq})
			ok = send("id: %d\nevent: %s\ndata: %s\n\n", e.ID, e.Kind, data)
		}
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
