package web

import (
	"cmp"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Status is what the server is doing now, for Admin › System and for yars
// status (StatusHandler): one function builds it for both. Everything but
// Schema and Deliveries is read from memory, so it is there when the
// database is locked or closed. It holds usernames and engagement IDs, and
// the ring's lines, which are redacted as the service log is; never a key, a
// token or an address.
type Status struct {
	Version  string    `json:"version"`
	Schema   int       `json:"schema"` // 0: the database did not say
	Started  time.Time `json:"started"`
	UptimeMS int64     `json:"uptime_ms"`
	// the check runs holding a slot, the ones waiting for one, the fixes
	// with AI under way
	ChecksRunning int `json:"checks_running"`
	ChecksQueued  int `json:"checks_queued"`
	Fixes         int `json:"fixes"`
	// webhook deliveries waiting to be sent or tried again (-1: the database
	// did not say) and mails being sent (there is no queue of mail)
	Deliveries int           `json:"deliveries"`
	Mails      int           `json:"mails"`
	Streams    []StreamCount `json:"streams"` // open event streams, by account
	Locks      []LockInfo    `json:"locks"`   // repository locks held or waited for
	Lines      []StatusLine  `json:"lines"`   // the ring: the last warn and error lines, oldest first
}

// StreamCount is an account's open event streams.
type StreamCount struct {
	User string `json:"user"`
	Open int    `json:"open"`
}

// LockInfo is a repository lock that is held or waited for: Eng "" is the
// main repository, HeldMS 0 a lock nobody holds at the moment.
type LockInfo struct {
	Eng     string `json:"eng"`
	HeldMS  int64  `json:"held_ms"`
	Waiting int    `json:"waiting"`
}

// StatusLine is a line of the ring.
type StatusLine struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Text  string    `json:"text"`
}

// statusDBWait is how long Status waits for the database's two numbers.
const statusDBWait = time.Second

// Status reads the server's state now.
func (s *Server) Status() Status {
	st := Status{Version: s.Version, Started: s.started, Deliveries: -1}
	if !s.started.IsZero() {
		st.UptimeMS = time.Since(s.started).Milliseconds()
	}
	if s.Store != nil {
		w := s.Store.Work()
		st.ChecksRunning, st.ChecksQueued, st.Fixes = w.ChecksRunning, w.ChecksQueued, w.Fixes
		for _, l := range s.Store.LockStates() {
			st.Locks = append(st.Locks, LockInfo{Eng: l.Eng, HeldMS: l.Held.Milliseconds(), Waiting: l.Waiting})
			if l.Held > 0 && st.Locks[len(st.Locks)-1].HeldMS == 0 {
				st.Locks[len(st.Locks)-1].HeldMS = 1 // held, for under a millisecond
			}
		}
		st.Schema, st.Deliveries = s.statusDB()
	}
	if s.Notifier != nil {
		st.Mails = s.Notifier.Sending()
	}
	s.streamsMu.Lock()
	for u, n := range s.streams {
		st.Streams = append(st.Streams, StreamCount{User: u, Open: n})
	}
	s.streamsMu.Unlock()
	slices.SortFunc(st.Streams, func(a, b StreamCount) int { return strings.Compare(a.User, b.User) })
	if s.LogRing != nil {
		for _, l := range s.LogRing.Lines() {
			st.Lines = append(st.Lines, StatusLine{Time: l.Time, Level: l.Level.String(), Text: l.Text})
		}
	}
	return st
}

// statusDB reads what Status takes from the database: the schema (0 when it
// is not read) and the waiting deliveries (-1 when they are not). A database
// that does not answer within statusDBWait (locked by a long write) reads as
// both unknown: the rest of the status must come anyway.
func (s *Server) statusDB() (schema, deliveries int) {
	d := s.Store.DB()
	if d == nil {
		return 0, -1
	}
	type facts struct{ schema, deliveries int }
	got := make(chan facts, 1)
	go func() {
		f := facts{0, -1}
		if v, err := d.Version(); err == nil {
			f.schema = v
		}
		if n, err := d.PendingDeliveries(); err == nil {
			f.deliveries = n
		}
		got <- f
	}()
	select {
	case f := <-got:
		return f.schema, f.deliveries
	case <-time.After(statusDBWait):
		return 0, -1
	}
}

// StatusHandler serves the status and nothing else: GET /status answers
// Status as JSON. yars serve mounts it on a socket in the data folder that
// only the service's own account can open, which is all the proof it asks
// for; it is never part of Handler.
func (s *Server) StatusHandler() http.Handler {
	s.init()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(s.Status())
	})
	return mux
}

// stateView is the Current state and Log panels of Admin › System.
type stateView struct {
	ChecksRunning, ChecksQueued, Fixes, Mails int
	Deliveries                                string // "—" when the database did not say
	Streams                                   []StreamCount
	Locks                                     []lockRow
	Lines                                     []lineRow // newest first
}

// lockRow is a repository lock on the page.
type lockRow struct {
	Repo, Held string
	Waiting    int
}

// lineRow is a line of the ring on the page: State is the tag's class.
type lineRow struct {
	Time, Level, State, Text string
}

// stateViewOf is st as the page shows it.
func stateViewOf(st Status) stateView {
	v := stateView{ChecksRunning: st.ChecksRunning, ChecksQueued: st.ChecksQueued, Fixes: st.Fixes, Mails: st.Mails,
		Deliveries: "—", Streams: st.Streams}
	if st.Deliveries >= 0 {
		v.Deliveries = strconv.Itoa(st.Deliveries)
	}
	for _, l := range st.Locks {
		row := lockRow{Repo: cmp.Or(l.Eng, "main"), Held: "—", Waiting: l.Waiting}
		if l.HeldMS > 0 {
			row.Held = dur(time.Duration(l.HeldMS) * time.Millisecond)
		}
		v.Locks = append(v.Locks, row)
	}
	for i := len(st.Lines) - 1; i >= 0; i-- {
		l := st.Lines[i]
		state := "warn"
		if l.Level != "WARN" {
			state = "bad"
		}
		v.Lines = append(v.Lines, lineRow{Time: l.Time.Local().Format("2006-01-02 15:04:05"), Level: l.Level, State: state, Text: l.Text})
	}
	return v
}
