package web

import (
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

// defaultHealthWait is how long a probe waits for the database's answer.
const defaultHealthWait = 2 * time.Second

// What a probe that fails for a reason other than the database's own error
// is logged with (the body never holds a reason).
var (
	errHealthNoDB = errors.New("no database")
	errHealthSlow = errors.New("the database did not answer in time")
)

// probeState is the state of GET /healthz: the one read of the database
// under way (run; probes that come meanwhile wait for the same read) and
// whether the last answer was a bad one (the log gets a line when that
// changes).
type probeState struct {
	mu  sync.Mutex
	run *healthRun
	bad bool
}

// healthRun is one read of the database: done closes once err is set.
type healthRun struct {
	start time.Time
	done  chan struct{}
	err   error
}

// healthz answers a probe (a load balancer, a container runtime, a monitor)
// without a login: 200 "ok" when the server answers and its database reads,
// else 503 "unavailable". The answer is the same for everyone and holds
// nothing else: no version, no count, no path, no error text (an SQLite
// error names the file). It reads no cookie, sets none and writes nothing.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	err := s.healthRead()
	s.probe.mu.Lock()
	was := s.probe.bad
	s.probe.bad = err != nil
	s.probe.mu.Unlock()
	// one line when the answer changes, not one per probe: a probe asks every
	// few seconds, and the ring of warnings holds 200 lines
	switch {
	case err != nil && !was:
		s.log().Warn("health check failed", "err", err)
	case err == nil && was:
		s.log().Info("health check passes again")
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "unavailable\n")
		return
	}
	io.WriteString(w, "ok\n")
}

// healthRead reads the database once (its schema number: no write, no
// transaction, no repository lock, so a long push or a held engagement is
// not "down") and waits for the answer for the server's health wait. One
// read runs at a time: probes that come while it runs share it, and once it
// has run longer than the wait they are answered at once, so a database
// that hangs does not gather a goroutine per probe.
func (s *Server) healthRead() error {
	read := s.healthProbe
	if read == nil {
		if s.Store == nil || s.Store.DB() == nil {
			return errHealthNoDB
		}
		d := s.Store.DB()
		read = func() error { _, err := d.Version(); return err }
	}
	wait := s.healthWait
	if wait <= 0 {
		wait = defaultHealthWait
	}
	h := &s.probe
	h.mu.Lock()
	run := h.run
	if run == nil {
		run = &healthRun{start: time.Now(), done: make(chan struct{})}
		h.run = run
		go func() {
			run.err = read()
			h.mu.Lock()
			h.run = nil
			h.mu.Unlock()
			close(run.done)
		}()
	} else if time.Since(run.start) > wait {
		h.mu.Unlock()
		return errHealthSlow
	}
	h.mu.Unlock()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-run.done:
		return run.err
	case <-timer.C:
		return errHealthSlow
	}
}
