package web

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/abno525/yars/internal/auth"
)

// defaultDebugFor is how long the debug level stays on once Admin › System
// switched it on.
const defaultDebugFor = 15 * time.Minute

// debugAction is the audit action of the switch (it shows under System in
// Admin › Activity).
const debugAction = "system.debug"

// debugPeriod is how long the debug level stays on.
func (s *Server) debugPeriod() time.Duration {
	if s.debugFor > 0 {
		return s.debugFor
	}
	return defaultDebugFor
}

// debugSwitch is POST /admin/system/debug: the form says on or off and
// nothing else (no level, no time).
func (s *Server) debugSwitch(w http.ResponseWriter, r *http.Request) {
	s.setDebug(r.PostFormValue("on") == "1", auth.UserFrom(r.Context()).Username)
	http.Redirect(w, r, "/admin/system#syslog", http.StatusSeeOther)
}

// setDebug switches the service log to debug for debugPeriod (on), or back
// (off), for the admin by. It sets the level and nothing else: the
// redaction and the ring's own level are not its to change. Switched on
// while it is on, the period starts again (one timer). Off, the level is the
// one the server started with, also when that is not info. Each change is
// audited. Nothing is stored: after a restart the level is the configured
// one. A server without LogLevel has no switch to move. The audit row is
// written after debugMu is let go: a busy database must not hold the status
// (debugState) for as long as the row waits.
func (s *Server) setDebug(on bool, by string) {
	if s.LogLevel == nil {
		return
	}
	if detail := s.switchDebug(on, by); detail != "" {
		s.auditDebug(by, detail)
	}
}

// switchDebug is setDebug's change under debugMu; it returns the detail of
// the audit row to write, "" when nothing changed.
func (s *Server) switchDebug(on bool, by string) (detail string) {
	s.debugMu.Lock()
	defer s.debugMu.Unlock()
	if !on {
		if s.debugUntil.IsZero() {
			return ""
		}
		s.log().Info("log: the debug level is switched off", "user", by)
		s.debugOff()
		return "off"
	}
	if s.debugUntil.IsZero() {
		s.debugBase = s.LogLevel.Level()
	}
	if s.debugTimer != nil {
		s.debugTimer.Stop()
	}
	s.debugGen++
	gen, period := s.debugGen, s.debugPeriod()
	s.debugUntil = time.Now().Add(period)
	s.LogLevel.Set(slog.LevelDebug)
	s.debugTimer = time.AfterFunc(period, func() { s.debugEnd(gen) })
	s.log().Info("log: the debug level is switched on", "user", by, "minutes", int(period.Minutes()))
	return "on · until " + s.debugUntil.Format("15:04")
}

// debugOff puts the level back to the one before the switch (debugMu held).
func (s *Server) debugOff() {
	if s.debugTimer != nil {
		s.debugTimer.Stop()
		s.debugTimer = nil
	}
	s.debugGen++ // a timer that fired already finds another period
	s.LogLevel.Set(s.debugBase)
	s.debugUntil = time.Time{}
}

// debugEnd is the timer of period gen: the debug level ends by itself,
// audited as yars. A timer of a period that was switched off or started
// again meanwhile changes nothing. The audit row is written after debugMu
// is let go, as in setDebug.
func (s *Server) debugEnd(gen int) {
	s.debugMu.Lock()
	if gen != s.debugGen || s.debugUntil.IsZero() {
		s.debugMu.Unlock()
		return
	}
	s.log().Info("log: the debug level ended by itself")
	s.debugOff()
	s.debugMu.Unlock()
	select {
	case <-s.stop: // the database closes with the server
		return
	default:
	}
	s.auditDebug("yars", "off · ended by itself")
}

// auditDebug writes the switch's audit row.
func (s *Server) auditDebug(by, detail string) {
	if s.Store == nil || s.Store.DB() == nil {
		return
	}
	if err := s.Store.DB().Audit(by, debugAction, "", detail); err != nil {
		s.log().Error("log: the debug switch is not audited", "user", by, "err", err)
	}
}

// stopDebug ends a debug period when the server stops: the timer is stopped
// and the level put back, without an audit row.
func (s *Server) stopDebug() {
	if s.LogLevel == nil {
		return
	}
	s.debugMu.Lock()
	defer s.debugMu.Unlock()
	if !s.debugUntil.IsZero() {
		s.debugOff()
	}
}

// debugState is the switch as the page and yars status show it: the level
// word now ("" without LogLevel) and when a debug period ends (zero: off).
func (s *Server) debugState() (level string, until time.Time) {
	if s.LogLevel == nil {
		return "", time.Time{}
	}
	s.debugMu.Lock()
	defer s.debugMu.Unlock()
	switch lv := s.LogLevel.Level(); {
	case lv <= slog.LevelDebug:
		level = "debug"
	case lv <= slog.LevelInfo:
		level = "info"
	case lv <= slog.LevelWarn:
		level = "warn"
	default:
		level = "error"
	}
	return level, s.debugUntil
}
