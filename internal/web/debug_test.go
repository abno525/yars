package web

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/logs"
)

// debugEnv is a server whose log has a level that can change, as yars serve
// builds it: the log starts at level, on out, with the ring.
func debugEnv(t *testing.T, level slog.Level) (*env, *slog.LevelVar, *lockedBuf) {
	t.Helper()
	out := &lockedBuf{}
	lv := new(slog.LevelVar)
	lv.Set(level)
	ring := logs.NewRing()
	e := newEnvLog(t, slog.New(logs.HandlerRing(out, logs.Text, lv, ring)))
	e.srv.LogLevel, e.srv.LogRing = lv, ring
	return e, lv, out
}

// debugRows are the audit rows of the debug switch, newest first.
func debugRows(t *testing.T, e *env) []db.AuditEntry {
	t.Helper()
	l, _, err := e.srv.Store.DB().AuditQuery(db.AuditFilter{Action: "system.debug", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// debugRow is the switch's row on Admin › System.
func debugRow(t *testing.T, e *env) string {
	t.Helper()
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	row := between(between(b, `id="syslog"`, "</section>"), `<td class="setname">Debug level for 15 minutes</td>`, "</tr>")
	if row == "" {
		t.Fatalf("no debug row:\n%s", between(b, `id="syslog"`, "</section>"))
	}
	return row
}

var untilSlot = regexp.MustCompile(`<span class="slot w96 mono">(\d\d:\d\d)</span>`)

const offSlot = `<span class="slot w96 mono">—</span>`

// Admin › System switches the log to debug for 15 minutes, without a
// restart: an admin's POST, audited, shown with the time it ends. Switched
// off, the level is at once the one the server started with. It changes the
// level only: a debug line is redacted as every line, and the ring keeps
// warnings and errors as before.
func TestDebugSwitch(t *testing.T) {
	e, lv, out := debugEnv(t, slog.LevelWarn)
	lg := e.srv.Logger
	ctx := context.Background()
	if rec := e.do(t, "dora", "GET", "/admin/system/debug", nil, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/admin/system/debug", url.Values{"on": {"1"}}, map[string]string{"Sec-Fetch-Site": "cross-site"}); rec.Code != http.StatusForbidden {
		t.Fatalf("a cross-site POST %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/admin/system/debug", url.Values{"on": {"1"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("not an admin %d", rec.Code)
	}
	if lg.Enabled(ctx, slog.LevelInfo) || len(debugRows(t, e)) != 0 {
		t.Fatal("a refused request changed the level or was audited")
	}
	if row := debugRow(t, e); !strings.Contains(row, `action="/admin/system/debug"`) || !strings.Contains(row, `name="on" value="1"`) ||
		!strings.Contains(row, `role="switch" aria-checked="false"`) || strings.Contains(row, "disabled") || !strings.Contains(row, offSlot) {
		t.Fatalf("the row, off:\n%s", row)
	}

	// on: only on or off is read of the form, never a level or a time
	rec := e.do(t, "dora", "POST", "/admin/system/debug", url.Values{"on": {"1"}, "level": {"error"}, "minutes": {"600"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/system#syslog" {
		t.Fatalf("on: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if !lg.Enabled(ctx, slog.LevelDebug) || lv.Level() != slog.LevelDebug {
		t.Fatalf("the level after the switch: %v", lv.Level())
	}
	rows := debugRows(t, e)
	if len(rows) != 1 || rows[0].Actor != "dora" || !regexp.MustCompile(`^on · until \d\d:\d\d$`).MatchString(rows[0].Detail) {
		t.Fatalf("audit %+v", rows)
	}
	row := debugRow(t, e)
	m := untilSlot.FindStringSubmatch(row)
	if m == nil || !strings.Contains(row, `role="switch" aria-checked="true"`) || !strings.Contains(row, `name="on" value="0"`) {
		t.Fatalf("the row, on:\n%s", row)
	}
	// it ends 15 minutes from now
	if end := time.Now().Add(15 * time.Minute); m[1] != end.Format("15:04") && m[1] != end.Add(-time.Minute).Format("15:04") {
		t.Fatalf("it ends at %s, now is %s", m[1], time.Now().Format("15:04"))
	}
	if st := e.srv.Status(); st.Level != "debug" || st.DebugUntil.IsZero() {
		t.Fatalf("status %+v", st)
	}

	// the redaction is as it was, and so is the ring
	before := len(e.srv.LogRing.Lines())
	e.do(t, "dora", "GET", "/static/app.js", nil, nil)
	lg.Debug("a debug line", "password", "zqpassword7f3kq", "err", "open findings/F-001-zqslug7f3kq/finding.md")
	if got := out.String(); !strings.Contains(got, `level=DEBUG msg=request`) ||
		!strings.Contains(got, `level=DEBUG msg="a debug line" err="open findings/F-001/finding.md"`) || strings.Contains(got, "zq") {
		t.Fatalf("the log at debug:\n%s", got)
	}
	if after := len(e.srv.LogRing.Lines()); after != before {
		t.Fatalf("the ring took %d debug or info lines", after-before)
	}

	// off, before the time: back to the level of the start, at once
	if rec := e.do(t, "dora", "POST", "/admin/system/debug", url.Values{"on": {"0"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("off: %d", rec.Code)
	}
	if lv.Level() != slog.LevelWarn {
		t.Fatalf("the level after off: %v", lv.Level())
	}
	if rows := debugRows(t, e); len(rows) != 2 || rows[0].Actor != "dora" || rows[0].Detail != "off" {
		t.Fatalf("audit %+v", rows)
	}
	if row := debugRow(t, e); !strings.Contains(row, `aria-checked="false"`) || !strings.Contains(row, offSlot) {
		t.Fatalf("the row after off:\n%s", row)
	}
	if st := e.srv.Status(); st.Level != "warn" || !st.DebugUntil.IsZero() {
		t.Fatalf("status after off %+v", st)
	}
	// off again changes and audits nothing
	e.do(t, "dora", "POST", "/admin/system/debug", url.Values{"on": {"0"}}, nil)
	if rows := debugRows(t, e); len(rows) != 2 {
		t.Fatalf("a second off is audited: %+v", rows)
	}
}

// Debug ends by itself: the level goes back to the one the server started
// with, the row shows off, and the end is audited as yars. Switched on
// twice it is one period, counted from the second time. A timer of a period
// that was switched off, or of a server that stopped, changes nothing.
func TestDebugEndsByItself(t *testing.T) {
	e, lv, _ := debugEnv(t, slog.LevelWarn)
	on := func() {
		t.Helper()
		if rec := e.do(t, "dora", "POST", "/admin/system/debug", url.Values{"on": {"1"}}, nil); rec.Code != http.StatusSeeOther {
			t.Fatalf("on: %d", rec.Code)
		}
	}
	ended := func() int {
		n := 0
		for _, r := range debugRows(t, e) {
			if r.Actor == "yars" {
				if r.Detail != "off · ended by itself" {
					t.Fatalf("audit %+v", r)
				}
				n++
			}
		}
		return n
	}
	wait := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(time.Minute)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatalf("%s: level %v, audit %+v", what, lv.Level(), debugRows(t, e))
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	e.srv.debugFor = 30 * time.Millisecond
	on()
	wait("the period does not end", func() bool { return lv.Level() == slog.LevelWarn && ended() == 1 })
	if row := debugRow(t, e); !strings.Contains(row, `aria-checked="false"`) || !strings.Contains(row, offSlot) {
		t.Fatalf("the row after the end:\n%s", row)
	}

	// twice: one period, from the second
	// (no sleep between the two: the first period's timer is run by hand, so
	// a slow machine changes nothing)
	period := func() (int, time.Time) {
		e.srv.debugMu.Lock()
		defer e.srv.debugMu.Unlock()
		return e.srv.debugGen, e.srv.debugUntil
	}
	e.srv.debugFor = time.Hour
	on()
	first, until := period()
	on()
	if _, again := period(); again.Before(until) {
		t.Fatalf("the second period ends at %v, before the first (%v)", again, until)
	}
	e.srv.debugEnd(first) // the first period's timer, had it fired late
	if lv.Level() != slog.LevelDebug || ended() != 1 {
		t.Fatalf("the first period's timer ended the second: level %v, %d ends", lv.Level(), ended())
	}
	e.srv.debugFor = 30 * time.Millisecond
	on()
	wait("the last period does not end", func() bool { return lv.Level() == slog.LevelWarn && ended() == 2 })

	// off early: the late timer changes nothing
	e.srv.debugFor = time.Hour
	on()
	late, _ := period()
	e.do(t, "dora", "POST", "/admin/system/debug", url.Values{"on": {"0"}}, nil)
	lv.Set(slog.LevelInfo) // as if something else had set a level meanwhile
	e.srv.debugEnd(late)
	if lv.Level() != slog.LevelInfo || ended() != 2 {
		t.Fatalf("a timer fired after off: level %v, %d ends", lv.Level(), ended())
	}

	// a server that stops ends the period without an audit row
	lv.Set(slog.LevelWarn)
	on()
	late, _ = period()
	e.srv.Close()
	if lv.Level() != slog.LevelWarn {
		t.Fatalf("the level after the stop: %v", lv.Level())
	}
	e.srv.debugEnd(late)
	if ended() != 2 {
		t.Fatalf("the stop is audited as an end: %+v", debugRows(t, e))
	}
}

// The audit row is written without the switch's lock. With the database
// busy (another write holds it) the switch waits for its row, and yars
// status and Admin › System answer meanwhile: Status returns before the
// audit gave up.
func TestDebugAuditDoesNotHoldStatus(t *testing.T) {
	e, lv, out := debugEnv(t, slog.LevelWarn)
	// busy holds the database's write lock while change runs, asks for the
	// status once the level is want, and lets the audit row through after
	busy := func(what string, want slog.Level, level string, change func()) {
		t.Helper()
		tx, err := e.srv.Store.DB().Begin() // immediate: it holds the write lock
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { defer close(done); change() }()
		deadline := time.Now().Add(time.Minute)
		for lv.Level() != want {
			if time.Now().After(deadline) {
				tx.Rollback()
				t.Fatalf("%s: the level stays %v", what, lv.Level())
			}
			time.Sleep(time.Millisecond)
		}
		st := e.srv.Status()
		waited := strings.Contains(out.String(), "the debug switch is not audited")
		tx.Rollback()
		<-done
		if waited || st.Level != level {
			t.Fatalf("%s: the status waited for the audit row (level %q):\n%s", what, st.Level, out.String())
		}
	}
	busy("on", slog.LevelDebug, "debug", func() { e.srv.setDebug(true, "dora") })
	busy("off", slog.LevelWarn, "warn", func() { e.srv.setDebug(false, "dora") })
	e.srv.setDebug(true, "dora")
	e.srv.debugMu.Lock()
	gen := e.srv.debugGen
	e.srv.debugMu.Unlock()
	busy("the end", slog.LevelWarn, "warn", func() { e.srv.debugEnd(gen) })
	// each row came once the database was free
	rows := debugRows(t, e)
	if len(rows) != 4 || rows[0].Actor != "yars" || rows[0].Detail != "off · ended by itself" || rows[2].Detail != "off" {
		t.Fatalf("audit %+v", rows)
	}
}

// A server that started at debug stays at debug when the period ends.
func TestDebugKeepsTheStartLevel(t *testing.T) {
	e, lv, _ := debugEnv(t, slog.LevelDebug)
	e.srv.debugFor = 20 * time.Millisecond
	e.do(t, "dora", "POST", "/admin/system/debug", url.Values{"on": {"1"}}, nil)
	deadline := time.Now().Add(5 * time.Second)
	for len(debugRows(t, e)) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("the period does not end: %+v", debugRows(t, e))
		}
		time.Sleep(2 * time.Millisecond)
	}
	if lv.Level() != slog.LevelDebug {
		t.Fatalf("level %v", lv.Level())
	}
}

// A server whose log has no changeable level (none was handed in) shows the
// same row: the switch is there, off and disabled, the slot holds a dash.
func TestDebugRowWithoutALevel(t *testing.T) {
	e := setup(t)
	row := debugRow(t, e)
	if !strings.Contains(row, `role="switch" aria-checked="false"`) || !strings.Contains(row, " disabled") || !strings.Contains(row, offSlot) {
		t.Fatalf("the row:\n%s", row)
	}
	if rec := e.do(t, "dora", "POST", "/admin/system/debug", url.Values{"on": {"1"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST %d", rec.Code)
	}
	if len(debugRows(t, e)) != 0 || !strings.Contains(debugRow(t, e), offSlot) {
		t.Fatal("a switch without a level changed or audited something")
	}
}
