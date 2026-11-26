package logs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// ringLog is a logger on a buffer (stderr) and a ring, as yars serve builds
// its own, with the output's level.
func ringLog(level slog.Level) (*slog.Logger, *bytes.Buffer, *Ring) {
	var buf bytes.Buffer
	ring := NewRing()
	return slog.New(HandlerRing(&buf, Text, level, ring)), &buf, ring
}

// The ring keeps the newest 200 warn and error lines: the oldest go first,
// and info and debug lines are never kept.
func TestRingKeepsTheLastWarnings(t *testing.T) {
	lg, _, ring := ringLog(slog.LevelDebug)
	lg.Debug("a debug line")
	lg.Info("an info line")
	if got := ring.Lines(); len(got) != 0 {
		t.Fatalf("the ring keeps info or debug: %+v", got)
	}
	for i := range RingLines + 1 {
		lg.Warn("a warning", "n", i)
	}
	lg.Error("an error", "err", errors.New("boom"))
	got := ring.Lines()
	if len(got) != RingLines {
		t.Fatalf("%d lines kept, want %d", len(got), RingLines)
	}
	if first, last := got[0], got[len(got)-1]; first.Text != `msg="a warning" n=2` || first.Level != slog.LevelWarn || first.Time.IsZero() ||
		last.Text != `msg="an error" err=boom` || last.Level != slog.LevelError {
		t.Fatalf("first %+v, last %+v", first, last)
	}
}

// The ring's level is its own: warnings are kept with the output at error
// (and are not written to stderr then), and debug on stderr adds nothing to
// the ring.
func TestRingLevelIsItsOwn(t *testing.T) {
	lg, out, ring := ringLog(slog.LevelError)
	lg.Warn("kept, not written")
	lg.Info("neither")
	if got := ring.Lines(); len(got) != 1 || got[0].Text != `msg="kept, not written"` {
		t.Fatalf("ring at output level error: %+v", got)
	}
	if out.Len() != 0 {
		t.Fatalf("stderr at error holds a warning: %s", out)
	}
	lg, out, ring = ringLog(slog.LevelDebug)
	lg.Debug("written, not kept")
	if !strings.Contains(out.String(), "written, not kept") || len(ring.Lines()) != 0 {
		t.Fatalf("debug: stderr %q, ring %+v", out, ring.Lines())
	}
	// a level that changes while the server runs (debug for 15 minutes)
	// changes stderr only
	var lv slog.LevelVar
	lv.Set(slog.LevelWarn)
	var buf bytes.Buffer
	ring = NewRing()
	lg = slog.New(HandlerRing(&buf, Text, &lv, ring))
	lv.Set(slog.LevelDebug)
	lg.Debug("d")
	lg.Info("i")
	if len(ring.Lines()) != 0 || !strings.Contains(buf.String(), "msg=d") {
		t.Fatalf("after the level changed: stderr %q, ring %+v", &buf, ring.Lines())
	}
}

// The setup code is written at a level above error, so that no log.level
// hides it: the ring does not keep it (the panel and yars status show the
// ring).
func TestRingLeavesOutTheSetupCode(t *testing.T) {
	lg, out, ring := ringLog(slog.LevelError)
	lg.Log(context.Background(), Always, "no accounts yet", "setup_code", "zqsetupcode7f3kq")
	if !strings.Contains(out.String(), "setup_code=zqsetupcode7f3kq") {
		t.Fatalf("stderr lacks the setup code: %q", out)
	}
	if got := ring.Lines(); len(got) != 0 {
		t.Fatalf("the ring keeps the setup code: %+v", got)
	}
}

// The ring is behind the same redaction as stderr: a private key is dropped
// and an error's text is cleaned, also for a logger made with With, which
// keeps its attributes in the ring's lines.
func TestRingIsRedacted(t *testing.T) {
	lg, _, ring := ringLog(slog.LevelInfo)
	lg.Warn("save failed", "password", "zqpassword7f3kq", "err", errors.New("open findings/F-001-zqslug7f3kq/finding.md: permission denied"))
	lg.With("eng", "acme", "token", "zqtoken7f3kq").WithGroup("g").Error("in a group", "n", 1, "title", "zqtitle7f3kq")
	got := ring.Lines()
	if len(got) != 2 {
		t.Fatalf("lines %+v", got)
	}
	if got[0].Text != `msg="save failed" err="open findings/F-001/finding.md: permission denied"` {
		t.Errorf("first line: %s", got[0].Text)
	}
	if got[1].Text != `msg="in a group" eng=acme g.n=1` {
		t.Errorf("second line: %s", got[1].Text)
	}
	for _, l := range got {
		if strings.Contains(l.Text, "zq") {
			t.Errorf("the ring holds private text: %s", l.Text)
		}
	}
}

// What the ring holds is bounded in bytes too: one line is cut (a panic's
// stack is up to 64 KiB), and many large lines push the oldest out before
// the count does.
func TestRingIsBoundedInBytes(t *testing.T) {
	lg, _, ring := ringLog(slog.LevelInfo)
	lg.Error("http server", "err", "panic", "stack", strings.Repeat("goroutine 1 [running]:\n", 3000))
	got := ring.Lines()
	if len(got) != 1 || len(got[0].Text) > ringLineMax+len("…") || !strings.HasSuffix(got[0].Text, "…") {
		t.Fatalf("a huge line: %d lines, %d bytes", len(got), len(got[0].Text))
	}
	for i := range RingLines {
		lg.Warn("large", "err", fmt.Sprint(i, strings.Repeat("x", 1000)), "more", strings.Repeat("y", 1000), "and", strings.Repeat("z", 1000))
	}
	got = ring.Lines()
	total := 0
	for _, l := range got {
		total += len(l.Text)
	}
	if total > ringBytesMax || len(got) >= RingLines || len(got) == 0 {
		t.Fatalf("%d lines of %d bytes together (most: %d)", len(got), total, ringBytesMax)
	}
	if last := got[len(got)-1].Text; !strings.Contains(last, fmt.Sprint("err=", RingLines-1, "xxx")) {
		t.Fatalf("the newest line is not the last: %.80s", last)
	}
	// a line is one line: a line break in a value is quoted
	lg, _, ring = ringLog(slog.LevelInfo)
	lg.Warn("login failed", "user", "x\nlevel=ERROR msg=forged\x1b[2J")
	if got := ring.Lines(); len(got) != 1 || strings.ContainsAny(got[0].Text, "\n\x1b") {
		t.Fatalf("a value with a line break: %+v", got)
	}
}

// Without a ring HandlerRing is Handler.
func TestHandlerRingWithoutARing(t *testing.T) {
	var buf bytes.Buffer
	lg := slog.New(HandlerRing(&buf, Text, slog.LevelInfo, nil))
	lg.Warn("w", "password", "x")
	if got := buf.String(); !strings.Contains(got, "level=WARN msg=w") || strings.Contains(got, "password") {
		t.Fatalf("log: %q", got)
	}
}
