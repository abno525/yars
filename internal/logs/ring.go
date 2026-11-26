package logs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// RingLines is how many lines a Ring keeps.
const RingLines = 200

const (
	// ringLineMax is the most of one line a Ring keeps (a panic's stack is
	// up to 64 KiB).
	ringLineMax = 4 << 10
	// ringBytesMax is the most a Ring keeps in all.
	ringBytesMax = 256 << 10
)

// Line is one line a Ring kept: when it was written, its level, and the
// rest as the text form writes it (msg=… key=value …, values quoted where
// they hold a space or a character that does not print).
type Line struct {
	Time  time.Time
	Level slog.Level
	Text  string
}

// Ring keeps the server's last warn and error lines in memory, for Admin ›
// System and yars status: at most RingLines of them and ringBytesMax bytes,
// the oldest dropped first. It is lost at a restart (the journal has the
// rest). It belongs to one server: yars serve makes it and hands it on.
type Ring struct {
	mu    sync.Mutex
	lines []Line
	bytes int          // of the lines' text
	buf   bytes.Buffer // the line being written, under mu
}

// NewRing is an empty ring.
func NewRing() *Ring { return &Ring{} }

// Lines are the lines kept, oldest first.
func (r *Ring) Lines() []Line {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Line(nil), r.lines...)
}

// handler writes the records it is given into the ring.
func (r *Ring) handler() slog.Handler {
	// the line's time and level are kept beside its text
	opts := &slog.HandlerOptions{Level: slog.LevelWarn, ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && (a.Key == slog.TimeKey || a.Key == slog.LevelKey) {
			return slog.Attr{}
		}
		return a
	}}
	return &ringHandler{ring: r, h: slog.NewTextHandler(&r.buf, opts)}
}

// ringHandler keeps warn and error records in its ring. A line above error
// is not kept: the setup code of a first start is written there (Always),
// and the ring is shown on a page.
type ringHandler struct {
	ring *Ring
	h    slog.Handler // a text handler on ring.buf
}

func (h *ringHandler) Enabled(_ context.Context, lv slog.Level) bool {
	return lv >= slog.LevelWarn && lv <= slog.LevelError
}

func (h *ringHandler) Handle(ctx context.Context, rec slog.Record) error {
	if !h.Enabled(ctx, rec.Level) {
		return nil
	}
	r := h.ring
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf.Reset()
	if err := h.h.Handle(ctx, rec); err != nil {
		return err
	}
	text := strings.TrimRight(r.buf.String(), "\n")
	if len(text) > ringLineMax {
		text = strings.ToValidUTF8(text[:ringLineMax], "") + "…"
	}
	r.buf.Reset()
	r.lines = append(r.lines, Line{Time: rec.Time, Level: rec.Level, Text: text})
	r.bytes += len(text)
	drop := 0
	for len(r.lines)-drop > RingLines || (r.bytes > ringBytesMax && len(r.lines)-drop > 1) {
		r.bytes -= len(r.lines[drop].Text)
		drop++
	}
	if drop > 0 {
		// a new slice: the dropped lines' text is let go
		r.lines = append([]Line(nil), r.lines[drop:]...)
	}
	return nil
}

func (h *ringHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &ringHandler{ring: h.ring, h: h.h.WithAttrs(as)}
}

func (h *ringHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &ringHandler{ring: h.ring, h: h.h.WithGroup(name)}
}

// fanout gives each record to every handler that wants its level: the
// stream on stderr has log.level, the ring its own.
type fanout []slog.Handler

func (f fanout) Enabled(ctx context.Context, lv slog.Level) bool {
	for _, h := range f {
		if h.Enabled(ctx, lv) {
			return true
		}
	}
	return false
}

func (f fanout) Handle(ctx context.Context, rec slog.Record) error {
	var errs []error
	for _, h := range f {
		if h.Enabled(ctx, rec.Level) {
			if err := h.Handle(ctx, rec.Clone()); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (f fanout) WithAttrs(as []slog.Attr) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithAttrs(as)
	}
	return out
}

func (f fanout) WithGroup(name string) slog.Handler {
	if name == "" {
		return f
	}
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithGroup(name)
	}
	return out
}

// HandlerRing is Handler with ring (when not nil) keeping the warn and
// error lines too, whatever level is: both are behind the one Redact, so the
// ring holds what stderr may hold and no more.
func HandlerRing(w io.Writer, format string, level slog.Leveler, ring *Ring) slog.Handler {
	if ring == nil {
		return Handler(w, format, level)
	}
	return Redact(fanout{output(w, format, level), ring.handler()})
}
