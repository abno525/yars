package logs

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// Record is one log line a Recorder kept: its level, message and
// attributes by key (a group's as "group.key"), values resolved.
type Record struct {
	Level slog.Level
	Msg   string
	Attrs map[string]any
	line  string
}

// Str is the attribute key as text ("" when the record has none).
func (r Record) Str(key string) string {
	v, ok := r.Attrs[key]
	if !ok {
		return ""
	}
	return fmt.Sprint(v)
}

// Has reports whether the record has the attribute key.
func (r Record) Has(key string) bool { _, ok := r.Attrs[key]; return ok }

// String is the record as one line: LEVEL msg key=value …, keys in the
// order they were given.
func (r Record) String() string { return r.line }

// Recorder keeps every record of its logger, at every level, for a test to
// read: each test gives its server its own, as the server keeps no logger in
// a package variable.
type Recorder struct {
	mu   sync.Mutex
	recs []Record
}

// NewRecorder is a logger and the Recorder that keeps what it is given.
func NewRecorder() (*slog.Logger, *Recorder) {
	r := &Recorder{}
	return slog.New(&recHandler{to: r}), r
}

// Records are the records kept so far, oldest first.
func (r *Recorder) Records() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Record(nil), r.recs...)
}

// With are the records kept so far whose message is msg.
func (r *Recorder) With(msg string) []Record {
	var out []Record
	for _, x := range r.Records() {
		if x.Msg == msg {
			out = append(out, x)
		}
	}
	return out
}

// Text is every record kept so far, a line each.
func (r *Recorder) Text() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	for _, x := range r.recs {
		b.WriteString(x.line + "\n")
	}
	return b.String()
}

// Reset forgets the records kept so far.
func (r *Recorder) Reset() {
	r.mu.Lock()
	r.recs = nil
	r.mu.Unlock()
}

type recHandler struct {
	to     *Recorder
	attrs  []slog.Attr // of With, keys already prefixed
	prefix string      // of WithGroup: "g." or ""
}

func (h *recHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recHandler) Handle(_ context.Context, r slog.Record) error {
	out := Record{Level: r.Level, Msg: r.Message, Attrs: map[string]any{}}
	var b strings.Builder
	b.WriteString(r.Level.String() + " " + r.Message)
	add := func(a slog.Attr) {
		out.Attrs[a.Key] = a.Value.Any()
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Any())
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		for _, f := range flatten(h.prefix, a) {
			add(f)
		}
		return true
	})
	out.line = b.String()
	h.to.mu.Lock()
	h.to.recs = append(h.to.recs, out)
	h.to.mu.Unlock()
	return nil
}

func (h *recHandler) WithAttrs(as []slog.Attr) slog.Handler {
	n := &recHandler{to: h.to, prefix: h.prefix, attrs: h.attrs[:len(h.attrs):len(h.attrs)]}
	for _, a := range as {
		n.attrs = append(n.attrs, flatten(h.prefix, a)...)
	}
	return n
}

func (h *recHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &recHandler{to: h.to, prefix: h.prefix + name + ".", attrs: h.attrs}
}

// flatten is a with its value resolved, a group as its members with the
// group's name before each key.
func flatten(prefix string, a slog.Attr) []slog.Attr {
	v := a.Value.Resolve()
	if v.Kind() != slog.KindGroup {
		if a.Key == "" {
			return nil
		}
		return []slog.Attr{{Key: prefix + a.Key, Value: v}}
	}
	if a.Key != "" {
		prefix += a.Key + "."
	}
	var out []slog.Attr
	for _, m := range v.Group() {
		out = append(out, flatten(prefix, m)...)
	}
	return out
}
