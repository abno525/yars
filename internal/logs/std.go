package logs

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
)

// StdHandler makes the lines of a library that writes free text through the
// standard logger (net/http's ErrorLog, net/http/cgi) lines of l: each
// becomes one record with the constant message msg and the library's text
// in err. Use it as slog.NewLogLogger(logs.StdHandler(l, msg), level).
func StdHandler(l *slog.Logger, msg string) slog.Handler { return stdHandler{Or(l), msg} }

type stdHandler struct {
	to  *slog.Logger
	msg string
}

func (h stdHandler) Enabled(ctx context.Context, lv slog.Level) bool { return h.to.Enabled(ctx, lv) }
func (h stdHandler) Handle(ctx context.Context, r slog.Record) error {
	h.to.LogAttrs(ctx, r.Level, h.msg, slog.String("err", strings.TrimSpace(r.Message)))
	return nil
}
func (h stdHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h stdHandler) WithGroup(string) slog.Handler      { return h }

// LineWriter is a writer whose every line becomes one record of l at level,
// with the constant message msg and the line in err (the stderr of a child
// process). Flush writes a last line that had no line break.
type LineWriter struct {
	to    *slog.Logger
	level slog.Level
	msg   string
	attrs []slog.Attr

	mu  sync.Mutex
	buf []byte
}

// NewLineWriter is a LineWriter on l; attrs go on every record.
func NewLineWriter(l *slog.Logger, level slog.Level, msg string, attrs ...slog.Attr) *LineWriter {
	return &LineWriter{to: Or(l), level: level, msg: msg, attrs: attrs}
}

// lineMax is the most of one line a LineWriter keeps before it writes it.
const lineMax = 8 << 10

func (w *LineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 && len(w.buf) < lineMax {
			break
		}
		if i < 0 {
			i = len(w.buf) - 1
		}
		w.line(w.buf[:i])
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}

// Flush writes what is left of a line.
func (w *LineWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.line(w.buf)
	w.buf = nil
}

func (w *LineWriter) line(b []byte) {
	if s := strings.TrimSpace(string(b)); s != "" {
		w.to.LogAttrs(context.Background(), w.level, w.msg, append(w.attrs[:len(w.attrs):len(w.attrs)], slog.String("err", s))...)
	}
}
