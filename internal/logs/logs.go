// Package logs builds the service log of yars serve: one log/slog logger on
// stderr, made at the start and handed to every part of the server. No part
// keeps a logger in a package variable; a part that was given none writes
// nothing (Or).
package logs

import (
	"io"
	"log/slog"
)

// The values log.format takes in config.yaml ("" is Text).
const (
	Text = "text"
	JSON = "json"
)

// Or is l, or a logger that writes nothing when l is nil: a part built
// without a logger (a test, a command at the terminal) stays silent.
func Or(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.New(slog.DiscardHandler)
	}
	return l
}

// ParseLevel is the level a log.level value (or --log-level) names: debug,
// info, warn or error, in lower case. "" is info. ok is false for any other
// word.
func ParseLevel(s string) (level slog.Level, ok bool) {
	switch s {
	case "debug":
		return slog.LevelDebug, true
	case "", "info":
		return slog.LevelInfo, true
	case "warn":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	}
	return slog.LevelInfo, false
}

// ValidFormat reports whether s is a log.format value: text, json or "".
func ValidFormat(s string) bool { return s == "" || s == Text || s == JSON }

// Handler is the service log's handler chain on w: lines as text (time level
// msg key=value …) or, with format json, one JSON object a line, from level
// up. level is read on every line, so a slog.LevelVar changes it while the
// server runs. Everything that reads the server's records (the stream on
// stderr, and the ring in memory of HandlerRing) is built behind one Redact:
// no line holds a password, a token's value or text.
func Handler(w io.Writer, format string, level slog.Leveler) slog.Handler {
	return Redact(output(w, format, level))
}

// output writes records to w as they are given.
func output(w io.Writer, format string, level slog.Leveler) slog.Handler {
	opts := &slog.HandlerOptions{Level: level, ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		// an Always line reads as the info line it is
		if lv, ok := a.Value.Any().(slog.Level); ok && a.Key == slog.LevelKey && len(groups) == 0 && lv == Always {
			a.Value = slog.StringValue(slog.LevelInfo.String())
		}
		return a
	}}
	if format == JSON {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// New is a logger on Handler(w, format, level).
func New(w io.Writer, format string, level slog.Leveler) *slog.Logger {
	return slog.New(Handler(w, format, level))
}

// Always is the level of a line no log.level hides (the setup code of a
// first start): above error, and written as INFO.
const Always = slog.LevelError + 4
