package logs

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"unicode"
)

// Redact is h behind the rule of the service log: a line holds IDs and
// usernames, never text. It drops every attribute whose key names something
// private (secretKey), on a record, on a logger made with With, and inside a
// group; and it cleans the values it lets through (scrub): an error's text
// is free text that the code logging it did not write. Everything that
// keeps the server's lines is built behind one Redact (Handler).
func Redact(h slog.Handler) slog.Handler { return &redactor{h: h} }

type redactor struct {
	h slog.Handler
	// drop: the logger is inside a group whose name is a private key
	drop bool
}

func (r *redactor) Enabled(ctx context.Context, lv slog.Level) bool { return r.h.Enabled(ctx, lv) }

func (r *redactor) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, rec.Message, rec.PC)
	if !r.drop {
		rec.Attrs(func(a slog.Attr) bool {
			if c, ok := clean(a); ok {
				out.AddAttrs(c)
			}
			return true
		})
	}
	return r.h.Handle(ctx, out)
}

func (r *redactor) WithAttrs(as []slog.Attr) slog.Handler {
	if r.drop {
		return r
	}
	kept := make([]slog.Attr, 0, len(as))
	for _, a := range as {
		if c, ok := clean(a); ok {
			kept = append(kept, c)
		}
	}
	return &redactor{h: r.h.WithAttrs(kept)}
}

func (r *redactor) WithGroup(name string) slog.Handler {
	if name == "" {
		return r
	}
	return &redactor{h: r.h.WithGroup(name), drop: r.drop || secretKey(name)}
}

// clean is a as the log may hold it; ok is false when it may not. A group
// is cleaned member by member. Under a private key only a number passes
// (token is a token's ID; its value is a string). A string, an error and any
// other value that is not a number or a time is written as scrubbed text.
func clean(a slog.Attr) (slog.Attr, bool) {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		if a.Key != "" && secretKey(a.Key) {
			return slog.Attr{}, false
		}
		members := v.Group()
		kept := make([]slog.Attr, 0, len(members))
		for _, m := range members {
			if c, ok := clean(m); ok {
				kept = append(kept, c)
			}
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(kept...)}, true
	}
	switch v.Kind() {
	case slog.KindInt64, slog.KindUint64, slog.KindFloat64, slog.KindBool, slog.KindDuration, slog.KindTime:
		return slog.Attr{Key: a.Key, Value: v}, true
	}
	if secretKey(a.Key) {
		return slog.Attr{}, false
	}
	var s string
	switch x := v.Any().(type) {
	case nil:
		return slog.Attr{Key: a.Key, Value: v}, true
	case string:
		s = x
	case error:
		s = x.Error()
	default:
		s = fmt.Sprint(x)
	}
	if a.Key == stackKey {
		return slog.String(a.Key, scrubTo(s, stackMax)), true
	}
	return slog.String(a.Key, scrub(s)), true
}

// secretWords are the parts of a key that name something a line never
// holds: a password, the value of a token or a key, a header that carries
// one, and text people wrote (a title, a section, chat, a reason, a file's
// name, a prompt and its answer, a search).
var secretWords = map[string]bool{
	"password": true, "passwd": true, "pass": true, "pw": true, "token": true, "secret": true, "key": true, "apikey": true,
	"authorization": true, "auth": true, "cookie": true, "session": true, "bearer": true,
	"body": true, "text": true, "title": true, "reason": true, "chat": true, "comment": true, "content": true,
	"name": true, "filename": true, "label": true, "prompt": true, "answer": true, "query": true, "q": true, "email": true,
}

// secretInside are words that make a key private wherever they stand in it
// (newPassword, authtoken).
var secretInside = []string{"password", "passwd", "secret", "token", "apikey", "cookie", "authorization"}

// secretKey reports whether an attribute's key names something private: one
// of its parts (split at anything that is no letter or digit, and at a
// capital after a small letter) is a secret word, in any case, or the key
// holds one of the longer words anywhere. new_password, api-key, apiKey,
// Set-Cookie and authToken are; user, eng, finding, req, route, status, ms,
// err and setup_code are not.
func secretKey(key string) bool {
	low := strings.ToLower(key)
	for _, w := range secretInside {
		if strings.Contains(low, w) {
			return true
		}
	}
	start, prev := 0, rune(0)
	part := func(end int) bool { return end > start && secretWords[strings.ToLower(key[start:end])] }
	for i, c := range key {
		switch {
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			if part(i) {
				return true
			}
			start = i + len(string(c))
		case unicode.IsUpper(c) && unicode.IsLower(prev):
			if part(i) {
				return true
			}
			start = i
		}
		prev = c
	}
	return part(len(key))
}

// valueMax is the most of one value a line holds.
const valueMax = 1024

// stackMax is the most of a stack trace (the attribute stack) a line holds:
// what net/http keeps of a panicking handler's trace.
const stackMax = 64 << 10

// stackKey is the attribute that holds a stack trace: cleaned as any value,
// cut at stackMax.
const stackKey = "stack"

var (
	// a finding's folder is its ID and a slug of its title: F-001-sql-injection
	slugRe = regexp.MustCompile(`\bF-(\d{1,9})-[^/"'\s:]*`)
	// an attachment's file name
	attachRe = regexp.MustCompile(`\b(attachments/)[^/"'\n:]+`)
	// the query and the login of an address: either can carry a key
	urlRe = regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s"'?#@]*@)?([^\s"'?#]*)(?:[?#][^\s"']*)?`)
	// a value a parser quotes from the file it read (YAML: !!str `the text`)
	quotedRe = regexp.MustCompile("`[^`]*`")
)

// scrub is s without what an error's text can carry of a finding: a
// finding's folder becomes its ID (the folder's name holds the title), an
// attachment's file name is left out, an address loses its login, query and
// fragment, what a parser quotes between backticks goes, and the value is
// cut at valueMax bytes.
func scrub(s string) string { return scrubTo(s, valueMax) }

// scrubTo is scrub with the cut at max bytes.
func scrubTo(s string, max int) string {
	s = quotedRe.ReplaceAllString(s, "`-`")
	s = slugRe.ReplaceAllString(s, "F-$1")
	s = attachRe.ReplaceAllString(s, "${1}-")
	s = urlRe.ReplaceAllString(s, "$1$3")
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "") + "…"
	}
	return s
}
