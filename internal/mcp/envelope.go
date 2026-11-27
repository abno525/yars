package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

// Every tool's text is one JSON object (M32): {"ok":true, …} on success,
// {"ok":true,"items":[…],"next":"…"} for a list, and on a refusal (the MCP
// result has isError) {"ok":false,"code":"…","message":"…"}.

// ok renders a success object: {"ok":true, …fields}. fields must marshal
// to a JSON object (anything else is an error) without an "ok" key of its
// own; its keys keep their order.
func ok(fields any) (string, error) {
	b, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	if len(b) < 2 || b[0] != '{' {
		return "", errors.New("ok: not an object")
	}
	if string(b) == "{}" {
		return `{"ok":true}`, nil
	}
	return `{"ok":true,` + string(b[1:]), nil
}

// okMsg is a success with only a message: {"ok":true,"message":"…"}.
func okMsg(msg string) (string, error) {
	return ok(struct {
		Message string `json:"message"`
	}{msg})
}

// list renders a list: {"ok":true,"items":[…],"next":"<cursor or empty>"}.
func list[T any](items []T, next string) (string, error) {
	if items == nil {
		items = []T{}
	}
	return ok(struct {
		Items []T    `json:"items"`
		Next  string `json:"next"`
	}{items, next})
}

// Paging of the list tools: limit (default 50, at most 200) and cursor (the
// next of the previous answer: an offset, as text).
const (
	defaultLimit = 50
	maxLimit     = 200
)

var (
	pLimit  = param{"limit", "how many to return, 1 to 200 (default 50)"}
	pCursor = param{"cursor", "the next of the previous answer, to read on from there"}
)

// page cuts items to the caller's limit and cursor and returns the next
// cursor ("" at the end). A limit outside 1–200 or a cursor that is not a
// whole number from 0 is invalid; a cursor past the end gives an empty page.
func page[T any](a args, items []T) (out []T, next string, err error) {
	limit, off, err := pageArgs(a)
	if err != nil {
		return nil, "", err
	}
	if off >= len(items) {
		return []T{}, "", nil
	}
	end := min(off+limit, len(items))
	if end < len(items) {
		next = strconv.Itoa(end)
	}
	return items[off:end], next, nil
}

// pageArgs reads limit (1–200, default 50) and cursor (a whole number from
// 0, default 0); anything else is invalid.
func pageArgs(a args) (limit, cursor int, err error) {
	limit = defaultLimit
	if s := a.str("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxLimit {
			return 0, 0, refuse("invalid", fmt.Sprintf("limit must be a whole number from 1 to %d", maxLimit))
		}
		limit = n
	}
	if s := a.str("cursor"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return 0, 0, refuse("invalid", "cursor must be the next of an earlier answer (a whole number from 0)")
		}
		cursor = n
	}
	return limit, cursor, nil
}

// listPage renders the page of items a asks for.
func listPage[T any](a args, items []T) (string, error) {
	out, next, err := page(a, items)
	if err != nil {
		return "", err
	}
	return list(out, next)
}

// refusal is an error a tool or the gate made with its code.
type refusal struct{ code, msg string }

func (e refusal) Error() string { return e.msg }

// refuse is a refusal with code and words.
func refuse(code, msg string) error { return refusal{code, msg} }

// codeOf maps an error to its code: not_found, not_allowed, conflict,
// invalid, archived, busy, no_database, server_error.
func codeOf(err error) string {
	var r refusal
	var d *workflow.Denied
	switch {
	case errors.As(err, &r): // a tool's own (invalid: a missing argument, an unknown field)
		return r.code
	case errors.Is(err, store.ErrConflict): // a Denied that raced a change too
		return "conflict"
	case errors.As(err, &d):
		return "not_allowed"
	case errors.Is(err, store.ErrNotFound):
		return "not_found"
	case errors.Is(err, store.ErrArchived):
		return "archived"
	case errors.Is(err, store.ErrNoDB):
		return "no_database"
	case errors.Is(err, store.ErrBusy):
		return "busy"
	case errors.Is(err, store.ErrInvalidValue), errors.Is(err, store.ErrInvalidBody),
		errors.Is(err, store.ErrInvalidChat), errors.Is(err, errAmbiguous):
		return "invalid"
	}
	// the server's own failure (its disk, its database, a file of its own
	// that does not parse), never the caller's mistake
	return "server_error"
}

// internalError is what a caller is told of a failure of the server itself,
// as the website says it: the error's own words can hold a path of the
// server or a statement of its database, and go to the server's log only.
const internalError = "internal error"

// wording is the message a caller gets for err: what explain says, but for
// a server_error only internalError. A finding file that does not parse
// keeps its words (its folder and the parser's complaint about the file's
// own text): the caller needs them to repair it.
func wording(err error) string {
	var bad *store.UnreadableError
	if codeOf(err) == "server_error" && !errors.As(err, &bad) {
		return internalError
	}
	return explain(err)
}

// fail renders a refusal and its code from an error; the message is what
// wording says. For a finding file that does not parse the message names
// the folder, and the parser's complaint, which can quote the file's own
// text, is under "untrusted" as detail (untrusted.go).
func fail(err error) string {
	type theirs struct {
		Detail string `json:"detail"`
	}
	out := struct {
		OK      bool    `json:"ok"`
		Code    string  `json:"code"`
		Message string  `json:"message"`
		Theirs  *theirs `json:"untrusted,omitempty"`
	}{false, codeOf(err), wording(err), nil}
	var bad *store.UnreadableError
	if errors.As(err, &bad) && bad.Err != nil {
		out.Message = bad.Eng + "/" + bad.Dir + ": " + store.ErrUnreadable.Error()
		out.Theirs = &theirs{bad.Err.Error()}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// invalid is a refusal of the caller's argument or value (code invalid).
func invalid(format string, a ...any) error {
	return refuse("invalid", fmt.Sprintf(format, a...))
}
