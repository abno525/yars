package mcp

import (
	"encoding/json"
	"errors"

	"yars/internal/store"
	"yars/internal/workflow"
)

// Every tool's text is one JSON object (M32): {"ok":true, …} on success,
// {"ok":true,"items":[…],"next":"…"} for a list, and on a refusal (the MCP
// result has isError) {"ok":false,"code":"…","message":"…"}.

// ok renders a success object: {"ok":true, …fields}. fields must marshal
// to a JSON object; its keys keep their order.
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

// refusal is an error a tool or the gate made with its code.
type refusal struct{ code, msg string }

func (e refusal) Error() string { return e.msg }

// refuse is a refusal with code and words.
func refuse(code, msg string) error { return refusal{code, msg} }

// codeOf maps an error to its code: not_found, not_allowed, conflict,
// invalid, archived, busy, no_database.
func codeOf(err error) string {
	var r refusal
	var d *workflow.Denied
	switch {
	case errors.As(err, &r):
		return r.code
	case errors.As(err, &d):
		return "not_allowed"
	case errors.Is(err, store.ErrConflict):
		return "conflict"
	case errors.Is(err, store.ErrNotFound):
		return "not_found"
	case errors.Is(err, store.ErrArchived):
		return "archived"
	case errors.Is(err, store.ErrNoDB):
		return "no_database"
	case errors.Is(err, store.ErrBusy):
		return "busy"
	}
	// ErrInvalidValue, ErrInvalidBody, ErrInvalidChat and a tool's own
	// (a missing argument, an unknown field)
	return "invalid"
}

// fail renders a refusal and its code from an error; the message is what
// explain says.
func fail(err error) string {
	b, _ := json.Marshal(struct {
		OK      bool   `json:"ok"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}{false, codeOf(err), explain(err)})
	return string(b)
}
