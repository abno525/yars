package logs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
)

// Request is what the log line of one request holds. The outermost handler
// makes it and puts it in the request's context; the layers the request
// passes (the mux, the login check, the git and MCP endpoints) fill in what
// only they know, and the line is written from it when the request ends.
// One request is one goroutine, so it has no lock. Every method works on a
// nil *Request (a handler mounted without the logging one, stdio MCP) and
// does nothing there.
type Request struct {
	// ID names the request in every line it causes (req) and in the
	// response's X-Request-ID header: 8 hex digits the server made.
	ID string
	// Route is the pattern the request matched, never its path: paths hold
	// IDs, which have their own fields, and text.
	Route string
	User  string // the account, once known
	Token int64  // the ID of the API token used (0 = none), never its value
	// Eng and Finding are IDs (the caller has checked their form).
	Eng, Finding string
	// Tool and Code are an MCP call's tool and the code of its answer.
	Tool, Code string
}

// SetRoute names the route unless an inner layer named it already.
func (r *Request) SetRoute(route string) {
	if r != nil && r.Route == "" {
		r.Route = route
	}
}

// SetUser names the account that asks.
func (r *Request) SetUser(name string) {
	if r != nil && name != "" {
		r.User = name
	}
}

// SetToken names the API token used, by its ID.
func (r *Request) SetToken(id int64) {
	if r != nil {
		r.Token = id
	}
}

// SetTarget names the engagement and the finding ("" leaves one as it is).
func (r *Request) SetTarget(eng, finding string) {
	if r == nil {
		return
	}
	if eng != "" {
		r.Eng = eng
	}
	if finding != "" {
		r.Finding = finding
	}
}

// SetTool names an MCP call's tool and the code of its answer.
func (r *Request) SetTool(tool, code string) {
	if r != nil {
		r.Tool, r.Code = tool, code
	}
}

// Attrs are the fields of the request known so far, in the log's names:
// req, then user, token, eng, finding, tool and code where set.
func (r *Request) Attrs() []slog.Attr {
	if r == nil {
		return nil
	}
	out := make([]slog.Attr, 0, 8)
	out = append(out, slog.String("req", r.ID))
	if r.User != "" {
		out = append(out, slog.String("user", r.User))
	}
	if r.Token != 0 {
		out = append(out, slog.Int64("token", r.Token))
	}
	if r.Eng != "" {
		out = append(out, slog.String("eng", r.Eng))
	}
	if r.Finding != "" {
		out = append(out, slog.String("finding", r.Finding))
	}
	if r.Tool != "" {
		out = append(out, slog.String("tool", r.Tool))
	}
	if r.Code != "" {
		out = append(out, slog.String("code", r.Code))
	}
	return out
}

type requestKey struct{}

// WithRequest is ctx carrying r.
func WithRequest(ctx context.Context, r *Request) context.Context {
	return context.WithValue(ctx, requestKey{}, r)
}

// RequestFrom is the request ctx carries, or nil.
func RequestFrom(ctx context.Context) *Request {
	r, _ := ctx.Value(requestKey{}).(*Request)
	return r
}

// ReqID is the ID of the request ctx carries ("" when it carries none).
func ReqID(ctx context.Context) string {
	if r := RequestFrom(ctx); r != nil {
		return r.ID
	}
	return ""
}

// HeaderID is the response header that carries a request's ID.
const HeaderID = "X-Request-ID"

// NewRequestID is a new request ID: 8 hex digits from crypto/rand. It is
// made by the server for every request and never read from one.
func NewRequestID() string {
	var b [4]byte
	rand.Read(b[:]) // never fails (crypto/rand)
	return hex.EncodeToString(b[:])
}
