package web

import (
	"bytes"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/abno525/yars/internal/logs"
)

// errPageView is an error answered as a page: the status, the handler's
// words, and on a server error the request's ID (as the log has it).
type errPageView struct {
	Title   string // the status text ("Not Found")
	Code    int
	Reason  string
	Request string // "" below 500
}

// errBodyMax is how much of a plain error body the page reads.
const errBodyMax = 4 << 10

// wantsPage tells a request a person's browser made for a page: it accepts
// HTML by name and is not htmx's. An htmx request shows an error's body in a
// toast, the page's own fetch calls read it, and a script, a download, an
// image and the event stream never ask for text/html: they all keep the
// plain text.
func wantsPage(r *http.Request) bool {
	if r.Header.Get("HX-Request") == "true" {
		return false
	}
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		if mt, _, err := mime.ParseMediaType(strings.TrimSpace(part)); err == nil && mt == "text/html" {
			return true
		}
	}
	return false
}

// errorPages draws a signed-in page request's plain-text error (http.Error,
// http.NotFound, the mux's own 404 and 405, Server.fail) in the layout, with
// the status it was answered with. The page is built with no engagement and
// holds nothing of the address, so an engagement that does not exist and one
// the account is not on are the same page, as they are the same text. When
// the page cannot be built the plain text goes out as it was.
func (s *Server) errorPages(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !wantsPage(r) {
			next.ServeHTTP(w, r)
			return
		}
		ew := &errWriter{ResponseWriter: w}
		next.ServeHTTP(ew, r)
		if !ew.held {
			return
		}
		text := strings.TrimSpace(ew.body.String())
		p, err := s.base(r, "")
		if err != nil {
			s.log().Error("the error page is not built", "req", w.Header().Get(logs.HeaderID), "err", err)
			w.WriteHeader(ew.code)
			w.Write(ew.body.Bytes())
			return
		}
		v := errPageView{Title: http.StatusText(ew.code), Code: ew.code}
		if v.Title == "" {
			v.Title = "Error"
		}
		// a server error's text ends with its request's line (internalError);
		// the page has a row for it
		id := w.Header().Get(logs.HeaderID)
		if ew.code >= 500 && id != "" {
			v.Request = id
			text = strings.TrimSpace(strings.TrimSuffix(text, "Request "+id))
		}
		// "404 page not found", "405 method not allowed": the number has its row
		v.Reason = strings.TrimSpace(strings.TrimPrefix(text, strconv.Itoa(ew.code)+" "))
		p.ErrPage, p.TabTitle = v, v.Title
		s.renderStatus(w, ew.code, "error.html", p)
	})
}

// errWriter holds back a plain-text answer of status 400 or more (its
// status and body), and passes every other answer through untouched.
type errWriter struct {
	http.ResponseWriter
	wrote bool // a status went out or is held
	held  bool
	code  int
	body  bytes.Buffer
}

func (w *errWriter) WriteHeader(code int) {
	if w.wrote {
		if !w.held {
			w.ResponseWriter.WriteHeader(code)
		}
		return
	}
	if code >= 100 && code < 200 {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.wrote = true
	h := w.Header()
	mt, _, _ := mime.ParseMediaType(h.Get("Content-Type"))
	if code >= 400 && mt == "text/plain" && h.Get("Content-Disposition") == "" {
		w.held, w.code = true, code
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *errWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.held {
		if room := errBodyMax - w.body.Len(); room > 0 {
			w.body.Write(b[:min(len(b), room)])
		}
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// Flush sends what is buffered (nothing while an error is held).
func (w *errWriter) Flush() {
	if !w.held {
		http.NewResponseController(w.ResponseWriter).Flush()
	}
}

// Unwrap lets http.ResponseController reach the connection (deadlines).
func (w *errWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
