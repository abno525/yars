package web

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"yars/internal/auth"
	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/events"
)

// --- gzip ---

func TestGzipPages(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "GET", "/e/acme", nil, map[string]string{"Accept-Encoding": "gzip, br"})
	if rec.Header().Get("Content-Encoding") != "gzip" || !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("not gzipped: %v", rec.Header())
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(zr)
	if !strings.Contains(string(b), "F-001") {
		t.Fatalf("body:\n%s", b)
	}
	// no Accept-Encoding: plain
	if rec := e.do(t, "alice", "GET", "/e/acme", nil, nil); rec.Header().Get("Content-Encoding") != "" || !strings.Contains(rec.Body.String(), "F-001") {
		t.Fatal("gzipped without Accept-Encoding")
	}
	// HEAD is never compressed
	if rec := e.do(t, "alice", "HEAD", "/e/acme", nil, map[string]string{"Accept-Encoding": "gzip"}); rec.Header().Get("Content-Encoding") != "" {
		t.Fatal("HEAD gzipped")
	}
}

func TestGzipSkips(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"stream": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: x\n\n")
		},
		"download": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", `attachment; filename="x.json"`)
			io.WriteString(w, `{"a":1}`)
		},
		"encoded": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Encoding", "br")
			io.WriteString(w, "xx")
		},
		"binary": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			io.WriteString(w, "png")
		},
		"empty": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNoContent)
		},
		// gzip would make these bigger (36 B -> 61 B)
		"small": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		},
		"small-status": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
		},
		"small-length": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Length", "12")
			io.WriteString(w, "<p>small</p>")
		},
	}
	for name, h := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		gzipHandler(h).ServeHTTP(rec, req)
		if ce := rec.Header().Get("Content-Encoding"); ce == "gzip" {
			t.Errorf("%s: compressed", name)
		}
	}
	// JSON of a useful size is compressed, with or without a length, and
	// the status stays
	big := `{"a":"` + strings.Repeat("x", 2000) + `"}`
	for _, withLen := range []bool{true, false} {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		gzipHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if withLen {
				w.Header().Set("Content-Length", strconv.Itoa(len(big)))
			}
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, big)
		})).ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated || rec.Header().Get("Content-Encoding") != "gzip" || rec.Header().Get("Content-Length") != "" {
			t.Fatalf("json (length %v): %d %v", withLen, rec.Code, rec.Header())
		}
	}
	// a status without a body still goes out
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	gzipHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusSeeOther)
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("bodiless status %d", rec.Code)
	}
}

// --- static files ---

func TestStaticHashedImmutable(t *testing.T) {
	e := setup(t)
	page := e.do(t, "alice", "GET", "/", nil, nil).Body.String()
	m := regexp.MustCompile(`href="/static/([0-9a-f]{12})/style\.css"`).FindStringSubmatch(page)
	if m == nil || m[1] != staticHash {
		t.Fatalf("no hashed stylesheet link:\n%s", page)
	}
	for _, f := range []string{"htmx.min.js", "app.js", "sse.js"} {
		if !strings.Contains(page, `src="/static/`+staticHash+`/`+f+`"`) {
			t.Fatalf("no hashed %s", f)
		}
	}
	rec := e.do(t, "", "GET", "/static/"+staticHash+"/style.css", nil, nil)
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || !strings.Contains(rec.Body.String(), ":root") {
		t.Fatalf("code %d cc %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	// unhashed (old links) still work, but are revalidated
	rec = e.do(t, "", "GET", "/static/style.css", nil, nil)
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("plain: code %d cc %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	// a stale hash (page from before a deploy) gets today's file, not cached for long
	rec = e.do(t, "", "GET", "/static/000000000000/app.js", nil, nil)
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("stale: code %d cc %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	if rec := e.do(t, "", "GET", "/static/"+staticHash+"/nope.js", nil, nil); rec.Code != 404 || strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("missing file: code %d cc %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
}

func TestHTTPServerTimeouts(t *testing.T) {
	e := setup(t)
	hs := e.srv.HTTPServer(":0")
	if hs.ReadHeaderTimeout != 10*time.Second || hs.ReadTimeout != 60*time.Second || hs.WriteTimeout != 60*time.Second || hs.IdleTimeout != 120*time.Second {
		t.Fatalf("timeouts %+v", hs)
	}
	if hs.Handler == nil {
		t.Fatal("no handler")
	}
}

// --- server-sent events ---

// liveServer is a real HTTP server for the handler. Its Close is registered
// before any stream's, so streams close first (Close waits for handlers).
func (e *env) liveServer(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(e.h)
	t.Cleanup(ts.Close)
	return ts
}

type sseStream struct {
	lines chan string
	resp  *http.Response
}

func (e *env) openSSE(t *testing.T, ts *httptest.Server, query string, hdr map[string]string) *sseStream {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+"/events?"+query, nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks["alice"]})
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" || resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("code %d headers %v", resp.StatusCode, resp.Header)
	}
	s := &sseStream{lines: make(chan string, 4096), resp: resp}
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			s.lines <- sc.Text()
		}
		close(s.lines)
	}()
	return s
}

// waitFor reads lines until one has the prefix; it returns that line.
func (s *sseStream) waitFor(t *testing.T, prefix string) string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case l, ok := <-s.lines:
			if !ok {
				t.Fatalf("stream ended before %q", prefix)
			}
			if strings.HasPrefix(l, prefix) {
				return l
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q", prefix)
		}
	}
}

// A server that stops ends its open event streams (the pages reconnect to
// the next one); http.Server.Shutdown does not wait for them.
func TestSSEEndsOnClose(t *testing.T) {
	e := setup(t)
	ts := e.liveServer(t)
	s := e.openSSE(t, ts, "eng=acme", nil)
	s.waitFor(t, "id: ")
	e.srv.Close()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-s.lines:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("the stream is still open after Close")
		}
	}
}

func TestSSEChatEvent(t *testing.T) {
	e := setup(t)
	ts := e.liveServer(t)
	s := e.openSSE(t, ts, "eng=acme&f=F-001", map[string]string{"Accept-Encoding": "gzip"})
	s.waitFor(t, "id: ") // the stream's starting id: subscribed
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"live?"}}, nil)
	s.waitFor(t, "event: chat")
	if l := s.waitFor(t, "data: "); !strings.Contains(l, `"f":"F-001"`) {
		t.Fatalf("data %q", l)
	}
	// a workflow change arrives as its own event
	if err := e.srv.Store.SetReviewers("acme", fdir, []string{"bob"}, wAlice); err != nil {
		t.Fatal(err)
	}
	s.waitFor(t, "event: workflow")
}

func TestSSEFilteredAndContent(t *testing.T) {
	e := setup(t)
	if _, err := e.srv.Store.CreateFinding("acme", "XSS", e.authorOf(config.User{Username: "alice"})); err != nil {
		t.Fatal(err)
	}
	ts := e.liveServer(t)
	s := e.openSSE(t, ts, "eng=acme&f=F-001", nil)
	s.waitFor(t, "id: ")
	// another finding's chat is not sent to this page
	e.do(t, "bob", "POST", "/e/acme/f/002/chat", url.Values{"text": {"other"}}, nil)
	e.do(t, "alice", "POST", fpath+"/s/Impact", url.Values{"body": {"Bad."}}, nil)
	l := s.waitFor(t, "event: ")
	if l != "event: content" {
		t.Fatalf("first event %q, want content (other finding's chat filtered out)", l)
	}
}

func TestSSEPushAndHeartbeat(t *testing.T) {
	e := setup(t)
	e.srv.heartbeat = 50 * time.Millisecond
	ts := e.liveServer(t)
	s := e.openSSE(t, ts, "eng=acme&f=F-001", nil)
	s.waitFor(t, ": ping")
	e.srv.Events.Publish(events.Event{Eng: "acme", Kind: events.Push})
	s.waitFor(t, "event: push")
}

func TestSSEResyncOnLastEventID(t *testing.T) {
	e := setup(t)
	ts := e.liveServer(t)
	before := e.srv.Events.Last()
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"while away"}}, nil)
	s := e.openSSE(t, ts, "eng=acme&f=F-001", map[string]string{"Last-Event-ID": fmt.Sprint(before)})
	s.waitFor(t, "event: resync")
	// up to date: no resync
	s2 := e.openSSE(t, ts, "eng=acme&f=F-001", map[string]string{"Last-Event-ID": fmt.Sprint(e.srv.Events.Last())})
	l := s2.waitFor(t, "")
	for l == "" || strings.HasPrefix(l, "retry:") {
		l = s2.waitFor(t, "")
	}
	if !strings.HasPrefix(l, "id: ") {
		t.Fatalf("first line %q, want only the id", l)
	}
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"now"}}, nil)
	if l := s2.waitFor(t, "event: "); l != "event: chat" {
		t.Fatalf("got %q", l)
	}
}

func TestSSEBadParams(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "alice", "GET", "/events?eng=../x", nil, nil); rec.Code != 400 {
		t.Fatalf("code %d", rec.Code)
	}
	if rec := e.do(t, "", "GET", "/events?eng=acme", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated code %d", rec.Code)
	}
}

// The finding page listens for events instead of polling every 5 s.
func TestFindingPageLive(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if strings.Contains(b, "every 5s") {
		t.Fatal("still polling every 5 s")
	}
	if !strings.Contains(b, `data-sse-url="/events?eng=acme&amp;f=F-001"`) {
		t.Fatalf("no event stream url:\n%s", b)
	}
	list := b[strings.Index(b, `id="chat-list"`):]
	list = list[:strings.Index(list, ">")]
	if !strings.Contains(list, "sse:chat") || !strings.Contains(list, "sse:poll") || !strings.Contains(list, "data-sse") {
		t.Fatalf("chat list triggers: %s", list)
	}
	wf := b[strings.Index(b, `id="workflow"`):]
	wf = wf[:strings.Index(wf, ">")]
	if !strings.Contains(wf, "sse:workflow") || !strings.Contains(wf, `hx-get="/e/acme/f/001/workflow"`) || !strings.Contains(wf, "data-sse") {
		t.Fatalf("workflow bar triggers: %s", wf)
	}
	// the bar can be fetched on its own
	rec := e.do(t, "alice", "GET", "/e/acme/f/001/workflow", nil, nil)
	if rec.Code != 200 || !strings.HasPrefix(strings.TrimSpace(rec.Body.String()), `<section class="wf" id="workflow"`) {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
	js := e.do(t, "alice", "GET", "/static/sse.js", nil, nil).Body.String()
	for _, want := range []string{"EventSource", "htmx.trigger", "sse:", "document.hidden", "30000"} {
		if !strings.Contains(js, want) {
			t.Fatalf("sse.js lacks %q", want)
		}
	}
}

// Browsers allow 6 HTTP/1.1 connections per host: a stream held open by
// every background tab would stall the whole app once a few finding tabs are
// open. sse.js closes the stream while the tab is hidden and, when it comes
// back, reconnects and catches up (resync).
func TestSSEClosedInHiddenTabs(t *testing.T) {
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/sse.js", nil, nil).Body.String()
	i := strings.Index(js, "function onVisibility")
	if i < 0 {
		t.Fatal("sse.js has no onVisibility handler")
	}
	body := js[i:]
	body = body[:strings.Index(body, "\n  }\n")]
	for _, want := range []string{"document.hidden", "disconnect()", "connect(", "fire('resync')"} {
		if !strings.Contains(body, want) {
			t.Fatalf("onVisibility lacks %q:\n%s", want, body)
		}
	}
	if !strings.Contains(js, "function disconnect() {\n    if (es) { es.close();") {
		t.Fatal("disconnect does not close the stream")
	}
	if !strings.Contains(js, "addEventListener('visibilitychange', onVisibility)") {
		t.Fatal("onVisibility not registered")
	}
}

// --- chat poll ---

func TestChatPollShortCircuit(t *testing.T) {
	e := setup(t)
	e.do(t, "alice", "POST", fpath+"/chat", url.Values{"text": {"first"}}, nil)
	b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	m := regexp.MustCompile(`id="chat-list" hx-get="([^"]+)"`).FindStringSubmatch(b)
	if m == nil {
		t.Fatalf("no list url:\n%s", b)
	}
	list := strings.ReplaceAll(m[1], "&amp;", "&")
	loads := e.srv.chatLoads.Load()
	if rec := e.do(t, "bob", "GET", list, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("unchanged poll code %d", rec.Code)
	}
	if n := e.srv.chatLoads.Load(); n != loads {
		t.Fatalf("unchanged poll loaded the chat (%d loads)", n-loads)
	}
	e.do(t, "alice", "POST", fpath+"/chat", url.Values{"text": {"second"}}, nil)
	rec := e.do(t, "bob", "GET", list, nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "second") {
		t.Fatalf("changed poll code %d", rec.Code)
	}
	// a workflow event changes the stamp too (it shows in the status box)
	m = regexp.MustCompile(`id="chat-list" hx-get="([^"]+)"`).FindStringSubmatch(rec.Body.String())
	list = strings.ReplaceAll(m[1], "&amp;", "&")
	e.toVerification(t)
	if rec := e.do(t, "bob", "GET", list, nil, nil); rec.Code != 200 {
		t.Fatalf("after submit: code %d", rec.Code)
	}
}

// Long threads show the newest 50 messages; older ones load on request.
func TestChatShowsLast50(t *testing.T) {
	e := setup(t)
	bob := config.User{Username: "bob", Role: "reviewer"}
	for i := range 55 {
		if _, err := e.srv.Store.PostChat("acme", fdir, chat.Message{Text: fmt.Sprintf("m%02d", i)}, bob); err != nil {
			t.Fatal(err)
		}
	}
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if strings.Contains(b, "<p>m04</p>") || !strings.Contains(b, "<p>m05</p>") || !strings.Contains(b, "<p>m54</p>") {
		t.Fatal("want m05..m54 only")
	}
	m := regexp.MustCompile(`hx-get="([^"]+)"[^>]*>Show older`).FindStringSubmatch(b)
	if m == nil {
		t.Fatalf("no show-older control:\n%s", b[strings.Index(b, `id="chat-list"`):])
	}
	all := e.do(t, "alice", "GET", strings.ReplaceAll(m[1], "&amp;", "&"), nil, nil).Body.String()
	if !strings.Contains(all, "<p>m00</p>") || strings.Contains(all, "Show older") {
		t.Fatal("older messages not loaded")
	}
	// refreshes of the full list keep it full
	if !regexp.MustCompile(`id="chat-list" hx-get="[^"]*all=1`).MatchString(all) {
		t.Fatal("full list refreshes lose all=1")
	}
}

// --- board pagination ---

func TestBoardPagination(t *testing.T) {
	if boardPage != 200 {
		t.Fatalf("page size %d, want 200", boardPage)
	}
	e := setup(t)
	a := e.authorOf(config.User{Username: "alice"})
	for _, title := range []string{"B", "C", "D", "E"} {
		if _, err := e.srv.Store.CreateFinding("acme", title, a); err != nil {
			t.Fatal(err)
		}
	}
	e.srv.pageSize = 2
	rows := regexp.MustCompile(`<td class="fid">`)
	b := e.do(t, "alice", "GET", "/e/acme?sort=title", nil, nil).Body.String()
	if n := len(rows.FindAllString(b, -1)); n != 2 {
		t.Fatalf("%d rows, want 2", n)
	}
	m := regexp.MustCompile(`<button type="button" class="btn secondary w152" hx-get="([^"]+)"[^>]*>Load 2 more</button>`).FindStringSubmatch(b)
	if m == nil {
		t.Fatalf("no load-more button:\n%s", b)
	}
	more := strings.ReplaceAll(m[1], "&amp;", "&")
	if !strings.Contains(more, "offset=2") || !strings.Contains(more, "sort=title") {
		t.Fatalf("more url %q", more)
	}
	p2 := e.do(t, "alice", "GET", more, nil, map[string]string{"HX-Request": "true"}).Body.String()
	if strings.Contains(p2, "<table") || len(rows.FindAllString(p2, -1)) != 2 || !strings.Contains(p2, "offset=4") {
		t.Fatalf("page 2:\n%s", p2)
	}
	p3 := e.do(t, "alice", "GET", "/e/acme?sort=title&offset=4", nil, map[string]string{"HX-Request": "true"}).Body.String()
	if len(rows.FindAllString(p3, -1)) != 1 || strings.Contains(p3, "more</button>") || strings.Contains(p3, "No findings match") {
		t.Fatalf("last page:\n%s", p3)
	}
	// filter links never carry the offset
	if strings.Contains(e.do(t, "alice", "GET", "/e/acme?offset=2", nil, nil).Body.String(), "status=draft&amp;offset") {
		t.Fatal("filter link keeps offset")
	}
}

// --- markdown cache ---

func TestMarkdownCached(t *testing.T) {
	e := setup(t)
	e.do(t, "alice", "POST", fpath+"/s/Impact", url.Values{"body": {"**Bad.**"}}, nil)
	e.do(t, "alice", "GET", fpath, nil, nil)
	miss := e.srv.md.Misses()
	e.do(t, "bob", "GET", fpath, nil, nil)
	if e.srv.md.Misses() != miss {
		t.Fatalf("second view re-rendered markdown (%d new)", e.srv.md.Misses()-miss)
	}
	pv := func() string {
		return e.do(t, "alice", "POST", "/e/acme/preview", url.Values{"body": {"_draft_"}}, nil).Body.String()
	}
	if b := pv(); !strings.Contains(b, "<em>draft</em>") {
		t.Fatalf("preview:\n%s", b)
	}
	miss = e.srv.md.Misses()
	if pv(); e.srv.md.Misses() != miss {
		t.Fatal("preview did not use the cache")
	}
}
