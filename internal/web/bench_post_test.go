package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/gitrepo"
)

// deadlineRecorder is a response that records each write deadline set on
// it, as a real connection takes them.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

// The rules bench runs scripts and AI rules, so it is a POST: a link an
// admin opens (a GET), a form on another site and a POST that carries its
// values in the address run nothing. A run lifts the server's 60 s write
// deadline to one lint run, and Run on engagement again before each finding
// (pre1 2.27).
func TestRuleBenchIsAPost(t *testing.T) {
	e := setupSerial(t)
	ran := filepath.Join(t.TempDir(), "ran")
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo run >> " + ran + "; echo '[]'\n"})
	if _, err := e.srv.Store.CreateFinding("acme", "Missing HSTS header", gitrepo.Author{Name: "alice"}); err != nil {
		t.Fatal(err)
	}
	runs := func() int {
		b, _ := os.ReadFile(ran)
		return strings.Count(string(b), "run")
	}
	form := url.Values{"rule": {"scripted"}, "eng": {"acme"}, "fid": {fdir}}
	query := "?" + form.Encode()

	// a link: nothing runs
	if rec := e.do(t, "dora", "GET", "/admin/rules/bench"+query, nil, nil); rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Errorf("GET: %d", rec.Code)
	}
	if rec := e.do(t, "dora", "GET", "/admin/rules/bench"+query+"&all=1", nil, nil); rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Errorf("GET all: %d", rec.Code)
	}
	// a form on another site
	if rec := e.do(t, "dora", "POST", "/admin/rules/bench", form, map[string]string{"Sec-Fetch-Site": "cross-site"}); rec.Code != http.StatusForbidden {
		t.Errorf("a cross-site POST: %d", rec.Code)
	}
	// the values are the form's, not the address's
	if rec := e.do(t, "dora", "POST", "/admin/rules/bench"+query, url.Values{}, nil); rec.Code != http.StatusNotFound {
		t.Errorf("a POST with its values in the address: %d", rec.Code)
	}
	// not an admin
	if rec := e.do(t, "alice", "POST", "/admin/rules/bench", form, nil); rec.Code != http.StatusForbidden {
		t.Errorf("alice: %d", rec.Code)
	}
	if n := runs(); n != 0 {
		t.Fatalf("the script ran %d times for requests that run nothing", n)
	}

	// the page's form posts, with htmx and without
	page := e.do(t, "dora", "GET", "/admin/rules", nil, nil).Body.String()
	tag := between(page, `<form class="benchform"`, ">")
	if !strings.Contains(tag, ` method="post"`) || !strings.Contains(tag, ` hx-post="/admin/rules/bench"`) || strings.Contains(tag, "hx-get") {
		t.Errorf("the bench form: %s", tag)
	}

	post := func(v url.Values) *deadlineRecorder {
		t.Helper()
		req := httptest.NewRequest("POST", "/admin/rules/bench", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks["dora"]})
		rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		e.h.ServeHTTP(rec, req)
		return rec
	}
	long := func(d time.Time) bool { return time.Until(d) > 100*time.Second } // past the server's 60 s
	rec := post(form)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `id="bench-out"`) || runs() != 1 {
		t.Fatalf("Try: %d, %d runs\n%s", rec.Code, runs(), rec.Body.String())
	}
	if len(rec.deadlines) != 1 || !long(rec.deadlines[0]) {
		t.Errorf("Try: write deadlines %v", rec.deadlines)
	}
	all := url.Values{"rule": {"scripted"}, "eng": {"acme"}, "fid": {fdir}, "all": {"1"}}
	rec = post(all)
	// the first finding's result is kept from the Try: the script runs once more
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "0 hits in 0 of 2 findings") || runs() != 2 {
		t.Fatalf("Run on engagement: %d, %d runs\n%s", rec.Code, runs(), rec.Body.String())
	}
	// one for the request and one before each of the two findings
	if len(rec.deadlines) != 3 || !long(rec.deadlines[2]) {
		t.Errorf("Run on engagement: write deadlines %v", rec.deadlines)
	}
}
