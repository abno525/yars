package web

import (
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"yars/internal/auth"
	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/index"
	"yars/internal/seed"
	"yars/internal/store"
)

// The budget test runs only on request (it needs a quiet machine):
//
//	go test ./internal/web/ -run TestPageBudgets -count=1 -args -bench-budgets [-bench-full]
//
// or with YARS_BENCH=1 [YARS_BENCH_FULL=1] in the environment.
var (
	benchBudgets = flag.Bool("bench-budgets", false, "run TestPageBudgets")
	benchFull    = flag.Bool("bench-full", false, "seed 50×300 findings and 10k messages (default 10×100, 2k)")
)

func fullSize() bool { return *benchFull || os.Getenv("YARS_BENCH_FULL") == "1" }

func benchOptions() seed.Options {
	if fullSize() {
		return seed.Options{Engagements: 50, Findings: 300, Messages: 10000}
	}
	return seed.Options{Engagements: 10, Findings: 100, Messages: 2000}
}

// seededEnv is a server on a seeded data directory, logged in as every
// seeded user.
type seededEnv struct {
	srv  *Server
	h    http.Handler
	st   *store.Store
	d    *db.DB
	toks map[string]string
	// a finding with the most chat messages, and its board
	board, finding, eng, dir string
}

func seeded(tb testing.TB, o seed.Options) *seededEnv {
	tb.Helper()
	dir := filepath.Join(tb.TempDir(), "data")
	r, err := gitrepo.Init(dir)
	if err != nil {
		tb.Fatal(err)
	}
	if err := seed.Fill(dir, o); err != nil {
		tb.Fatal(err)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		tb.Fatal(err)
	}
	d, err := db.Open(db.Path(dir))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { d.Close() })
	st := store.New(r, cfg, d)
	au := auth.New(d)
	srv := &Server{Store: st, Index: index.New(st, r), Auth: au, Cfg: cfg}
	e := &seededEnv{srv: srv, h: srv.Handler(), st: st, d: d, toks: map[string]string{}}
	for _, u := range seed.Users {
		tok, ok := au.Login(u.Username, seed.Password)
		if !ok {
			tb.Fatal("login", u.Username)
		}
		e.toks[u.Username] = tok
	}
	// the busiest finding of the first engagement
	e.eng = seed.EngID(0)
	chats, err := d.AllMessages(e.eng)
	if err != nil {
		tb.Fatal(err)
	}
	refs, err := st.ListFindings(e.eng)
	if err != nil || len(refs) == 0 {
		tb.Fatal("no findings", err)
	}
	best := refs[0]
	for _, ref := range refs {
		if len(chats[ref.F.Meta.ID]) > len(chats[best.F.Meta.ID]) {
			best = ref
		}
	}
	e.dir = best.Dir
	e.board = "/e/" + e.eng
	e.finding = "/e/" + e.eng + "/f/" + best.Dir
	return e
}

func (e *seededEnv) get(tb testing.TB, user, path string) {
	tb.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks[user]})
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		tb.Fatalf("GET %s as %s: %d", path, user, rec.Code)
	}
}

func (e *seededEnv) user(tb testing.TB, name string) config.User {
	u, ok := e.srv.Auth.Lookup(name)
	if !ok {
		tb.Fatal("no user", name)
	}
	return u
}

// p95 of the durations (nearest rank).
func p95(ds []time.Duration) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	i := (len(s)*95+99)/100 - 1
	return s[max(i, 0)]
}

func timeN(n int, fn func()) []time.Duration {
	out := make([]time.Duration, 0, n)
	for range n {
		t := time.Now()
		fn()
		out = append(out, time.Since(t))
	}
	return out
}

// Warm board, finding and inbox requests on the seeded data start no git
// process.
func TestSeededPagesStartNoGit(t *testing.T) {
	e := seeded(t, seed.Options{Engagements: 10, Findings: 100, Messages: 2000})
	pages := []string{e.board, e.finding, "/inbox", "/"}
	for _, p := range pages {
		e.get(t, "dir1", p)
	}
	for _, p := range pages {
		for _, u := range []string{"dir1", "rev1", "pen1"} {
			n := gitrepo.Spawned()
			e.get(t, u, p)
			if got := gitrepo.Spawned() - n; got != 0 {
				t.Errorf("%s as %s: %d git processes", p, u, got)
			}
		}
	}
}

// Long inbox lists show one page each; "Load more" appends the next page
// of that list only.
func TestInboxPaginates(t *testing.T) {
	e := seeded(t, seed.Options{Engagements: 2, Findings: 40})
	e.srv.pageSize = 3
	engs, _ := e.srv.Index.Engagements()
	v, err := e.srv.inboxFor(e.user(t, "rev1"), engs)
	if err != nil {
		t.Fatal(err)
	}
	review := len(v.Review)
	if review <= 6 || v.Count() != review {
		t.Fatalf("fixture has only %d findings in verification", review)
	}
	body := func(path string, hx bool) string {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks["rev1"]})
		if hx {
			req.Header.Set("HX-Request", "true")
		}
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s: %d", path, rec.Code)
		}
		return rec.Body.String()
	}
	titles := regexp.MustCompile(`<td class="title">`)
	full := body("/inbox", false)
	if n := len(titles.FindAllString(full, -1)); n > 9 {
		t.Fatalf("%d rows on the first page, want at most 3 per list", n)
	}
	if !strings.Contains(full, "/inbox?list=review&amp;offset=3") {
		t.Fatal("no load-more for the review list")
	}
	// the badge still counts everything
	if !strings.Contains(full, `<span class="badge">`+strconv.Itoa(review)) {
		t.Errorf("badge does not count %d", review)
	}
	next := body("/inbox?list=review&offset=3", true)
	if strings.Contains(next, "<table") || strings.Contains(next, "<h2") || len(titles.FindAllString(next, -1)) != 3 ||
		!strings.Contains(next, "list=review&amp;offset=6") {
		t.Fatalf("second page:\n%s", next)
	}
	last := body("/inbox?list=review&offset="+strconv.Itoa(review-1), true)
	if len(titles.FindAllString(last, -1)) != 1 || strings.Contains(last, "offset=") {
		t.Fatalf("last page:\n%s", last)
	}
}

type budget struct {
	name  string
	got   time.Duration
	limit time.Duration
}

func TestPageBudgets(t *testing.T) {
	if !*benchBudgets && os.Getenv("YARS_BENCH") != "1" {
		t.Skip("run with -args -bench-budgets (or YARS_BENCH=1)")
	}
	o := benchOptions()
	t0 := time.Now()
	e := seeded(t, o)
	t.Logf("data: %d engagements × %d findings, %d messages (seeded in %s)", o.Engagements, o.Findings, o.Messages, time.Since(t0).Round(time.Millisecond))

	var res []budget
	// cold start: the first page builds the whole index
	t0 = time.Now()
	e.get(t, "dir1", e.board)
	res = append(res, budget{"cold start (first board)", time.Since(t0), 3 * time.Second})

	page := func(name, user, path string, limit time.Duration) {
		for range 5 {
			e.get(t, user, path)
		}
		res = append(res, budget{name, p95(timeN(50, func() { e.get(t, user, path) })), limit})
	}
	page("board p95", "dir1", e.board, 30*time.Millisecond)
	page("finding p95", "dir1", e.finding, 40*time.Millisecond)
	page("inbox p95 (director)", "dir1", "/inbox", 20*time.Millisecond)
	page("inbox p95 (reviewer)", "rev1", "/inbox", 20*time.Millisecond)

	// a chat post: the store tells the index, which updates one row; the
	// next reader finds it up to date
	ix := e.srv.Index
	rev := e.user(t, "rev1")
	var post, refresh []time.Duration
	for i := range 50 {
		t1 := time.Now()
		if _, err := e.st.PostChat(e.eng, e.dir, chat.Message{Text: fmt.Sprintf("bench %d", i)}, rev); err != nil {
			t.Fatal(err)
		}
		t2 := time.Now()
		if _, err := ix.Gen(); err != nil {
			t.Fatal(err)
		}
		post, refresh = append(post, t2.Sub(t1)), append(refresh, time.Since(t2))
	}
	t.Logf("chat post (store write + row update) p95 %s", p95(post))
	res = append(res, budget{"index refresh after chat p95", p95(refresh), 5 * time.Millisecond})
	// the reload of the changed engagement is what makes a content change
	// expensive: measure the first index read after the commit
	refs, err := e.st.ListFindings(e.eng)
	if err != nil {
		t.Fatal(err)
	}
	a := gitrepo.Author{Name: "dir1", Email: "dir1@yars.local"}
	var content []time.Duration
	for i := range 10 {
		ref := refs[i%len(refs)]
		if err := e.st.UpdateSection(e.eng, ref.Dir, "Impact", fmt.Sprintf("Changed %d.\n", i), "", a); err != nil {
			t.Fatal(err)
		}
		t1 := time.Now()
		rows, err := ix.Rows(index.Query{EngID: e.eng})
		if err != nil || len(rows) != o.Findings {
			t.Fatalf("rows %d %v", len(rows), err)
		}
		content = append(content, time.Since(t1))
	}
	res = append(res, budget{"index refresh after content change p95", p95(content), 300 * time.Millisecond})

	for _, b := range res {
		mark := "ok"
		if b.got > b.limit {
			mark = "OVER"
			t.Errorf("%s: %s, budget %s", b.name, b.got, b.limit)
		}
		t.Logf("%-42s %10s  (budget %s) %s", b.name, b.got.Round(10*time.Microsecond), b.limit, mark)
	}
}

func benchPage(b *testing.B, user string, path func(*seededEnv) string) {
	e := seeded(b, benchOptions())
	p := path(e)
	e.get(b, user, p)
	b.ResetTimer()
	for b.Loop() {
		e.get(b, user, p)
	}
}

func BenchmarkBoard(b *testing.B) {
	benchPage(b, "dir1", func(e *seededEnv) string { return e.board })
}

func BenchmarkFinding(b *testing.B) {
	benchPage(b, "dir1", func(e *seededEnv) string { return e.finding })
}

func BenchmarkInbox(b *testing.B) {
	benchPage(b, "dir1", func(*seededEnv) string { return "/inbox" })
}

// BenchmarkRefreshAfterChat: a chat post and the next index read.
func BenchmarkRefreshAfterChat(b *testing.B) {
	e := seeded(b, benchOptions())
	rev := e.user(b, "rev1")
	e.srv.Index.Gen()
	i := 0
	for b.Loop() {
		i++
		if _, err := e.st.PostChat(e.eng, e.dir, chat.Message{Text: fmt.Sprintf("bench %d", i)}, rev); err != nil {
			b.Fatal(err)
		}
		if _, err := e.srv.Index.Gen(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRefreshAfterContent: the index read after a content commit in
// one engagement (the commit itself is not timed).
func BenchmarkRefreshAfterContent(b *testing.B) {
	e := seeded(b, benchOptions())
	e.srv.Index.Gen()
	a := gitrepo.Author{Name: "dir1", Email: "dir1@yars.local"}
	i := 0
	for b.Loop() {
		b.StopTimer()
		i++
		if err := e.st.UpdateSection(e.eng, e.dir, "Impact", fmt.Sprintf("Changed %d.\n", i), "", a); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if _, err := e.srv.Index.Gen(); err != nil {
			b.Fatal(err)
		}
	}
}
