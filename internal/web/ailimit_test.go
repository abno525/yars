package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abno525/yars/internal/db"
)

// The AI spend limit is saved beside the prices on Admin › AI, in their
// form. A value that is no such number stores nothing, and neither does a
// limit without a price: the cost could not be worked out.
func TestAILimitSaved(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	form := url.Values{"provider": {"off"}, "price_in": {"3"}, "price_out": {"15"}, "limit": {"10.5"}}
	if rec := e.do(t, "dora", "POST", "/admin/ai", form, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	if v, _ := d.Setting(db.AILimitKey); v != "10.5" {
		t.Fatalf("limit %q", v)
	}
	if l, _ := d.AuditLog(1); len(l) != 1 || !strings.Contains(l[0].Detail, "limit 10.5") {
		t.Fatalf("audit %+v", l)
	}
	b := e.do(t, "dora", "GET", "/admin/ai", nil, nil).Body.String()
	if !strings.Contains(b, `<span class="flabel">Limit</span><span class="keyrow"><input class="monoin w128" name="limit" value="10.5" inputmode="decimal" autocomplete="off"><span class="muted">per 30 days</span></span>`) {
		t.Fatalf("form after save:\n%s", b)
	}
	// after Price out, before the key
	if i, j, k := strings.Index(b, `name="price_out"`), strings.Index(b, `name="limit"`), strings.Index(b, `name="key"`); i < 0 || i > j || j > k {
		t.Fatalf("the Limit row's place: %d %d %d", i, j, k)
	}
	for _, bad := range []string{"-1", "1.23456", "abc"} {
		form.Set("limit", bad)
		if rec := e.do(t, "dora", "POST", "/admin/ai", form, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Limit: a number with up to 4 decimals") {
			t.Errorf("limit %q: %d", bad, rec.Code)
		}
	}
	rec := e.do(t, "dora", "POST", "/admin/ai", url.Values{"provider": {"off"}, "limit": {"5"}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Limit: set a price first") {
		t.Fatalf("a limit without a price: %d", rec.Code)
	}
	if v, _ := d.Setting(db.AILimitKey); v != "10.5" {
		t.Fatalf("a refused save changed the limit: %q", v)
	}
	if v, _ := d.Setting(db.AIPriceInKey); v != "3" {
		t.Fatalf("a refused save changed a price: %q", v)
	}
	form.Set("limit", "")
	e.do(t, "dora", "POST", "/admin/ai", form, nil)
	if v, _ := d.Setting(db.AILimitKey); v != "" {
		t.Fatalf("an empty limit kept %q", v)
	}
}

// The limit is compared with the cost of the last 30 days at the prices: a
// call older than that does not count, and without a limit nothing is
// reached. The time is handed in.
func TestAILimitCountsThirtyDays(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	add := func(days, in, out int) {
		t.Helper()
		if err := d.AddAIUsage(db.AIUsage{TS: now.AddDate(0, 0, -days).Format(time.RFC3339), User: "alice", Purpose: "rule", In: in, Out: out, OK: true}); err != nil {
			t.Fatal(err)
		}
	}
	d.SetSetting(db.AIPriceInKey, "3")
	d.SetSetting(db.AIPriceOutKey, "15")
	add(40, 5000000, 0) // 15.00, outside the 30 days
	if st, err := aiLimitAt(d, now); err != nil || st.Set || st.Reached {
		t.Fatalf("without a limit: %+v %v", st, err)
	}
	d.SetSetting(db.AILimitKey, "4.5")
	if st, err := aiLimitAt(d, now); err != nil || !st.Set || st.Reached || st.Spent != 0 {
		t.Fatalf("only an old call: %+v %v", st, err)
	}
	add(29, 1000000, 0) // 3.00
	if st, _ := aiLimitAt(d, now); st.Reached {
		t.Fatalf("under the limit: %+v", st)
	}
	add(1, 0, 100000) // 1.50: 4.50 in all
	if st, _ := aiLimitAt(d, now); !st.Reached || st.Limit != 4.5 {
		t.Fatalf("at the limit: %+v", st)
	}
	// a limit of nothing is reached at once
	d.SetSetting(db.AILimitKey, "0")
	if st, _ := aiLimitAt(d, now.AddDate(1, 0, 0)); !st.Set || !st.Reached {
		t.Fatalf("limit 0: %+v", st)
	}
}

// aiLimitEnv is a server with three AI rules on the Impact section, a fake
// provider that counts its calls, prices and a limit of 1.
func aiLimitEnv(t *testing.T) (e *env, calls *atomic.Int32) {
	t.Helper()
	e = setupSerial(t)
	calls = &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"violations\":[]}"}}],"usage":{"prompt_tokens":12,"completion_tokens":3}}`)
	}))
	t.Cleanup(srv.Close)
	rule := func(id string) string {
		return "- id: " + id + "\n  level: warning\n  target: section:Impact\n  ai: zqinstr7 be plain, says " + id + "\n"
	}
	e.rules(t, rule("ai-a")+rule("ai-b")+rule("ai-c")+fooRule, nil)
	e.srv.wireAI()
	form := url.Values{"provider": {"openai"}, "base_url": {srv.URL}, "model": {"m1"}, "key": {"sk-test-0123456789"}, "price_in": {"3"}, "price_out": {"15"}, "limit": {"1"}}
	if rec := e.do(t, "dora", "POST", "/admin/ai", form, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	return e, calls
}

// check writes impact into the finding and runs a Check on it.
func (e *env) checkImpact(t *testing.T, impact string) {
	t.Helper()
	if err := e.srv.Store.UpdateSection("acme", fdir, "Impact", impact, "", wAlice); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "alice", "POST", fpath+"/checks", nil, hxReq); rec.Code != 200 {
		t.Fatalf("check %d", rec.Code)
	}
	e.srv.Store.WaitChecks()
}

const limitLine = "ai: the spend limit is reached; AI rules are skipped"

// Under the limit the AI rules call the provider. Once the cost of the last
// 30 days reaches it, a Check goes on without them: no call, each AI step
// failed with the words, the run done, and one warn line for the three
// rules. Admin › AI shows the state, Fix with AI is refused with words, and
// Test still calls. The line comes again only after the limit was not
// reached in between.
func TestAILimitStopsTheCalls(t *testing.T) {
	e, calls := aiLimitEnv(t)
	d := e.srv.Store.DB()
	e.checkImpact(t, "a foo here")
	if calls.Load() != 3 {
		t.Fatalf("under the limit: %d calls", calls.Load())
	}
	page := func() string { return e.do(t, "dora", "GET", "/admin/ai", nil, nil).Body.String() }
	if b := page(); strings.Contains(b, "Limit reached") || !strings.Contains(b, `<span class="tag idle">Not tested</span>`) {
		t.Fatalf("Admin AI under the limit:\n%s", b)
	}
	if n := len(e.log.With(limitLine)); n != 0 {
		t.Fatalf("%d limit lines under the limit", n)
	}
	// 1,000,000 tokens in at 3 per million: 3.00 of a limit of 1
	if err := d.AddAIUsage(db.AIUsage{User: "alice", Purpose: "rule", In: 1000000, OK: true}); err != nil {
		t.Fatal(err)
	}
	e.checkImpact(t, "another foo here")
	if calls.Load() != 3 {
		t.Fatalf("over the limit the provider got %d calls", calls.Load()-3)
	}
	st, err := e.srv.Store.CheckStatus("acme", fdir)
	if err != nil || st.Run.State != db.RunDone {
		t.Fatalf("the run over the limit: %+v %v", st.Run, err)
	}
	failed := 0
	for _, x := range st.Steps {
		if x.Kind == "ai" && x.State == db.StepFailed && x.Message == "AI rules skipped: the AI spend limit is reached" && x.Fail == "" {
			failed++
		}
	}
	if failed != 3 {
		t.Fatalf("AI steps: %+v", st.Steps)
	}
	if b := e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String(); !strings.Contains(b, "AI checks failed") || !strings.Contains(b, "AI rules skipped: the AI spend limit is reached") || !strings.Contains(b, "Avoid foo") {
		t.Fatalf("the strip:\n%s", b)
	}
	recs := e.log.With(limitLine)
	if len(recs) != 1 || recs[0].Level != slog.LevelWarn || !recs[0].Has("spent") || recs[0].Str("limit") != "1" {
		t.Fatalf("%d limit lines:\n%s", len(recs), e.log.Text())
	}
	// the state on Admin › AI; a page view writes no line
	if b := page(); !strings.Contains(b, `<h2>AI provider</h2><span class="tag warn">Limit reached</span>`) {
		t.Fatalf("Admin AI over the limit:\n%s", b)
	}
	// Fix with AI is refused with words
	rec := e.do(t, "alice", "POST", fpath+"/checks/fix", nil, hxReq)
	if rec.Code != http.StatusUnprocessableEntity || strings.TrimSpace(rec.Body.String()) != "the AI spend limit is reached" {
		t.Fatalf("fix over the limit: %d %s", rec.Code, rec.Body.String())
	}
	if e.srv.Store.FixRunning("acme", "F-001") {
		t.Fatal("a fix runs over the limit")
	}
	// Test is not held
	if rec := e.do(t, "dora", "POST", "/admin/ai/test", url.Values{}, nil); rec.Code != 200 || calls.Load() != 4 {
		t.Fatalf("Test over the limit: %d, %d calls", rec.Code, calls.Load())
	}
	if n := len(e.log.With(limitLine)); n != 1 {
		t.Fatalf("%d limit lines after a page view, a fix press and a Test:\n%s", n, e.log.Text())
	}
	if strings.Contains(e.log.Text(), "zqinstr7") {
		t.Fatalf("a rule's instruction is in the log:\n%s", e.log.Text())
	}
	// a higher limit: the rules call again; lowered, the line comes once more
	save := func(limit string) {
		t.Helper()
		base, _ := d.Setting(db.AIBaseKey)
		form := url.Values{"provider": {"openai"}, "base_url": {base}, "model": {"m1"}, "price_in": {"3"}, "price_out": {"15"}, "limit": {limit}}
		if rec := e.do(t, "dora", "POST", "/admin/ai", form, nil); rec.Code != http.StatusSeeOther {
			t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
		}
	}
	save("100")
	e.checkImpact(t, "a third foo here")
	if calls.Load() != 7 {
		t.Fatalf("under the raised limit: %d calls", calls.Load())
	}
	if b := page(); strings.Contains(b, "Limit reached") {
		t.Fatalf("Admin AI under the raised limit:\n%s", b)
	}
	save("1")
	e.checkImpact(t, "a fourth foo here")
	if calls.Load() != 7 || len(e.log.With(limitLine)) != 2 {
		t.Fatalf("over the limit again: %d calls, %d lines", calls.Load(), len(e.log.With(limitLine)))
	}
}
