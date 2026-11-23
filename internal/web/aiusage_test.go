package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yars/internal/db"
)

// usagePanel is Admin › System's AI usage panel.
func usagePanel(t *testing.T, e *env) string {
	t.Helper()
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	i := strings.Index(b, `<section class="panel sys" id="aiusage">`)
	if i < 0 {
		t.Fatalf("no AI usage panel:\n%s", b)
	}
	if j := strings.Index(b, `id="retention"`); j < 0 || j > i {
		t.Fatal("AI usage is not after Retention")
	}
	return b[i : i+strings.Index(b[i:], "</section>")]
}

// D24: with prices of 3 and 15 per million tokens, 1,000,000 in and
// 100,000 out cost 4.50.
func TestUsagePanelCost(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	d.SetSetting(db.AIPriceInKey, "3")
	d.SetSetting(db.AIPriceOutKey, "15")
	if err := d.AddAIUsage(db.AIUsage{User: "alice", Purpose: "rule", Provider: "openai", Model: "m1", Rule: "acr", In: 1000000, Out: 100000, MS: 900, OK: true}); err != nil {
		t.Fatal(err)
	}
	p := usagePanel(t, e)
	for _, want := range []string{`<span class="sl">Period</span><span class="sv">7 days</span>`, `<span class="sl">Period</span><span class="sv">30 days</span>`,
		`<span class="sl">Cost</span><span class="sv">4.50</span>`,
		`<thead><tr><th>User</th><th class="c-num">Calls</th><th class="c-num">Tokens in</th><th class="c-num">Tokens out</th><th class="c-num">Cost</th></tr></thead>`,
		`<td class="clip" title="alice">alice</td><td class="num" title="1">1</td><td class="num" title="1000000">1000000</td><td class="num" title="100000">100000</td><td class="num" title="4.50">4.50</td>`} {
		if !strings.Contains(p, want) {
			t.Fatalf("panel lacks %s:\n%s", want, p)
		}
	}
	// ten digits and "TOKENS OUT" fit their columns
	if css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String(); !strings.Contains(css, ".usagetable th.c-num { width: 152px; }") {
		t.Fatal("the usage table's number columns are the narrow default")
	}
	if n := strings.Count(p, `<span class="sv">4.50</span>`); n != 2 {
		t.Fatalf("cost shown %d times in the stats:\n%s", n, p)
	}
}

// D24: without a price the cost is a dash; without calls the table has its
// empty row.
func TestUsagePanelNoPrice(t *testing.T) {
	e := setup(t)
	if p := usagePanel(t, e); !strings.Contains(p, `<tr class="emptyrow"><td colspan="5">—</td></tr>`) || !strings.Contains(p, `<span class="sl">Calls</span><span class="sv">0</span>`) {
		t.Fatalf("empty panel:\n%s", p)
	}
	e.srv.Store.DB().AddAIUsage(db.AIUsage{User: "alice", Purpose: "rule", Provider: "openai", Model: "m1", In: 10, Out: 1, OK: true})
	p := usagePanel(t, e)
	if !strings.Contains(p, `<td class="num" title="—">—</td>`) || !strings.Contains(p, `<span class="sl">Cost</span><span class="sv">—</span>`) || strings.Contains(p, "0.00") {
		t.Fatalf("panel without prices:\n%s", p)
	}
}

// D24: the admin's prices are saved (empty = none); a bad one is refused.
func TestAIPricesSaved(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	form := url.Values{"provider": {"off"}, "price_in": {"2.5"}, "price_out": {"10.1234"}}
	if rec := e.do(t, "dora", "POST", "/admin/ai", form, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	if in, _ := d.Setting(db.AIPriceInKey); in != "2.5" {
		t.Fatalf("price in %q", in)
	}
	if l, _ := d.AuditLog(1); len(l) != 1 || !strings.Contains(l[0].Detail, "price 2.5/10.1234") {
		t.Fatalf("audit %+v", l)
	}
	b := e.do(t, "dora", "GET", "/admin/ai", nil, nil).Body.String()
	if !strings.Contains(b, `name="price_in" value="2.5"`) || !strings.Contains(b, `name="price_out" value="10.1234"`) || !strings.Contains(b, `class="monoin w128"`) {
		t.Fatalf("form after save:\n%s", b)
	}
	for _, bad := range []string{"-1", "1.23456", "abc"} {
		if rec := e.do(t, "dora", "POST", "/admin/ai", url.Values{"provider": {"off"}, "price_in": {bad}}, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("price %q: %d", bad, rec.Code)
		}
	}
	if in, _ := d.Setting(db.AIPriceInKey); in != "2.5" {
		t.Fatalf("a refused price changed it: %q", in)
	}
	e.do(t, "dora", "POST", "/admin/ai", url.Values{"provider": {"off"}, "price_in": {""}, "price_out": {""}}, nil)
	if in, _ := d.Setting(db.AIPriceInKey); in != "" {
		t.Fatalf("an empty price kept %q", in)
	}
}

// D24: a call made by the server is stored with who made it (the admin's
// Test here).
func TestAIUsageWired(t *testing.T) {
	e := setupSerial(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"violations\":[]}"}}],"usage":{"prompt_tokens":12,"completion_tokens":3}}`)
	}))
	t.Cleanup(srv.Close)
	e.rules(t, styleRules, nil)
	e.srv.wireAI() // the engine above came after the server's start
	form := url.Values{"provider": {"openai"}, "base_url": {srv.URL}, "model": {"m1"}, "key": {"sk-test-0123456789"}}
	if rec := e.do(t, "dora", "POST", "/admin/ai", form, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	if rec := e.do(t, "dora", "POST", "/admin/ai/test", url.Values{}, nil); rec.Code != 200 {
		t.Fatalf("test %d", rec.Code)
	}
	got, err := e.srv.Store.DB().AITotals(time.Now().Add(-time.Hour))
	if err != nil || len(got) != 2 || got[0] != (db.AITotal{Calls: 1, In: 12, Out: 3}) || got[1].User != "dora" {
		t.Fatalf("totals %+v %v", got, err)
	}
}

// Q1, Q16: the server keeps script and AI results in its database, so a
// check after a restart (a new engine) does not run the script again on
// the same finding.
func TestRuleResultsStoredInDatabase(t *testing.T) {
	e := setupSerial(t)
	log := filepath.Join(t.TempDir(), "runs")
	scripts := map[string]string{"check.sh": "cat >/dev/null; echo x >> " + log + "; echo '[{\"message\":\"script says hi\",\"quote\":\"q1\",\"target\":\"section:Impact\"}]'\n"}
	check := func() {
		t.Helper()
		e.rules(t, styleRules, scripts) // a new engine and runner: a restart
		e.srv.wireAI()
		if rn := e.srv.runner(); rn == nil || rn.Results == nil {
			t.Fatal("the runner keeps its results in memory only")
		}
		if rec := e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil); rec.Code != 200 {
			t.Fatalf("check %d", rec.Code)
		}
		e.srv.Store.WaitChecks()
		if b := e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String(); !strings.Contains(b, "script says hi") {
			t.Fatalf("panel:\n%s", b)
		}
	}
	check()
	check()
	if b, _ := os.ReadFile(log); strings.Count(string(b), "x") != 1 {
		t.Fatalf("the script ran %d times", strings.Count(string(b), "x"))
	}
	var n int
	if err := e.srv.Store.DB().QueryRow("SELECT count(*) FROM rule_cache WHERE kind = 'script'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("stored %d %v", n, err)
	}
}
