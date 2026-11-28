package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/rules"
)

// askedAI counts the questions put to the AI and finds nothing.
type askedAI struct {
	rules.SlowRunner
	mu sync.Mutex
	n  int
}

func (c *askedAI) AI(context.Context, rules.Rule, string, string) []rules.Violation {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return nil
}

func (c *askedAI) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// The engagement's AI switch is a field of the Settings tab's General panel,
// the same in both of the panel's states: a director flips it with a POST of
// its own, everyone else sees it disabled. Off, the Test bench and Try answer
// an AI rule with words and ask nothing.
func TestEngagementAISwitch(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, "- id: plain\n  level: warning\n  target: title\n  ai: Be plain.\n", nil)
	cnt := &askedAI{SlowRunner: e.srv.Rules.Runner}
	e.srv.Rules.Runner = cnt
	field := func(user string) string {
		t.Helper()
		page := e.do(t, user, "GET", "/e/acme/settings", nil, nil).Body.String()
		grid := between(page, `<div class="fgrid two">`, "</div>\n    <div class=\"pfoot")
		if user != "dora" {
			grid = between(page, `<div class="fgrid two">`, "</div>\n  </section>")
		}
		if n := strings.Count(grid, `<div class="field">`) + strings.Count(grid, `<label class="field">`); n != 7 {
			t.Fatalf("%s: %d fields in the General panel:\n%s", user, n, grid)
		}
		if !strings.Contains(page, `<form id="engai" method="post" action="/e/acme/settings/ai" hidden>`) {
			t.Fatalf("%s: no form for the switch", user)
		}
		return between(grid, `<span class="flabel">AI</span>`, "</div>") + between(page, `<form id="engai"`, "</form>")
	}
	if f := field("dora"); !strings.Contains(f, `<button class="toggle on" role="switch" aria-checked="true" aria-label="AI" form="engai"><span>`) || !strings.Contains(f, `name="on" value="0"`) {
		t.Fatalf("a director, on:\n%s", f)
	}
	if f := field("alice"); !strings.Contains(f, `<button class="toggle on" role="switch" aria-checked="true" aria-label="AI" form="engai" disabled><span>`) {
		t.Fatalf("a pentester, on:\n%s", f)
	}
	off := url.Values{"on": {"0"}}
	for _, u := range []string{"alice", "bob"} {
		if rec := e.do(t, u, "POST", "/e/acme/settings/ai", off, nil); rec.Code == http.StatusSeeOther {
			t.Fatalf("%s switched it off", u)
		}
	}
	if eng, err := e.srv.Store.Engagement("acme"); err != nil || eng.AIOff() {
		t.Fatalf("switched off by a non-director: %+v %v", eng, err)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/settings/ai", off, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/settings" {
		t.Fatalf("dora: %d %s", rec.Code, rec.Body.String())
	}
	if eng, err := e.srv.Store.Engagement("acme"); err != nil || !eng.AIOff() {
		t.Fatalf("after the switch: %+v %v", eng, err)
	}
	if f := field("dora"); !strings.Contains(f, `<button class="toggle" role="switch" aria-checked="false" aria-label="AI" form="engai"><span>`) || !strings.Contains(f, `name="on" value="1"`) {
		t.Fatalf("a director, off:\n%s", f)
	}
	if f := field("alice"); !strings.Contains(f, `<button class="toggle" role="switch" aria-checked="false" aria-label="AI" form="engai" disabled><span>`) {
		t.Fatalf("a pentester, off:\n%s", f)
	}

	// the bench and Try: words, not "0 hits", and nothing asked
	hx := map[string]string{"HX-Request": "true"}
	for name, req := range map[string]struct {
		path string
		form url.Values
	}{
		"bench":     {"/admin/rules/bench", url.Values{"rule": {"plain"}, "eng": {"acme"}, "fid": {fdir}}},
		"bench all": {"/admin/rules/bench", url.Values{"rule": {"plain"}, "eng": {"acme"}, "all": {"1"}}},
		"try":       {"/admin/rules/try", url.Values{"id": {""}, "kind": {"ai"}, "level": {"warning"}, "target": {"title"}, "ai": {"Be short."}, "eng": {"acme"}, "fid": {fdir}}},
	} {
		rec := e.do(t, "dora", "POST", req.path, req.form, hx)
		if b := rec.Body.String(); rec.Code != http.StatusUnprocessableEntity || strings.TrimSpace(b) != "AI is off for this engagement" {
			t.Errorf("%s: %d\n%s", name, rec.Code, b)
		}
	}
	// a check from the page asks nothing either
	if rec := e.do(t, "alice", "POST", fpath+"/checks", nil, hxReq); rec.Code != 200 {
		t.Fatalf("check %d", rec.Code)
	}
	e.srv.Store.WaitChecks()
	if cnt.calls() != 0 {
		t.Fatalf("the AI was asked %d times", cnt.calls())
	}
	// on again: the bench asks
	if rec := e.do(t, "dora", "POST", "/e/acme/settings/ai", url.Values{"on": {"1"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("on again: %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/admin/rules/bench", url.Values{"rule": {"plain"}, "eng": {"acme"}, "fid": {fdir}}, hx); rec.Code != 200 || cnt.calls() != 1 {
		t.Fatalf("the bench with AI on: %d, %d calls\n%s", rec.Code, cnt.calls(), rec.Body.String())
	}
}

// Fix with AI keeps its slot where the engagement takes no AI: the button is
// there, disabled, and a press is refused with the words.
func TestFixButtonWhereAIIsOff(t *testing.T) {
	e, f := fixEnv(t, true)
	if btn := fixButton(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()); btn == "" || strings.Contains(btn, " disabled") {
		t.Fatalf("AI on: %q", btn)
	}
	if err := e.srv.Store.SetEngagementAI("acme", false, config.User{Username: "dora", Role: "director"}); err != nil {
		t.Fatal(err)
	}
	btn := fixButton(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if !strings.Contains(btn, "Fix with AI") || !strings.Contains(btn, " disabled") || !strings.Contains(btn, "w152") {
		t.Fatalf("AI off: %q", btn)
	}
	if rec := e.do(t, "alice", "POST", fpath+"/checks/fix", nil, hxReq); rec.Code != 422 || !strings.Contains(rec.Body.String(), "AI is off for this engagement") {
		t.Fatalf("a press: %d %s", rec.Code, rec.Body.String())
	}
	if f.calls != 0 {
		t.Fatal("the AI was asked")
	}
}
