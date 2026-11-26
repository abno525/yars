package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

// object parses a tool's text as one JSON object.
func object(t *testing.T, name, text string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("%s: not a JSON object: %v\n%.300s", name, err, text)
	}
	return m
}

// message is the "message" of a tool's answer (a refusal's too).
func message(t *testing.T, text string) string {
	t.Helper()
	s, _ := object(t, "answer", text)["message"].(string)
	return s
}

// itemsOf decodes the "items" of a list answer into v.
func itemsOf(t *testing.T, text string, v any) {
	t.Helper()
	var w struct {
		Items json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal([]byte(text), &w); err != nil || w.Items == nil {
		t.Fatalf("not a list answer: %v\n%.300s", err, text)
	}
	if err := json.Unmarshal(w.Items, v); err != nil {
		t.Fatalf("items: %v\n%.300s", err, text)
	}
}

// withRules gives the fixture a rules engine (start_check needs one).
func withRules(t *testing.T, f *fx) {
	t.Helper()
	rd := filepath.Join(f.dir, ".yars", "rules")
	os.MkdirAll(rd, 0o755)
	os.WriteFile(filepath.Join(rd, "r.yaml"), []byte("- id: no-sql\n  target: title\n  regex_forbid: 'SQL'\n- id: no-foo\n  target: section:Impact\n  regex_forbid: 'foo'\n  level: warning\n"), 0o644)
	eng := rules.NewEngine(rd, f.s.Cfg)
	f.s.Rules, f.s.Store.Linter = eng, eng
}

// Every tool, called right, answers one JSON object with "ok": true.
func TestEverySuccessIsAnObjectWithOK(t *testing.T) {
	f := newFx(t)
	withRules(t, f)
	addTemplate(t, f, "sqli", "SQL injection")
	defer f.s.Store.WaitChecks()
	fd := map[string]any{"engagement": "acme", "finding": "F-001"}
	with := func(extra map[string]any) map[string]any {
		m := map[string]any{"engagement": "acme", "finding": "F-001"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	thread := ""
	calls := []struct {
		tool string
		args func() map[string]any
	}{
		{"list_engagements", func() map[string]any { return map[string]any{} }},
		{"list_findings", func() map[string]any { return map[string]any{"engagement": "acme"} }},
		{"read_finding", func() map[string]any { return fd }},
		{"list_templates", func() map[string]any { return map[string]any{} }},
		{"create_finding", func() map[string]any { return map[string]any{"engagement": "acme", "title": "Open redirect"} }},
		{"update_section", func() map[string]any { return with(map[string]any{"section": "Impact", "body": "a foo here"}) }},
		{"set_field", func() map[string]any {
			return with(map[string]any{"field": "title", "value": "SQL injection in search"})
		}},
		{"add_chat_message", func() map[string]any { return with(map[string]any{"text": "a question"}) }},
		{"resolve_thread", func() map[string]any { return with(map[string]any{"thread": thread}) }},
		{"lint_finding", func() map[string]any { return fd }},
		{"start_check", func() map[string]any { return fd }},
		{"get_check_results", func() map[string]any { return fd }},
		{"fix_checks", func() map[string]any { return fd }},
		{"list_notifications", func() map[string]any { return map[string]any{} }},
		{"mark_notifications_read", func() map[string]any { return map[string]any{"all": true} }},
		{"whoami", func() map[string]any { return map[string]any{} }},
		{"get_config", func() map[string]any { return map[string]any{} }},
		{"list_team", func() map[string]any { return map[string]any{"engagement": "acme"} }},
		{"read_chat", func() map[string]any { return fd }},
		{"list_history", func() map[string]any { return fd }},
		{"list_attachments", func() map[string]any { return fd }},
		{"read_template", func() map[string]any { return map[string]any{"template": "sqli"} }},
		{"transition", func() map[string]any { return with(map[string]any{"action": "withdraw", "reason": "duplicate"}) }},
	}
	seen := map[string]bool{}
	for _, c := range calls {
		seen[c.tool] = true
		if c.tool == "fix_checks" {
			f.s.Store.Linter = &fixer{Engine: f.s.Rules} // a provider that answers
		}
		text, isErr := f.call(alice, c.tool, c.args())
		if isErr {
			t.Fatalf("%s failed: %s", c.tool, text)
		}
		m := object(t, c.tool, text)
		if m["ok"] != true {
			t.Fatalf("%s: no ok: %s", c.tool, text)
		}
		if c.tool == "add_chat_message" {
			thread, _ = m["id"].(string)
		}
		if c.tool == "start_check" || c.tool == "fix_checks" {
			f.s.Store.WaitChecks()
		}
	}
	for _, tl := range tools {
		if !seen[tl.name] {
			t.Errorf("tool %s not called", tl.name)
		}
	}
}

// A client of the plain answers is still told what happened.
func TestSuccessKeepsMessage(t *testing.T) {
	f := newFx(t)
	text := f.ok(alice, "update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact", "body": "Full read."})
	if text != `{"ok":true,"message":"updated Impact"}` {
		t.Fatalf("%s", text)
	}
}

func TestErrorCodes(t *testing.T) {
	cases := []struct {
		err  error
		code string
	}{
		{&workflow.Denied{Reason: "no"}, "not_allowed"},
		{fmt.Errorf("edit: %w", store.ErrConflict), "conflict"},
		{store.ErrNotFound, "not_found"},
		{store.ErrArchived, "archived"},
		{store.ErrNoDB, "no_database"},
		{store.ErrBusy, "busy"},
		{fmt.Errorf("%w: bad", store.ErrInvalidValue), "invalid"},
		{fmt.Errorf("%w: x", store.ErrInvalidBody), "invalid"},
		{fmt.Errorf("%w: x", store.ErrInvalidChat), "invalid"},
		{refuse("invalid", `missing argument "finding"`), "invalid"},
		{ambiguous{id: "F-001", dirs: []string{"a", "b"}}, "invalid"},
		// a refusal the caller can retry: the finding changed while its
		// checks ran (a Denied for the web, a conflict here)
		{&workflow.Denied{Reason: "the finding changed while its checks ran; try again", Err: store.ErrConflict}, "conflict"},
		// the server's own failures: not the caller's mistake
		{errors.New("disk full"), "server_error"},
		{fmt.Errorf("read: %w", os.ErrPermission), "server_error"},
		{&store.UnreadableError{Eng: "acme", Dir: "F-001-x", Err: errors.New("bad yaml")}, "server_error"},
	}
	for _, c := range cases {
		if got := codeOf(c.err); got != c.code {
			t.Errorf("%v: %s, want %s", c.err, got, c.code)
		}
		m := object(t, c.code, fail(c.err))
		want := explain(c.err)
		var bad *store.UnreadableError
		if c.code == "server_error" && !errors.As(c.err, &bad) {
			// the server's own failure is not told in its words (a path, a
			// statement): the log has them (pre1 2.29)
			want = "internal error"
		}
		if m["ok"] != false || m["code"] != c.code || m["message"] != want {
			t.Errorf("fail(%v) = %v", c.err, m)
		}
	}
	// over the wire: a refusal is isError with the object
	f := newFx(t)
	text, isErr := f.call(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-009"})
	if m := object(t, "read_finding", text); !isErr || m["code"] != "not_found" {
		t.Fatalf("%v %s", isErr, text)
	}
	text, isErr = f.call(alice, "read_finding", map[string]any{"engagement": "acme"})
	if m := object(t, "read_finding", text); !isErr || m["code"] != "invalid" || m["message"] != `missing argument "finding"` {
		t.Fatalf("%v %s", isErr, text)
	}
	// the gate: a token's action and engagements, the team
	f.s.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, dora.GitAuthor())
	edit := map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact", "body": "x"}
	read := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeRead}}
	acme := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeAll}, Engagements: []string{"acme"}}
	for _, c := range []struct {
		u    config.User
		tok  *db.TokenInfo
		tool string
		args map[string]any
		code string
	}{
		{alice, &read, "update_section", edit, "not_allowed"},
		{dora, &acme, "list_findings", map[string]any{"engagement": "beta"}, "not_allowed"},
		{alice, nil, "list_findings", map[string]any{"engagement": "beta"}, "not_found"},
	} {
		var text string
		if c.tok != nil {
			text, _ = f.callTok(c.u, *c.tok, c.tool, c.args)
		} else {
			text, _ = f.call(c.u, c.tool, c.args)
		}
		if m := object(t, c.tool, text); m["code"] != c.code {
			t.Errorf("%s as %s: %s, want %s", c.tool, c.u.Username, text, c.code)
		}
	}
}

// Q9: every mistake of the caller (an argument left out, blank or of the
// wrong type, a value the tool or the store refuses) is invalid, never
// server_error.
func TestClientMistakesStayInvalid(t *testing.T) {
	f := newFx(t)
	fd := func(extra map[string]any) map[string]any {
		m := map[string]any{"engagement": "acme", "finding": "F-001"}
		maps.Copy(m, extra)
		return m
	}
	field := func(name, value string) map[string]any { return fd(map[string]any{"field": name, "value": value}) }
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"read_finding", map[string]any{"engagement": "acme"}},
		{"read_finding", map[string]any{"engagement": "acme", "finding": " "}},
		{"read_finding", map[string]any{"engagement": "acme", "finding": 7}},
		{"lint_finding", fd(map[string]any{"all": "yes"})},
		{"list_findings", map[string]any{"engagement": "acme", "status": "open"}},
		{"list_findings", map[string]any{"engagement": "acme", "severity": "severe"}},
		{"list_findings", map[string]any{"engagement": "acme", "limit": "0"}},
		{"list_engagements", map[string]any{"cursor": "x"}},
		{"create_finding", map[string]any{"engagement": "acme", "title": " "}},
		{"create_finding", map[string]any{"engagement": "acme", "title": "two\nlines"}},
		{"update_section", fd(map[string]any{"section": "Summary", "body": "x"})},
		{"update_section", fd(map[string]any{"section": " ", "body": "x"})},
		{"update_section", fd(map[string]any{"section": "Impact", "body": "## Heading\n"})},
		{"set_field", fd(map[string]any{"field": " ", "value": "x"})},
		{"set_field", field("title", "")},
		{"set_field", field("severity", "severe")},
		{"set_field", field("cvss", "CVSS:3.1/AV:X")},
		{"set_field", field("cvss_reason.FOO", "x")},
		{"set_field", field("cvss_reason.AC", "x")}, // no vector yet
		{"set_field", field("details.Nope", "x")},
		{"set_field", field("reviewers", "nobody")},
		{"set_field", field("retest_result", "maybe")},
		{"set_field", field("assets", "{")},
		{"set_field", field("assets", `[{"host":"h","port":"x"}]`)},
		{"set_field", field("status", "complete")},
		{"set_field", field("colour", "red")},
		{"transition", fd(map[string]any{"action": "bogus"})},
		{"transition", fd(map[string]any{"action": "withdraw"})},
		{"add_chat_message", fd(map[string]any{"text": " "})},
		{"add_chat_message", fd(map[string]any{"text": "x", "section": "Nope"})},
		{"resolve_thread", fd(map[string]any{"thread": " "})},
		{"resolve_thread", fd(map[string]any{"thread": "nope"})},
		{"mark_notifications_read", map[string]any{}},
		{"mark_notifications_read", map[string]any{"ids": "x"}},
		{"read_template", map[string]any{"template": " "}},
		{"list_history", fd(map[string]any{"limit": "999"})},
	} {
		text, isErr := f.call(alice, c.tool, c.args)
		if m := object(t, c.tool, text); !isErr || m["code"] != "invalid" {
			t.Errorf("%s %v: %s", c.tool, c.args, text)
		}
	}
}

// serverLog collects what s logs from now on.
func serverLog(s *Server) *logs.Recorder {
	lg, rec := logs.NewRecorder()
	s.Logger = lg
	return rec
}

// failure is the one record of tool failing for user in what the server
// logged, and whether there is exactly one.
func failure(rec *logs.Recorder, msg, tool, user string) (logs.Record, bool) {
	var got []logs.Record
	for _, r := range rec.With(msg) {
		if r.Str("tool") == tool && r.Str("user") == user {
			got = append(got, r)
		}
	}
	if len(got) != 1 {
		return logs.Record{}, false
	}
	return got[0], true
}

// Q9: a failure of the server itself (its database closed under it, a data
// folder it may not write) is server_error. The caller gets "internal
// error" and no word of the failure (a path of the server, a statement of
// its database); the server's log has them (pre1 2.29).
func TestServerFailureIsServerError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only folder")
	}
	f := newFx(t)
	logged := serverLog(f.s)
	dir := filepath.Join(f.dir, "engagements", "acme", "findings", "F-001-sql-injection")
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	text, isErr := f.call(alice, "update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact", "body": "x"})
	if m := object(t, "read-only", text); !isErr || m["code"] != "server_error" || m["message"] != "internal error" {
		t.Fatalf("read-only folder: %s", text)
	}
	if strings.Contains(text, "permission denied") || strings.Contains(text, f.dir) || strings.Contains(text, "yars-tmp") {
		t.Fatalf("the answer has the server's words: %s", text)
	}
	if r, ok := failure(logged, "mcp: a tool failed", "update_section", "alice"); !ok || !strings.Contains(r.Str("err"), "permission denied") || r.Level != slog.LevelError {
		t.Fatalf("the log lacks the failure: %q", logged.Text())
	}
	os.Chmod(dir, 0o755)

	f.s.Store.DB().Close()
	for _, c := range []struct {
		u    config.User
		tool string
		args map[string]any
	}{
		{alice, "list_notifications", map[string]any{}},
		{alice, "mark_notifications_read", map[string]any{"all": true}},
		{alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"}}, // the team check
		{dora, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"}},
		{dora, "add_chat_message", map[string]any{"engagement": "acme", "finding": "F-001", "text": "x"}},
	} {
		logged.Reset()
		text, isErr := f.call(c.u, c.tool, c.args)
		if m := object(t, c.tool, text); !isErr || m["code"] != "server_error" || m["message"] != "internal error" || strings.Contains(text, "closed") {
			t.Errorf("%s with the database closed: %s", c.tool, text)
		}
		if r, ok := failure(logged, "mcp: a tool failed", c.tool, c.u.Username); !ok || !strings.Contains(r.Str("err"), "closed") {
			t.Errorf("%s with the database closed: the log has %q", c.tool, logged.Text())
		}
	}
}

// read_finding lists each action with the reason it is not open. When the
// server cannot work that out (its database fails), the reason is "internal
// error", not the database's words, and the log has them (pre1 2.29).
func TestAllowedActionsHideServerErrors(t *testing.T) {
	f := newFx(t)
	logged := serverLog(f.s)
	// alice's own draft, ready to submit but for a rule's error: Submit's
	// gate reads the dismissals
	rd := filepath.Join(t.TempDir(), "rules")
	os.MkdirAll(rd, 0o755)
	os.WriteFile(filepath.Join(rd, "style.yaml"), []byte("- id: hard\n  target: title\n  regex_forbid: 'SQL'\n  level: error\n  message: say what SQL means\n"), 0o644)
	f.s.Store.Linter = rules.NewEngine(rd, config.Default())
	f.ok(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "reviewers", "value": "bob"})
	f.ok(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "severity", "value": "high"})
	if _, err := f.s.Store.DB().Exec("ALTER TABLE dismissals RENAME TO dismissals_away"); err != nil {
		t.Fatal(err)
	}
	text, isErr := f.call(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})
	if isErr {
		t.Fatalf("read_finding: %s", text)
	}
	if strings.Contains(text, "dismissals") || strings.Contains(text, "SQL logic") || strings.Contains(text, "no such table") {
		t.Fatalf("the answer has the database's words: %s", text)
	}
	if !strings.Contains(text, `"reason":"internal error"`) {
		t.Fatalf("no action says internal error: %s", text)
	}
	recs := logged.With("mcp: a finding's allowed action is not worked out")
	if len(recs) == 0 || recs[0].Str("tool") != "read_finding" || recs[0].Str("user") != "alice" || recs[0].Str("eng") != "acme" ||
		recs[0].Str("finding") != "F-001" || !strings.Contains(recs[0].Str("err"), "dismissals") {
		t.Fatalf("the log lacks the failure: %q", logged.Text())
	}
}

// Q9: a team read that fails is the server's failure, not an engagement
// the caller is not on (not_found) nor a name that is no reviewer (invalid).
func TestTeamReadFailureIsServerError(t *testing.T) {
	f := newFx(t)
	if _, err := f.s.Store.DB().Exec("ALTER TABLE engagement_members RENAME TO engagement_members_away"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		u    config.User
		tool string
		args map[string]any
	}{
		{alice, "list_findings", map[string]any{"engagement": "acme"}},
		{dora, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "reviewers", "value": "bob"}},
	} {
		text, isErr := f.call(c.u, c.tool, c.args)
		if m := object(t, c.tool, text); !isErr || m["code"] != "server_error" || m["message"] != "internal error" || strings.Contains(text, "engagement_members") {
			t.Errorf("%s as %s with the team unreadable: %s", c.tool, c.u.Username, text)
		}
	}
	if ref, _ := f.s.Store.Finding("acme", "001"); len(ref.F.Meta.Reviewers) != 0 {
		t.Fatalf("reviewers set anyway: %v", ref.F.Meta.Reviewers)
	}
}

// A revert with nothing to revert is refused as reopen and unreport are
// (not_allowed); a missing reason is a missing argument (invalid), once the
// role and status allow the action.
func TestTransitionRefusalCodes(t *testing.T) {
	f := newFx(t)
	tr := func(u config.User, act, reason string) map[string]any {
		text, _ := f.call(u, "transition", map[string]any{"engagement": "acme", "finding": "F-001", "action": act, "reason": reason})
		return object(t, act, text)
	}
	for _, act := range []string{"revert", "reopen"} {
		if m := tr(alice, act, "x"); m["code"] != "not_allowed" {
			t.Errorf("%s on a draft: %v", act, m)
		}
	}
	if m := tr(alice, "withdraw", ""); m["code"] != "invalid" || m["message"] != "a reason is required to withdraw a finding" {
		t.Errorf("withdraw without a reason: %v", m)
	}
	// not allowed at all comes first
	if m := tr(pen2, "withdraw", ""); m["code"] != "not_allowed" {
		t.Errorf("withdraw by another pentester: %v", m)
	}
	// the store's cap on a reason holds for an agent too
	text, isErr := f.call(alice, "transition", map[string]any{"engagement": "acme", "finding": "F-001", "action": "withdraw", "reason": strings.Repeat("x", store.MaxReason+1)})
	if m := object(t, "withdraw", text); !isErr || !strings.Contains(m["message"].(string), "the reason is longer than 4000 characters") {
		t.Errorf("withdraw with a reason over the cap: %s", text)
	}
	if ref, _ := f.s.Store.Finding("acme", "001"); ref.F.Meta.Status != "draft" {
		t.Errorf("a refused withdraw moved it to %s", ref.F.Meta.Status)
	}
}

// ok splices into an object only: {} is {"ok":true}; a list or a value is
// an error.
func TestOKOnlyObjects(t *testing.T) {
	if got, err := ok(struct{}{}); err != nil || got != `{"ok":true}` {
		t.Fatalf("%q %v", got, err)
	}
	for _, v := range []any{[]int{}, 3, "x"} {
		if _, err := ok(v); err == nil {
			t.Errorf("ok(%v) accepted", v)
		}
	}
}

// Lists are {"ok": true, "items": […], "next": ""}.
func TestListsHaveItemsAndNext(t *testing.T) {
	f := newFx(t)
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"list_engagements", map[string]any{}},
		{"list_findings", map[string]any{"engagement": "acme"}},
		{"list_templates", map[string]any{}},
		{"list_notifications", map[string]any{}},
		{"lint_finding", map[string]any{"engagement": "acme", "finding": "F-001"}},
	} {
		m := object(t, c.tool, f.ok(alice, c.tool, c.args))
		if _, ok := m["items"].([]any); !ok || m["next"] != "" || m["ok"] != true {
			t.Errorf("%s: %v", c.tool, m)
		}
	}
}
