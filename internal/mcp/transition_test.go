package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/rules"
	"yars/internal/workflow"
)

// stale is the answer to a base the finding has changed since.
const stale = "the finding changed since you read it; read_finding again and retry"

// baseFx is f with what TestTransitionBase* call: the finding's hash as u
// reads it, a transition with base, and the finding's status.
func baseFx(t *testing.T, f *fx) (hash func(config.User) string, tr func(u config.User, act, base string) (map[string]any, bool), status func() string) {
	fd := map[string]any{"engagement": "acme", "finding": "F-001"}
	hash = func(u config.User) string {
		var rd struct {
			Hash string `json:"hash"`
		}
		json.Unmarshal([]byte(f.ok(u, "read_finding", fd)), &rd)
		return rd.Hash
	}
	tr = func(u config.User, act, base string) (map[string]any, bool) {
		text, isErr := f.call(u, "transition", map[string]any{"engagement": "acme", "finding": "F-001", "action": act, "base": base})
		return object(t, act, text), isErr
	}
	status = func() string {
		ref, err := f.s.Store.Finding("acme", "001")
		if err != nil {
			t.Fatal(err)
		}
		return ref.F.Meta.Status
	}
	return hash, tr, status
}

// Q10: read_finding gives the whole finding's hash; transition takes it as
// base, and a sign-off or an approval of content changed since is refused
// (conflict), as the website refuses it. Other actions ignore it.
func TestTransitionBase(t *testing.T) {
	f := stateFx(t, "verification")
	hash, tr, status := baseFx(t, f)
	h1 := hash(dora)
	if ref, _ := f.s.Store.Finding("acme", "001"); h1 == "" || h1 != ref.Hash {
		t.Fatalf("hash %q, the finding's %q", h1, ref.Hash)
	}
	// the author edits after the director and the reviewer read it
	f.ok(alice, "update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact", "body": "Changed after the read."})
	if m, isErr := tr(bob, "sign_off", h1); !isErr || m["code"] != "conflict" || m["message"] != stale {
		t.Fatalf("sign_off of a changed finding: %v", m)
	}
	if ref, _ := f.s.Store.Finding("acme", "001"); len(ref.F.Meta.ClearedBy) != 0 {
		t.Fatalf("signed off anyway: %v", ref.F.Meta.ClearedBy)
	}
	h2 := hash(bob)
	if h2 == h1 {
		t.Fatal("the hash did not change with the content")
	}
	if m, isErr := tr(bob, "clear", h2); isErr {
		t.Fatalf("clear with the current hash: %v", m)
	}
	// the director read the version before the edit: not approved
	if m, isErr := tr(dora, "approve", h1); !isErr || m["code"] != "conflict" || m["message"] != stale || status() != "verification" {
		t.Fatalf("approve of a changed finding: %v (%s)", m, status())
	}
	if m, isErr := tr(dora, "approve", hash(dora)); isErr || status() != "complete" {
		t.Fatalf("approve with the current hash: %v", m)
	}
	// another action ignores base, as on the website
	if m, isErr := tr(dora, "report", "stale"); isErr || status() != "reported" {
		t.Fatalf("report with a base: %v", m)
	}
	// without base: as before, the finding as it is
	g := stateFx(t, "verification")
	g.ok(bob, "transition", map[string]any{"engagement": "acme", "finding": "F-001", "action": "clear"})
	// the tool says so
	tl := toolByName["transition"]
	if len(tl.optional) != 2 || tl.optional[1].name != "base" || !strings.Contains(tl.optional[1].desc, "hash") ||
		!strings.Contains(toolByName["read_finding"].desc, "hash") {
		t.Fatalf("transition %+v", tl.optional)
	}
}

// The author marks their own complete finding reported over MCP, as on the
// finding page and the bulk bar: an agent follows its account's rules, which
// the workflow decides. Another pentester is refused with the workflow's own
// message; read_finding lists the action the same way.
func TestTransitionReportByAuthor(t *testing.T) {
	f := stateFx(t, "complete")
	_, tr, status := baseFx(t, f)
	listed := func(u config.User) workflow.Allowed {
		var rd struct {
			Allowed []workflow.Allowed `json:"allowed_actions"`
		}
		json.Unmarshal([]byte(f.ok(u, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})), &rd)
		for _, al := range rd.Allowed {
			if al.Action == "report" {
				return al
			}
		}
		t.Fatalf("%s: report not listed: %+v", u.Username, rd.Allowed)
		return workflow.Allowed{}
	}
	const other = "only the author or a director can mark a finding reported"
	if al := listed(pen2); al.Enabled || al.Reason != other {
		t.Fatalf("report listed for another pentester: %+v", al)
	}
	if m, isErr := tr(pen2, "report", ""); !isErr || m["code"] != "not_allowed" || !strings.HasSuffix(m["message"].(string), other) || status() != "complete" {
		t.Fatalf("report by another pentester: %v (%s)", m, status())
	}
	if al := listed(alice); !al.Enabled {
		t.Fatalf("report not enabled for the author: %+v", al)
	}
	if m, isErr := tr(alice, "report", ""); isErr || status() != "reported" {
		t.Fatalf("report by the author: %v (%s)", m, status())
	}
	if d := toolByName["transition"].desc; strings.Contains(d, "report (director") || !strings.Contains(d, "report (author or director: complete→reported)") {
		t.Fatalf("transition says: %s", d)
	}
}

// Q10 as a server runs it, with style rules and Require Check on: a stale
// base is a conflict before the checks (not "run check first" on content
// never read, not a refusal of the gate).
func TestTransitionBaseWithChecks(t *testing.T) {
	f := stateFx(t, "verification")
	rd := filepath.Join(f.dir, ".yars", "rules")
	os.MkdirAll(rd, 0o755)
	os.WriteFile(filepath.Join(rd, "r.yaml"), []byte("- id: none\n  target: title\n  regex_forbid: 'zzz'\n"), 0o644)
	eng := rules.NewEngine(rd, f.s.Cfg)
	f.s.Rules, f.s.Store.Linter = eng, eng
	if !f.s.Store.RequireCheck() {
		t.Fatal("Require Check off")
	}
	hash, tr, status := baseFx(t, f)
	h1 := hash(bob)
	f.ok(alice, "update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact", "body": "Changed after the read."})
	for _, c := range []struct {
		u   config.User
		act string
	}{{bob, "sign_off"}, {dora, "approve"}} {
		if m, isErr := tr(c.u, c.act, h1); !isErr || m["code"] != "conflict" || m["message"] != stale {
			t.Fatalf("%s of a changed finding: %v", c.act, m)
		}
	}
	if ref, _ := f.s.Store.Finding("acme", "001"); len(ref.F.Meta.ClearedBy) != 0 || status() != "verification" {
		t.Fatalf("changed anyway: %v (%s)", ref.F.Meta.ClearedBy, status())
	}
	// checked, the version read now passes
	f.ok(bob, "start_check", map[string]any{"engagement": "acme", "finding": "F-001"})
	f.s.Store.WaitChecks()
	if m, isErr := tr(bob, "sign_off", hash(bob)); isErr {
		t.Fatalf("sign_off with the current hash: %v", m)
	}
	if m, isErr := tr(dora, "approve", hash(dora)); isErr || status() != "complete" {
		t.Fatalf("approve with the current hash: %v", m)
	}
}
