package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"yars/internal/config"
)

// Q10: read_finding gives the whole finding's hash; transition takes it as
// base, and a sign-off or an approval of content changed since is refused
// (conflict), as the website refuses it. Other actions ignore it.
func TestTransitionBase(t *testing.T) {
	f := stateFx(t, "verification")
	fd := map[string]any{"engagement": "acme", "finding": "F-001"}
	hash := func(u config.User) string {
		var rd struct {
			Hash string `json:"hash"`
		}
		json.Unmarshal([]byte(f.ok(u, "read_finding", fd)), &rd)
		return rd.Hash
	}
	tr := func(u config.User, act, base string) (map[string]any, bool) {
		text, isErr := f.call(u, "transition", map[string]any{"engagement": "acme", "finding": "F-001", "action": act, "base": base})
		return object(t, act, text), isErr
	}
	status := func() string {
		ref, err := f.s.Store.Finding("acme", "001")
		if err != nil {
			t.Fatal(err)
		}
		return ref.F.Meta.Status
	}
	h1 := hash(dora)
	if ref, _ := f.s.Store.Finding("acme", "001"); h1 == "" || h1 != ref.Hash {
		t.Fatalf("hash %q, the finding's %q", h1, ref.Hash)
	}
	// the author edits after the director and the reviewer read it
	f.ok(alice, "update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact", "body": "Changed after the read."})
	if m, isErr := tr(bob, "sign_off", h1); !isErr || m["code"] != "conflict" || !strings.Contains(m["message"].(string), "changed since") {
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
	if m, isErr := tr(dora, "approve", h1); !isErr || m["code"] != "conflict" || status() != "verification" {
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
