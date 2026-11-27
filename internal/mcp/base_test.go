package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/workflow"
)

// pre1 6.1: a sign-off, an approval and the simple workflow's completion need
// base, the hash read_finding gave: without it (or with a blank one) the call
// is refused as a missing argument that names base and read_finding, and
// nothing is signed. The actions that sign nothing need none. What refuses
// the action anyway comes first: a clone, the archive, the role, an action
// the workflow lacks.
func TestTransitionNeedsBase(t *testing.T) {
	fd := func(act string, kv ...string) map[string]any {
		m := map[string]any{"engagement": "acme", "finding": "F-001", "action": act}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	needsBase := func(f *fx, u config.User, a map[string]any) string {
		t.Helper()
		text, isErr := f.bare(u, "transition", a)
		m := object(t, "transition", text)
		msg, _ := m["message"].(string)
		if !isErr || m["code"] != "invalid" || !strings.HasPrefix(msg, `missing argument "base"`) || !strings.Contains(msg, "read_finding") {
			t.Errorf("%s %v: %s", u.Username, a, text)
		}
		return msg
	}
	refused := func(f *fx, u config.User, a map[string]any, code, says string) {
		t.Helper()
		text, isErr := f.bare(u, "transition", a)
		if m := object(t, "transition", text); !isErr || m["code"] != code || !strings.Contains(message(t, text), says) || strings.Contains(text, `"base"`) {
			t.Errorf("%s %v: %s, want %s (%s)", u.Username, a, text, code, says)
		}
	}
	meta := func(f *fx) (status string, cleared []string) {
		ref, err := f.s.Store.Finding("acme", "001")
		if err != nil {
			t.Fatal(err)
		}
		return ref.F.Meta.Status, ref.F.Meta.ClearedBy
	}

	f := stateFx(t, "verification")
	for _, a := range []map[string]any{fd("clear"), fd("sign_off"), fd("clear", "base", ""), fd("sign_off", "base", "  ")} {
		needsBase(f, bob, a)
	}
	if _, cleared := meta(f); len(cleared) != 0 {
		t.Fatalf("signed off without a base: %v", cleared)
	}
	g := stateFx(t, "cleared")
	needsBase(g, dora, fd("approve"))
	if st, _ := meta(g); st != "verification" {
		t.Fatalf("approved without a base: %s", st)
	}
	s := simpleStateFx(t, "ready")
	if msg := needsBase(s, ben, f001("action", "complete")); standardWords.MatchString(msg) {
		t.Errorf("the simple workflow's refusal: %q", msg)
	}
	if st, _ := simpleRead(t, s); st != "draft" {
		t.Fatalf("completed without a base: %s", st)
	}

	// what signs nothing needs no base
	for _, c := range []struct {
		state string
		u     config.User
		act   string
	}{{"ready", alice, "submit"}, {"verification", bob, "return"}, {"verification", alice, "take_back"}, {"verification", alice, "withdraw"},
		{"complete", alice, "report"}, {"complete", dora, "reopen"}, {"reported", dora, "revert"}, {"withdrawn", alice, "revise"}} {
		if text, isErr := stateFx(t, c.state).bare(c.u, "transition", fd(c.act, "reason", "because")); isErr {
			t.Errorf("%s without a base: %s", c.act, text)
		}
	}

	// what refuses the action anyway is said first, and names no base
	refused(cloneOf(t, stateFx(t, "verification")), bob, fd("clear"), "no_database", "")
	arch := stateFx(t, "verification")
	if err := arch.s.Store.Archive("acme", dora); err != nil {
		t.Fatal(err)
	}
	refused(arch, bob, fd("clear"), "archived", "archived")
	refused(f, pen2, fd("clear"), "not_allowed", "only an assigned reviewer or a director can clear")
	refused(g, pen2, fd("approve"), "not_allowed", "director")
	refused(stateFx(t, "ready"), dora, fd("approve"), "not_allowed", "")
	refused(f, dora, fd("complete"), "invalid", "unknown action")
	refused(s, ben, f001("action", "approve"), "not_allowed", "is not part of the simple workflow")

	// read_finding says which actions need it
	needs := func(f *fx, u config.User) map[string]string {
		var rd struct {
			Allowed []workflow.Allowed `json:"allowed_actions"`
		}
		json.Unmarshal([]byte(f.ok(u, "read_finding", f001())), &rd)
		out := map[string]string{}
		for _, al := range rd.Allowed {
			out[al.Action] = al.Needs
		}
		return out
	}
	if n := needs(f, bob); n["clear"] != "base" || n["return"] != "reason" {
		t.Errorf("verification: %v", n)
	}
	if n := needs(g, dora); n["approve"] != "base" {
		t.Errorf("cleared: %v", n)
	}
	if n := needs(s, ben); n["complete"] != "base" || n["withdraw"] != "reason" {
		t.Errorf("simple: %v", n)
	}

	// the tools say it, in each workflow's words
	for _, fl := range []workflow.Flow{{}, {Simple: true}} {
		tl := toolByName["transition"].in(fl)
		base := tl.optional[1]
		if base.name != "base" || !strings.Contains(base.desc, "required for") || !strings.Contains(tl.desc, "refused without it") ||
			!strings.Contains(instructionsFor(fl), "without base") {
			t.Errorf("simple %v: transition %q, base %q", fl.Simple, tl.desc, base.desc)
		}
	}
}

// pre1 6.1: read_finding gives attachments_hash; transition takes it as
// attachments_base, and a sign-off of a finding whose attachments changed
// since is a conflict, as on the website. Without it the files are not
// compared.
func TestTransitionAttachmentsBase(t *testing.T) {
	f := stateFx(t, "verification")
	read := func() (hash, files string) {
		var rd struct {
			Hash  string `json:"hash"`
			Files string `json:"attachments_hash"`
		}
		json.Unmarshal([]byte(f.ok(bob, "read_finding", f001())), &rd)
		return rd.Hash, rd.Files
	}
	hash, files := read()
	if files == "" {
		t.Fatal("read_finding gives no attachments_hash")
	}
	if _, err := f.s.Store.AddAttachment("acme", "F-001-sql-injection", "notes.txt", []byte("hello"), alice); err != nil {
		t.Fatal(err)
	}
	if h, now := read(); h != hash || now == files {
		t.Fatalf("after an upload: hash %v, attachments_hash changed %v", h == hash, now != files)
	}
	text, isErr := f.bare(bob, "transition", f001("action", "clear", "base", hash, "attachments_base", files))
	if m := object(t, "clear", text); !isErr || m["code"] != "conflict" || m["message"] != stale {
		t.Fatalf("clear with the attachments of before: %s", text)
	}
	if ref, _ := f.s.Store.Finding("acme", "001"); len(ref.F.Meta.ClearedBy) != 0 {
		t.Fatalf("signed off anyway: %v", ref.F.Meta.ClearedBy)
	}
	_, files = read()
	if text, isErr := f.bare(bob, "transition", f001("action", "clear", "base", hash, "attachments_base", files)); isErr {
		t.Fatalf("clear with the current attachments: %s", text)
	}
	// without it: finding.md's hash alone
	g := stateFx(t, "verification")
	if text, isErr := g.bare(bob, "transition", f001("action", "clear", "base", hash)); isErr {
		t.Fatalf("clear without attachments_base: %s", text)
	}
}
