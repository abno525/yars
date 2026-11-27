package mcp

import (
	"encoding/json"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/store"
)

// fieldFx is what the field-base tests call on f's finding F-001 of
// engagement eng: read_finding's field_bases and details_base, and a
// set_field with a base ("" sends none).
func fieldFx(t *testing.T, f *fx, eng string) (bases func(config.User) (map[string]string, string), set func(u config.User, field, value, base string) (map[string]any, bool)) {
	bases = func(u config.User) (map[string]string, string) {
		var rd struct {
			Bases       map[string]string `json:"field_bases"`
			DetailsBase string            `json:"details_base"`
		}
		json.Unmarshal([]byte(f.ok(u, "read_finding", map[string]any{"engagement": eng, "finding": "F-001"})), &rd)
		return rd.Bases, rd.DetailsBase
	}
	set = func(u config.User, field, value, base string) (map[string]any, bool) {
		a := map[string]any{"engagement": eng, "finding": "F-001", "field": field, "value": value}
		if base != "" {
			a["base"] = base
		}
		text, isErr := f.call(u, "set_field", a)
		return object(t, field, text), isErr
	}
	return bases, set
}

// pre1 6.2: read_finding gives a base for the title and the severity, and
// set_field with it is refused (conflict) when the field changed since, so
// an agent does not overwrite what a colleague set meanwhile. The answer
// has the new base. Without a base, or with a group's token, the edit is
// not checked.
func TestMCPTitleAndSeverityBase(t *testing.T) {
	for _, c := range []struct {
		field, theirs, mine string
		stored              func(*fx) string
	}{
		{"title", "Dora's title", "Alice's title", func(f *fx) string {
			ref, _ := f.s.Store.Finding("acme", "001")
			return ref.F.Meta.Title
		}},
		{"severity", "high", "low", func(f *fx) string {
			ref, _ := f.s.Store.Finding("acme", "001")
			return ref.F.Meta.Severity
		}},
	} {
		f := newFx(t)
		bases, set := fieldFx(t, f, "acme")
		read, group := bases(alice)
		old := read[c.field]
		if old == "" {
			t.Fatalf("%s: no base in field_bases: %v", c.field, read)
		}
		if m, isErr := set(dora, c.field, c.theirs, ""); isErr {
			t.Fatalf("%s by dora: %v", c.field, m)
		}
		if m, isErr := set(alice, c.field, c.mine, old); !isErr || m["code"] != "conflict" || m["message"] != stale || c.stored(f) != c.theirs {
			t.Fatalf("%s with the base of before: %v (stored %q)", c.field, m, c.stored(f))
		}
		now, _ := bases(alice)
		m, isErr := set(alice, c.field, c.mine, now[c.field])
		if isErr || c.stored(f) != c.mine {
			t.Fatalf("%s with the current base: %v (stored %q)", c.field, m, c.stored(f))
		}
		if after, _ := bases(alice); m["base"] == nil || m["base"] != after[c.field] || after[c.field] == now[c.field] {
			t.Fatalf("%s: the answer's base %v, read_finding's %q", c.field, m["base"], after[c.field])
		}
		// a group's token (sent with every edit) holds no entry for it
		if m, isErr := set(dora, c.field, c.theirs, group); isErr || c.stored(f) != c.theirs {
			t.Fatalf("%s with details_base: %v", c.field, m)
		}
		if m, isErr := set(alice, c.field, c.mine, ""); isErr || c.stored(f) != c.mine {
			t.Fatalf("%s without a base: %v", c.field, m)
		}
	}
}

// pre1 6.2: the same for a retest finding's result. A finding that is no
// retest has no base for it.
func TestMCPRetestResultBase(t *testing.T) {
	f := stateFx(t, "complete")
	if read, _ := func() (map[string]string, string) { b, _ := fieldFx(t, f, "acme"); return b(alice) }(); read["retest_result"] != "" {
		t.Fatalf("a base for the result of a finding that is no retest: %v", read)
	}
	if err := f.s.Store.CreateRetest(store.Engagement{ID: "rt", Name: "RT"}, "acme", []string{"F-001-sql-injection"}, "", dora); err != nil {
		t.Fatal(err)
	}
	f.s.Store.DB().AddMembers("rt", "alice")
	bases, set := fieldFx(t, f, "rt")
	result := func() string {
		ref, err := f.s.Store.Finding("rt", "001")
		if err != nil || ref.F.Meta.Retest == nil {
			t.Fatalf("retest finding: %v", err)
		}
		return ref.F.Meta.Retest.Result
	}
	read, group := bases(alice)
	old := read["retest_result"]
	if old == "" {
		t.Fatalf("no base in field_bases: %v", read)
	}
	if m, isErr := set(dora, "retest_result", "fixed", ""); isErr {
		t.Fatalf("by dora: %v", m)
	}
	if m, isErr := set(alice, "retest_result", "not_fixed", old); !isErr || m["code"] != "conflict" || m["message"] != stale || result() != "fixed" {
		t.Fatalf("with the base of before: %v (stored %q)", m, result())
	}
	// the result it has already: a repeated call, no conflict
	if m, isErr := set(alice, "retest_result", "fixed", old); isErr {
		t.Fatalf("the result it has, with the base of before: %v", m)
	}
	now, _ := bases(alice)
	m, isErr := set(alice, "retest_result", "not_fixed", now["retest_result"])
	if isErr || result() != "not_fixed" {
		t.Fatalf("with the current base: %v (stored %q)", m, result())
	}
	if after, _ := bases(alice); m["base"] == nil || m["base"] != after["retest_result"] {
		t.Fatalf("the answer's base %v, read_finding's %q", m["base"], after["retest_result"])
	}
	if m, isErr := set(dora, "retest_result", "partially_fixed", group); isErr || result() != "partially_fixed" {
		t.Fatalf("with details_base: %v", m)
	}
	if m, isErr := set(alice, "retest_result", "fixed", ""); isErr || result() != "fixed" {
		t.Fatalf("without a base: %v", m)
	}
}
