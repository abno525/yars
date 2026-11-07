package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// P1-03 exactly: read_finding once, then every edit with the SAME
// details_base / cvss_base. Each is checked against its own row only.
func TestMCPSameGroupBaseEveryEdit(t *testing.T) {
	f := newFx(t)
	args := func(field, value, base string) map[string]any {
		return map[string]any{"engagement": "acme", "finding": "F-001", "field": field, "value": value, "base": base}
	}
	f.ok(alice, "set_field", args("cvss", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", ""))
	var rd struct {
		CVSSBase    string `json:"cvss_base"`
		DetailsBase string `json:"details_base"`
	}
	json.Unmarshal([]byte(f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})), &rd)
	f.ok(alice, "set_field", args("details.Location", "POST /login", rd.DetailsBase))
	f.ok(alice, "set_field", args("details.Cause", "no escaping", rd.DetailsBase))
	f.ok(alice, "set_field", args("details.Result", "data read", rd.DetailsBase))
	f.ok(alice, "set_field", args("cvss_reason.AC", "needs a race", rd.CVSSBase))
	f.ok(alice, "set_field", args("cvss_reason.AV", "internet", rd.CVSSBase))
	// a row edited twice with the first read's base: the second is refused
	if text, isErr := f.call(alice, "set_field", args("details.Location", "GET /", rd.DetailsBase)); !isErr || !strings.Contains(text, "changed since you read it") {
		t.Fatalf("same row twice: %v %s", isErr, text)
	}
	if text, isErr := f.call(alice, "set_field", args("cvss_reason.AC", "x", rd.CVSSBase)); !isErr || !strings.Contains(text, "changed since you read it") {
		t.Fatalf("same reason twice: %v %s", isErr, text)
	}
}

// D14, the DeepSeek case: one read_finding, then several Details rows and
// CVSS reasons edited one after another, each with its own field_bases
// entry. Nobody else touched the finding, so none is refused; a stale base
// of the same row is, with a message that blames nobody.
func TestMCPRowEditsOneAfterAnother(t *testing.T) {
	f := newFx(t)
	args := func(field, value, base string) map[string]any {
		return map[string]any{"engagement": "acme", "finding": "F-001", "field": field, "value": value, "base": base}
	}
	f.ok(alice, "set_field", args("cvss", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", ""))
	var rd struct {
		Bases map[string]string `json:"field_bases"`
	}
	json.Unmarshal([]byte(f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})), &rd)
	for _, k := range []string{"details.Location", "details.Cause", "cvss", "cvss_reason.AC"} {
		if rd.Bases[k] == "" {
			t.Fatalf("no base for %s: %v", k, rd.Bases)
		}
	}
	first := f.ok(alice, "set_field", args("details.Location", "POST /login", rd.Bases["details.Location"]))
	f.ok(alice, "set_field", args("details.Cause", "no escaping", rd.Bases["details.Cause"]))
	f.ok(alice, "set_field", args("cvss_reason.AC", "needs a race", rd.Bases["cvss_reason.AC"]))
	f.ok(alice, "set_field", args("cvss_reason.AV", "reachable from the internet", rd.Bases["cvss_reason.AV"]))
	// the same row again with the first read's base: refused
	text, isErr := f.call(alice, "set_field", args("details.Location", "GET /", rd.Bases["details.Location"]))
	if !isErr || !strings.Contains(text, "changed since you read it") || strings.Contains(text, "someone") {
		t.Fatalf("stale row: %v %s", isErr, text)
	}
	// with the base the first edit returned: fine
	_, nb, _ := strings.Cut(first, "new base ")
	if nb == "" {
		t.Fatalf("no new base in %q", first)
	}
	f.ok(alice, "set_field", args("details.Location", "GET /", nb))
	ref, _ := f.s.Store.Finding("acme", "001")
	m := ref.F.Meta
	if m.Details["Location"] != "GET /" || m.Details["Cause"] != "no escaping" || m.CVSSReasons["AC"] != "needs a race" || m.CVSSReasons["AV"] == "" {
		t.Fatalf("meta %v %v", m.Details, m.CVSSReasons)
	}
}
