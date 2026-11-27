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

// D14: a vector edit returns the new bases of the vector and of every
// reason (a reason's base covers its metric's value), so the reason of the
// metric just changed can be set next without reading the finding again.
func TestMCPReasonAfterVectorEdit(t *testing.T) {
	f := newFx(t)
	args := func(field, value, base string) map[string]any {
		return map[string]any{"engagement": "acme", "finding": "F-001", "field": field, "value": value, "base": base}
	}
	f.ok(alice, "set_field", args("cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", ""))
	var rd struct {
		CVSSBase string `json:"cvss_base"`
	}
	json.Unmarshal([]byte(f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})), &rd)
	out := f.ok(alice, "set_field", args("cvss", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", rd.CVSSBase))
	nb, _ := object(t, "set_field", out)["base"].(string)
	if _, inMsg, _ := strings.Cut(message(t, out), "new base "); nb == "" || inMsg != nb {
		t.Fatalf("no new base in %q", out)
	}
	f.ok(alice, "set_field", args("cvss_reason.AC", "needs a race", nb))
	f.ok(alice, "set_field", args("cvss_reason.AV", "internet", nb))
	// the vector again with it: fine, nobody changed the vector since
	f.ok(alice, "set_field", args("cvss", "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N", nb))
	// the reason edited again with that token: it changed since
	if text, isErr := f.call(alice, "set_field", args("cvss_reason.AC", "x", nb)); !isErr || !strings.Contains(text, "changed since you read it") {
		t.Fatalf("same reason twice: %v %s", isErr, text)
	}
	ref, _ := f.s.Store.Finding("acme", "001")
	if m := ref.F.Meta; m.CVSSReasons["AC"] != "needs a race" || m.CVSSReasons["AV"] != "internet" {
		t.Fatalf("reasons %v", m.CVSSReasons)
	}
}

// A CVSS:3.0 vector is taken and stored as the 3.1 vector of the same
// metrics, and the answer says so; a 3.1 vector's answer does not.
func TestMCPCVSS30StoredAs31IsSaid(t *testing.T) {
	f := newFx(t)
	args := func(value string) map[string]any {
		return map[string]any{"engagement": "acme", "finding": "F-001", "field": "cvss", "value": value}
	}
	const v31 = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
	out := f.ok(alice, "set_field", args("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"))
	if ref, _ := f.s.Store.Finding("acme", "001"); ref.F.Meta.CVSS != v31 {
		t.Fatalf("stored %q", ref.F.Meta.CVSS)
	}
	msg := message(t, out)
	if !strings.Contains(msg, "CVSS:3.0") || !strings.Contains(msg, "stored as "+v31) {
		t.Fatalf("the answer does not say the vector was rewritten: %q", msg)
	}
	// the new base is still the end of the message
	nb, _ := object(t, "set_field", out)["base"].(string)
	if _, inMsg, _ := strings.Cut(msg, "new base "); nb == "" || inMsg != nb {
		t.Fatalf("no new base in %q", out)
	}
	if msg := message(t, f.ok(alice, "set_field", args(v31))); strings.Contains(msg, "stored as") {
		t.Fatalf("a 3.1 vector's answer: %q", msg)
	}
}

// A vector edit that changes a metric removes that metric's reason (it
// explained the old value) and keeps the others; the base the answer gives
// is the one of the emptied row, so the new reason is set with it. Clearing
// the vector removes every reason.
func TestMCPVectorEditDropsStaleReason(t *testing.T) {
	f := newFx(t)
	args := func(field, value, base string) map[string]any {
		return map[string]any{"engagement": "acme", "finding": "F-001", "field": field, "value": value, "base": base}
	}
	f.ok(alice, "set_field", args("cvss", "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:N", ""))
	f.ok(alice, "set_field", args("cvss_reason.PR", "a low account is enough", ""))
	f.ok(alice, "set_field", args("cvss_reason.AC", "needs a race", ""))
	out := f.ok(alice, "set_field", args("cvss", "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N", ""))
	var rd struct {
		Reasons map[string]string `json:"cvss_reasons"`
	}
	json.Unmarshal([]byte(f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})), &rd)
	ref, _ := f.s.Store.Finding("acme", "001")
	if m := ref.F.Meta; m.CVSSReasons["PR"] != "" || m.CVSSReasons["AC"] != "needs a race" || rd.Reasons["PR"] != "" {
		t.Fatalf("reasons after PR:L to PR:H: %v (read_finding %v)", m.CVSSReasons, rd.Reasons)
	}
	nb, _ := object(t, "set_field", out)["base"].(string)
	f.ok(alice, "set_field", args("cvss_reason.PR", "an admin account is needed", nb))
	f.ok(alice, "set_field", args("cvss", "", ""))
	if ref, _ := f.s.Store.Finding("acme", "001"); len(ref.F.Meta.CVSSReasons) != 0 {
		t.Fatalf("reasons after the clear: %v", ref.F.Meta.CVSSReasons)
	}
}

// set_field reviewers replaces the whole list: with the list's base from
// read_finding it is refused when someone was added since; without a base
// it is not checked.
func TestMCPReviewersBase(t *testing.T) {
	f := newFx(t)
	args := func(value, base string) map[string]any {
		a := map[string]any{"engagement": "acme", "finding": "F-001", "field": "reviewers", "value": value}
		if base != "" {
			a["base"] = base
		}
		return a
	}
	f.ok(alice, "set_field", args("bob", ""))
	read := func() string {
		var rd struct {
			Bases map[string]string `json:"field_bases"`
		}
		json.Unmarshal([]byte(f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})), &rd)
		if rd.Bases["reviewers"] == "" {
			t.Fatalf("no base for reviewers: %v", rd.Bases)
		}
		return rd.Bases["reviewers"]
	}
	stale := read()
	if err := f.s.Store.AddReviewers("acme", "001", []string{"dora"}, dora); err != nil {
		t.Fatal(err)
	}
	if text, isErr := f.call(alice, "set_field", args("bob", stale)); !isErr || !strings.Contains(text, "changed since you read it") {
		t.Fatalf("stale list: %v %s", isErr, text)
	}
	if ref, _ := f.s.Store.Finding("acme", "001"); strings.Join(ref.F.Meta.Reviewers, ",") != "bob,dora" {
		t.Fatalf("reviewers %v", ref.F.Meta.Reviewers)
	}
	f.ok(alice, "set_field", args("bob,dora", read()))
	f.ok(alice, "set_field", args("bob", ""))
	if ref, _ := f.s.Store.Finding("acme", "001"); strings.Join(ref.F.Meta.Reviewers, ",") != "bob" {
		t.Fatalf("reviewers %v", ref.F.Meta.Reviewers)
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
	nb, _ := object(t, "set_field", first)["base"].(string)
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
