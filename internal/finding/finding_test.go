package finding

import (
	"reflect"
	"strings"
	"testing"
)

const canonical = `---
id: F-001
title: SQL injection in login form
status: draft
severity: high
cvss: CVSS:3.1/AV:N
author: alice
reviewers:
    - bob
---

## Description

text

## Location

/login
`

func TestParseBasic(t *testing.T) {
	f, err := Parse([]byte(canonical))
	if err != nil {
		t.Fatal(err)
	}
	if f.Meta.ID != "F-001" || f.Meta.Severity != "high" {
		t.Fatalf("meta: %+v", f.Meta)
	}
	// workflow state lives in the database: keys in a file are legacy
	if f.Meta.Status != "" || f.Meta.Reviewers != nil {
		t.Fatalf("state read from the file: %+v", f.Meta)
	}
	l, ok := f.Legacy()
	if !ok || l.Status != "draft" || !reflect.DeepEqual(l.Reviewers, []string{"bob"}) || !reflect.DeepEqual(l.Keys, []string{"reviewers", "status"}) {
		t.Fatalf("legacy %+v %v", l, ok)
	}
	var names []string
	for _, s := range f.Sections {
		names = append(names, s.Name)
	}
	if !reflect.DeepEqual(names, []string{"Description", "Location"}) {
		t.Fatalf("sections: %v", names)
	}
}

const bom = "\xef\xbb\xbf"

// Files an editor may write are read: a UTF-8 byte order mark (dropped on
// the next write), empty front matter, and a closing "---" with no newline
// after it (backlog, Core).
func TestParseEditorQuirks(t *testing.T) {
	f, err := Parse([]byte(bom + canonical))
	if err != nil || f.Meta.ID != "F-001" || len(f.Sections) != 2 {
		t.Fatalf("with a BOM: %v %+v", err, f)
	}
	if got := string(f.Bytes()); got != canonical {
		t.Fatalf("with a BOM, written back:\n%q", got)
	}
	empty := "---\n---\n\n## Description\n\ntext\n"
	f, err = Parse([]byte(empty))
	if err != nil || f.Meta.ID != "" || len(f.Sections) != 1 || f.Sections[0].Name != "Description" {
		t.Fatalf("empty front matter: %v %+v", err, f)
	}
	if got := string(f.Bytes()); got != empty {
		t.Fatalf("empty front matter, written back:\n%q", got)
	}
	for _, in := range []string{"---\nid: F-001\ntitle: X\n---", "---\nid: F-001\ntitle: X\n---\r\n", "---\n---"} {
		f, err := Parse([]byte(in))
		if err != nil || len(f.Sections) != 0 || f.Preamble != "" {
			t.Fatalf("%q: %v %+v", in, err, f)
		}
		if in != "---\n---" && f.Meta.ID != "F-001" {
			t.Fatalf("%q: meta %+v", in, f.Meta)
		}
	}
	for _, in := range []string{"", "id: F-001\n", "---\nid: F-001\n", "---\nid: F-001\n----\n"} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%q parsed", in)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	f, err := Parse([]byte(canonical))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(f.Bytes()); got != canonical {
		t.Fatalf("round trip mismatch:\n%q\nwant\n%q", got, canonical)
	}
}

func TestFencedHeading(t *testing.T) {
	in := strings.Replace(canonical, "text\n", "```\n## not a heading\n```\n", 1)
	f, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Sections) != 2 {
		t.Fatalf("got %d sections", len(f.Sections))
	}
	if string(f.Bytes()) != in {
		t.Fatal("round trip mismatch")
	}
}

func TestUnknownKeysPreserved(t *testing.T) {
	in := strings.Replace(canonical, "author: alice\n", "author: alice\nfoo: bar\n", 1)
	f, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	f.SetSection("Location", "/admin\n")
	if !strings.Contains(string(f.Bytes()), "foo: bar") {
		t.Fatalf("unknown key lost:\n%s", f.Bytes())
	}
}

func TestCRLF(t *testing.T) {
	lf, _ := Parse([]byte(canonical))
	crlf, err := Parse([]byte(strings.ReplaceAll(canonical, "\n", "\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(lf.Meta, crlf.Meta) || !reflect.DeepEqual(lf.Sections, crlf.Sections) {
		t.Fatal("CRLF parse differs from LF")
	}
}

func TestSetSection(t *testing.T) {
	f, _ := Parse([]byte(canonical))
	f.SetSection("Location", "/admin\n")
	if b, _ := f.Section("Location"); b != "\n/admin\n" {
		t.Fatalf("Location = %q", b)
	}
	if b, _ := f.Section("Description"); b != "\ntext\n\n" {
		t.Fatalf("Description changed: %q", b)
	}
	f.SetSection("Notes", "n\n")
	if f.Sections[len(f.Sections)-1].Name != "Notes" {
		t.Fatal("Notes not appended")
	}
	if !strings.Contains(string(f.Bytes()), "## Notes\n") {
		t.Fatal("Notes heading missing")
	}
}

func sectionNames(f *Finding) string {
	var n []string
	for _, s := range f.Sections {
		n = append(n, s.Name)
	}
	return strings.Join(n, ",")
}

func TestFenceRulesCommonMark(t *testing.T) {
	cases := map[string]string{
		"inline triple backticks": "```/api/login``` is vulnerable\n",
		"tilde inside backticks":  "```\n~~~\n## in fence\n```\n",
		"four-backtick fence":     "````\n```\n## in fence\n````\n",
	}
	for name, body := range cases {
		in := "---\nid: F-001\n---\n## A\n" + body + "## B\nb\n"
		f, err := Parse([]byte(in))
		if err != nil {
			t.Fatal(err)
		}
		if got := sectionNames(f); got != "A,B" {
			t.Errorf("%s: sections %q", name, got)
		}
	}
}

func TestValidateBody(t *testing.T) {
	if err := ValidateBody("```\nunclosed\n"); err == nil {
		t.Error("unclosed fence accepted")
	}
	if err := ValidateBody("text\n## Impact\nmore"); err == nil {
		t.Error("top-level ## heading accepted")
	}
	if err := ValidateBody("```\n## fine in fence\n```\n### sub ok\n```a``` inline"); err != nil {
		t.Errorf("valid body rejected: %v", err)
	}
}

func TestFrontMatterPreservedVerbatim(t *testing.T) {
	in := "---\nid: F-001\ntitle: T\nstatus: draft   # draft|verification|complete|reported\nreviewers: [bob]\ncvss: 9.8\nretest: { source: e/F-001, result: not_fixed, note: x }\n---\n## Impact\nold\n"
	f, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	f.SetSection("Impact", "new")
	want := strings.Replace(in, "## Impact\nold\n", "## Impact\n\nnew\n", 1)
	if got := string(f.Bytes()); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	// state filled in from the database is never written back to the file
	f.Meta.Status, f.Meta.Reviewers, f.Meta.ClearedBy = "verification", []string{"carol"}, []string{"carol"}
	f.Meta.Returned = &Returned{By: "carol", Reason: "x"}
	if got := string(f.Bytes()); got != want {
		t.Fatalf("state leaked into the file:\n%s", got)
	}
	f.Meta.Severity = "low"
	if !strings.Contains(string(f.Bytes()), "severity: low") {
		t.Fatal("deliberate meta change not written")
	}
}

func TestNoLegacyStateInCleanFile(t *testing.T) {
	f, _ := Parse([]byte("---\nid: F-001\ntitle: T\nseverity: high\n---\n## Impact\nx\n"))
	if _, ok := f.Legacy(); ok {
		t.Fatal("clean file reported as legacy")
	}
	if b := string(New("F-002", "X", "alice", []string{"Impact"}).Bytes()); strings.Contains(b, "status") || strings.Contains(b, "reviewers") {
		t.Fatalf("new finding writes state:\n%s", b)
	}
}

func TestCRLFWriteBack(t *testing.T) {
	in := strings.ReplaceAll(canonical, "\n", "\r\n")
	f, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Bytes()) != in {
		t.Fatal("CRLF not preserved on round trip")
	}
	f.SetSection("Location", "/a\r\n/b")
	out := string(f.Bytes())
	if strings.Contains(strings.ReplaceAll(out, "\r\n", ""), "\n") {
		t.Fatalf("bare LF in CRLF output: %q", out)
	}
}

func TestNew(t *testing.T) {
	defaults := []string{"Description", "Location", "Impact", "Steps to Reproduce", "Remediation", "References"}
	f := New("F-002", "XSS", "alice", defaults)
	if f.Meta.Status != "draft" || f.Meta.ID != "F-002" || f.Meta.Author != "alice" {
		t.Fatalf("meta: %+v", f.Meta)
	}
	if len(f.Sections) != 6 {
		t.Fatalf("sections: %d", len(f.Sections))
	}
	for i, s := range f.Sections {
		if s.Name != defaults[i] {
			t.Fatalf("section %d = %s", i, s.Name)
		}
	}
	if _, err := Parse(f.Bytes()); err != nil {
		t.Fatal(err)
	}
}
