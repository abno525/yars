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
	if f.Meta.ID != "F-001" || f.Meta.Status != "draft" {
		t.Fatalf("meta: %+v", f.Meta)
	}
	if !reflect.DeepEqual(f.Meta.Reviewers, []string{"bob"}) {
		t.Fatalf("reviewers: %v", f.Meta.Reviewers)
	}
	var names []string
	for _, s := range f.Sections {
		names = append(names, s.Name)
	}
	if !reflect.DeepEqual(names, []string{"Description", "Location"}) {
		t.Fatalf("sections: %v", names)
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
