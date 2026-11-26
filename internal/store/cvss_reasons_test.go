package store

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/workflow"
)

// A reason explains one value of its metric. When the metric changes and
// the change brings no reason for it, the stored one goes, so the old words
// do not pass the gate for the new value. A metric that did not change
// keeps its reason, and the bases returned are those of what was written.
func TestCVSSReasonGoesWithItsValue(t *testing.T) {
	s, _, fd := newFinding(t)
	low := "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:N"
	high := "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N"
	if err := s.UpdateCVSS(eng, fd, low, map[string]string{"PR": "r1", "AC": "race"}, "", alice); err != nil {
		t.Fatal(err)
	}
	got, err := s.UpdateCVSSRows(eng, fd, CVSSChange{Vector: &high}, alice)
	if err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	if _, ok := m.CVSSReasons["PR"]; ok || m.CVSSReasons["AC"] != "race" {
		t.Fatalf("reasons after PR:L to PR:H: %v", m.CVSSReasons)
	}
	if gate := strings.Join(workflow.Gate(m, s.Config()), "; "); !strings.Contains(gate, "Privileges Required") {
		t.Fatalf("the gate does not ask for the reason: %q", gate)
	}
	if want := CVSSRowHashes(m); !reflect.DeepEqual(got, want) {
		t.Fatalf("returned bases %v, of the file %v", got, want)
	}
	// a change that brings the reason for the new value keeps it
	if err := s.UpdateCVSS(eng, fd, low, map[string]string{"PR": "r2"}, "", alice); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.CVSSReasons["PR"] != "r2" || m.CVSSReasons["AC"] != "race" {
		t.Fatalf("reasons with a new one: %v", m.CVSSReasons)
	}
	// a metric saved back at its standard value loses its reason too
	std := "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N"
	if err := s.UpdateCVSS(eng, fd, std, nil, "", alice); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; len(m.CVSSReasons) != 1 || m.CVSSReasons["PR"] != "r2" {
		t.Fatalf("reasons after AC:H to AC:L: %v", m.CVSSReasons)
	}
}

// Clearing the vector removes its reasons from the file: they explain
// values that are gone.
func TestCVSSClearDropsReasons(t *testing.T) {
	s, dir, fd := newFinding(t)
	vec := "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:N"
	if err := s.UpdateCVSS(eng, fd, vec, map[string]string{"PR": "r1", "AC": "race"}, "", alice); err != nil {
		t.Fatal(err)
	}
	empty := ""
	got, err := s.UpdateCVSSRows(eng, fd, CVSSChange{Vector: &empty}, alice)
	if err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	b, _ := os.ReadFile(filepath.Join(dir, "engagements", eng, "findings", fd, "finding.md"))
	if len(m.CVSSReasons) != 0 || strings.Contains(string(b), "cvss_reasons") || strings.Contains(string(b), "race") {
		t.Fatalf("reasons left after the clear:\n%s", b)
	}
	if want := CVSSRowHashes(m); !reflect.DeepEqual(got, want) {
		t.Fatalf("returned bases %v, of the file %v", got, want)
	}
	if got := last(t, dir, "%s"); got != "F-001: clear CVSS" {
		t.Fatalf("commit %q", got)
	}
}
