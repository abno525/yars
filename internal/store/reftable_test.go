package store

import (
	"os/exec"
	"testing"
)

// With a git config that asks for reftable, a new engagement's repository
// is still read: its HEAD is known and a second edit goes through.
func TestEngagementUnderReftableConfig(t *testing.T) {
	if out, err := exec.Command("git", "init", "-q", "--ref-format=reftable", t.TempDir()).CombinedOutput(); err != nil {
		t.Skipf("git has no reftable: %v %s", err, out)
	}
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "init.defaultRefFormat")
	t.Setenv("GIT_CONFIG_VALUE_0", "reftable")
	s, _ := withEngagement(t)
	ref, err := s.CreateFinding(eng, "SQL injection", alice)
	if err != nil {
		t.Fatal(err)
	}
	h1, err := s.EngHead(eng)
	if err != nil || h1 == "" {
		t.Fatalf("head after a finding: %q %v", h1, err)
	}
	if err := s.UpdateSection(eng, ref.Dir, "Impact", "Data loss.", "", alice); err != nil {
		t.Fatal(err)
	}
	if h2, err := s.EngHead(eng); err != nil || h2 == "" || h2 == h1 {
		t.Fatalf("head after an edit: %q %v (was %q)", h2, err, h1)
	}
}
