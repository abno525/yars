package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	c, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, Default()) {
		t.Fatalf("got %+v", c)
	}
	want := []string{"Description", "Impact", "Steps to Reproduce", "Remediation", "References"}
	if !reflect.DeepEqual(c.Sections, want) {
		t.Fatalf("sections %v", c.Sections)
	}
	if !reflect.DeepEqual(c.Severities, []string{"critical", "high", "medium", "low", "info"}) {
		t.Fatalf("severities %v", c.Severities)
	}
}

func TestLoadPartial(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".yars"), 0o755)
	os.WriteFile(filepath.Join(dir, ".yars", "config.yaml"), []byte("sections: [A, B]\n"), 0o644)
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.Sections, []string{"A", "B"}) || !reflect.DeepEqual(c.Severities, Default().Severities) {
		t.Fatalf("got %+v", c)
	}
}

func TestUsersRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if us, err := LoadUsers(dir); err != nil || len(us) != 0 {
		t.Fatalf("missing file: %v %v", us, err)
	}
	in := []User{{Username: "alice", Email: "a@x", Role: "pentester", PasswordHash: "h"}}
	if err := SaveUsers(dir, in); err != nil {
		t.Fatal(err)
	}
	out, err := LoadUsers(dir)
	if err != nil || !reflect.DeepEqual(in, out) {
		t.Fatalf("got %v %v", out, err)
	}
}

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".yars"), 0o755)
	os.WriteFile(filepath.Join(dir, ".yars", "config.yaml"), []byte(body), 0o644)
	return dir
}

func TestDefaultDetailsAndSections(t *testing.T) {
	c := Default()
	want := []string{"Location", "Business impact", "Row 3", "Row 4", "Row 5"}
	if !reflect.DeepEqual(c.DetailsRows, want) {
		t.Fatalf("details %v", c.DetailsRows)
	}
	for _, s := range c.Sections {
		if s == "Location" {
			t.Fatal("Location still a default section")
		}
	}
	if c.CVSS.Version != "3.1" {
		t.Fatalf("version %q", c.CVSS.Version)
	}
}

func TestCVSSStandardMerge(t *testing.T) {
	c, err := Load(writeCfg(t, "cvss:\n  standard: {AC: H, UI: \"-\", C: N}\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"AV": "N", "AC": "H", "PR": "N", "S": "U", "C": "N", "I": "N", "A": "N"}
	if !reflect.DeepEqual(c.CVSS.Standard, want) {
		t.Fatalf("standard %v", c.CVSS.Standard)
	}
}

func TestNonStandard(t *testing.T) {
	c := Default()
	if !c.NonStandard("AC", "H") || c.NonStandard("AC", "L") || !c.NonStandard("C", "H") || c.NonStandard("C", "N") {
		t.Fatal("NonStandard wrong")
	}
}

func TestLoadRejectsUnsupportedVersion(t *testing.T) {
	_, err := Load(writeCfg(t, "cvss:\n  version: \"4.0\"\n"))
	if err == nil || !strings.Contains(err.Error(), "4.0") {
		t.Fatalf("err %v", err)
	}
}

func TestLoadRejectsBadStandard(t *testing.T) {
	_, err := Load(writeCfg(t, "cvss:\n  standard: {AV: Z}\n"))
	if err == nil || !strings.Contains(err.Error(), "AV") {
		t.Fatalf("err %v", err)
	}
}

func TestLoadRequiresRatingSeverities(t *testing.T) {
	_, err := Load(writeCfg(t, "severities: [high, medium, low]\n"))
	if err == nil || !strings.Contains(err.Error(), "critical") || !strings.Contains(err.Error(), "info") {
		t.Fatalf("err %v", err)
	}
}

func TestLoadAIConfig(t *testing.T) {
	c, err := Load(writeCfg(t, "ai:\n  provider: anthropic\n  model: claude-haiku-5-5\n  api_key_env: K\n"))
	if err != nil || c.AI.Provider != "anthropic" || c.AI.Model != "claude-haiku-5-5" || c.AI.APIKeyEnv != "K" {
		t.Fatalf("%+v %v", c.AI, err)
	}
	if _, err := Load(writeCfg(t, "ai:\n  provider: gemini\n")); err == nil || !strings.Contains(err.Error(), "gemini") {
		t.Fatalf("err %v", err)
	}
	// the key must never be sent over plain http to a remote host
	if _, err := Load(writeCfg(t, "ai:\n  provider: openai\n  base_url: http://evil.example/v1\n")); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain http accepted: %v", err)
	}
	if _, err := Load(writeCfg(t, "ai:\n  provider: openai\n  base_url: http://localhost:4000\n")); err != nil {
		t.Fatalf("local LiteLLM rejected: %v", err)
	}
}

func TestValidRole(t *testing.T) {
	if !ValidRole("director") || ValidRole("boss") {
		t.Fatal("ValidRole wrong")
	}
}
