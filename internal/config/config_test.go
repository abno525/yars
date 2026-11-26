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
	want := []string{"Location", "Cause", "Result", "Attack condition", "Business impact"}
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

func TestLoadSMTPAndBaseURL(t *testing.T) {
	c, err := Load(writeCfg(t, "base_url: https://yars.example.com/\nsmtp:\n  host: mail.example\n  port: 587\n  from: yars@example.com\n  username: yars\n  password_env: YARS_SMTP\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL != "https://yars.example.com" || !c.SMTP.Configured() || c.SMTP.Port != 587 || c.SMTP.PasswordEnv != "YARS_SMTP" || c.SMTP.Username != "yars" {
		t.Fatalf("%+v %q", c.SMTP, c.BaseURL)
	}
	if c, _ := Load(writeCfg(t, "smtp:\n  host: mail.example\n")); c.SMTP.Configured() || c.SMTP.Port != 25 {
		t.Fatalf("no from: %+v", c.SMTP)
	}
	if Default().SMTP.Configured() {
		t.Fatal("default has mail")
	}
	if _, err := Load(writeCfg(t, "base_url: ftp://x\n")); err == nil || !strings.Contains(err.Error(), "base_url") {
		t.Fatalf("err %v", err)
	}
}

// config.yaml names only environment variables that start with YARS_: the
// key goes to ai.base_url and the password to smtp.host, so any other name
// would send that variable of the server out. The refusal names the key,
// the value and the fix.
func TestEnvNamesNeedThePrefix(t *testing.T) {
	for body, key := range map[string]string{
		"ai:\n  provider: openai\n  base_url: https://x.example/v1\n  api_key_env: AWS_SECRET_ACCESS_KEY\n": "ai.api_key_env",
		"smtp:\n  host: mail.example\n  from: a@x\n  password_env: HOME\n":                                 "smtp.password_env",
		"ai:\n  api_key_env: yars_ai_key\n":                                                                "ai.api_key_env",
		"smtp:\n  password_env: YARS_\n":                                                                   "smtp.password_env",
		"smtp:\n  password_env: \"YARS_A B\"\n":                                                            "smtp.password_env",
	} {
		_, err := Parse([]byte(body))
		if err == nil {
			t.Fatalf("accepted:\n%s", body)
		}
		for _, want := range []string{key, "YARS_", "data folder", "commit"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("%q lacks %q", err, want)
			}
		}
	}
	if _, err := Parse([]byte("ai:\n  api_key_env: AWS_SECRET_ACCESS_KEY\n")); err == nil || !strings.Contains(err.Error(), `"AWS_SECRET_ACCESS_KEY"`) || !strings.Contains(err.Error(), "YARS_AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("the value and the new name: %v", err)
	}
	for _, body := range []string{"ai:\n  api_key_env: YARS_AI_KEY\nsmtp:\n  password_env: YARS_SMTP_PASSWORD\n", "ai:\n  api_key_env: \"\"\n", ""} {
		if _, err := Parse([]byte(body)); err != nil {
			t.Fatalf("%q: %v", body, err)
		}
	}
}

func TestLoadAIConfig(t *testing.T) {
	c, err := Load(writeCfg(t, "ai:\n  provider: anthropic\n  model: claude-haiku-5-5\n  api_key_env: YARS_K\n"))
	if err != nil || c.AI.Provider != "anthropic" || c.AI.Model != "claude-haiku-5-5" || c.AI.APIKeyEnv != "YARS_K" {
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

// Q3: checks.max_running bounds the check runs at once; unset (or a
// checks block without it) is 4, below 1 is refused.
func TestLoadChecksMaxRunning(t *testing.T) {
	if Default().Checks.MaxRunning != 4 {
		t.Fatalf("default %d", Default().Checks.MaxRunning)
	}
	for _, body := range []string{"", "checks:\n", "checks:\n  # max_running: 8\n", "checks: {}\n", "checks:\n  max_running: ~\n"} {
		if c, err := Load(writeCfg(t, body)); err != nil || c.Checks.MaxRunning != 4 {
			t.Fatalf("%q: %d %v", body, c.Checks.MaxRunning, err)
		}
	}
	if c, err := Load(writeCfg(t, "checks:\n  max_running: 1\n")); err != nil || c.Checks.MaxRunning != 1 {
		t.Fatalf("one: %d %v", c.Checks.MaxRunning, err)
	}
	for _, bad := range []string{"0", "-2"} {
		if _, err := Load(writeCfg(t, "checks:\n  max_running: "+bad+"\n")); err == nil || !strings.Contains(err.Error(), "checks.max_running") {
			t.Fatalf("%s accepted: %v", bad, err)
		}
	}
	if _, err := Load(writeCfg(t, "checks:\n  max_running: many\n")); err == nil {
		t.Fatal("a word accepted")
	}
}

func TestValidRole(t *testing.T) {
	if !ValidRole("director") || ValidRole("boss") || ValidRole("admin") {
		t.Fatal("ValidRole wrong")
	}
	if !reflect.DeepEqual(Roles, []string{"pentester", "reviewer", "director"}) {
		t.Fatalf("roles %v", Roles)
	}
}

// An account with a role YARS doesn't know (e.g. the old "admin") would
// silently lose all rights, so loading fails and says how to fix it.
func TestLoadUsersRejectsUnknownRole(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".yars"), 0o755)
	os.WriteFile(UsersPath(dir), []byte("- username: boss\n  role: admin\n"), 0o600)
	_, err := LoadUsers(dir)
	if err == nil || !strings.Contains(err.Error(), "boss") || !strings.Contains(err.Error(), "pentester, reviewer, director") {
		t.Fatalf("err %v", err)
	}
}
