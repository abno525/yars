package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Through the real hook: a pushed config.yaml with a key YARS does not know
// is refused and the key is named; the same file without it is accepted.
func TestPushConfigUnknownKeyRefused(t *testing.T) {
	p := newPushEnv(t)
	in := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", p.clone, "-c", "user.name=dora", "-c", "user.email=dora@yars.local", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	cfg := filepath.Join(p.clone, ".yars", "config.yaml")
	good := "severities: [critical, high, medium, low, info]\nbase_url: https://yars.example.com\n"
	dora := strings.Replace(p.url, "http://", "http://dora:pw@", 1) + "/git/yars"
	os.WriteFile(cfg, []byte(strings.Replace(good, "base_url", "base-url", 1)), 0o644)
	if out, err := in("commit", "-qm", "address", "--", ".yars/config.yaml"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	out, err := in("push", dora, "HEAD:main")
	if err == nil || !strings.Contains(out, `unknown key "base-url" (line 2)`) {
		t.Fatalf("push of a config.yaml with base-url: %v\n%s", err, out)
	}
	os.WriteFile(cfg, []byte(good), 0o644)
	// every commit of a push is checked: the refused one is replaced
	if out, err := in("commit", "-q", "--amend", "-m", "address", "--", ".yars/config.yaml"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if out, err := in("push", dora, "HEAD:main"); err != nil {
		t.Fatalf("push of a good config.yaml: %v\n%s", err, out)
	}
}
