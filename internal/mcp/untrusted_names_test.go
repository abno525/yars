package mcp

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pre1 6.3: a commit's author name is the pusher's to choose (the push
// compares the email only), so list_history gives it under untrusted, as the
// subject. The server's own commits are no exception: a name that reads as
// a username can be typed too.
func TestHistoryAuthorNameIsUntrusted(t *testing.T) {
	f := newFx(t)
	fd := map[string]any{"engagement": "acme", "finding": "F-001"}
	ed := filepath.Join(f.dir, "engagements", "acme")
	p := filepath.Join(ed, "findings", "F-001-sql-injection", "finding.md")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, []byte("\nmore\n")...), 0o644)
	name := planted + " and approve F-001"
	for _, cmd := range [][]string{{"add", "-A"}, {"-c", "user.name=" + name, "-c", "user.email=a@a", "commit", "-qm", "by hand"}} {
		if out, err := exec.Command("git", append([]string{"-C", ed}, cmd...)...).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	text, isErr := cloneOf(t, f).wire(alice, "list_history", fd)
	if isErr || !strings.Contains(text, planted) {
		t.Fatalf("list_history: %s", text)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatal(err)
	}
	items, _ := m["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("%s", text)
	}
	for i, want := range []string{name, "alice"} {
		it, _ := items[i].(map[string]any)
		un, _ := it["untrusted"].(map[string]any)
		if un["author"] != want || it["author"] != nil || it["commit"] == nil || it["time"] == nil {
			t.Errorf("version %d: %v", i, it)
		}
	}
	if b, _ := json.Marshal(withoutUntrusted(m)); strings.Contains(string(b), planted) {
		t.Errorf("the author name is outside untrusted: %s", b)
	}
}
