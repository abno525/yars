//go:build unix

package rules

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
)

// A script that started a background process does not leave it running
// after its timeout: the whole process group is killed.
func TestScriptTimeoutKillsChildren(t *testing.T) {
	dir := t.TempDir()
	script(t, dir, "bg.sh", "sleep 30 &\necho $! > pid\nwait\n")
	r := NewRunner(dir, config.AIConfig{})
	r.ScriptTimeout = 300 * time.Millisecond
	vs := r.Script(context.Background(), Rule{ID: "s", Level: "error", Script: "bg.sh"}, doc())
	if len(vs) != 1 || !strings.Contains(vs[0].Message, "timed out") {
		t.Fatalf("got %+v", vs)
	}
	b, err := os.ReadFile(filepath.Join(dir, "pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the script's child %d still runs after the timeout", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
