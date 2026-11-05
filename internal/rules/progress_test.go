package rules

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"yars/internal/config"
)

func TestScriptFailureMarked(t *testing.T) {
	dir := t.TempDir()
	script(t, dir, "slow.sh", "sleep 5\necho '[]'\n")
	script(t, dir, "junk.sh", "echo not json\n")
	script(t, dir, "fail.sh", "echo boom >&2\nexit 3\n")
	script(t, dir, "ok.sh", "echo '[{\"message\":\"m\"}]'\n")
	r := NewRunner(dir, config.AIConfig{})
	r.ScriptTimeout = 300 * time.Millisecond
	want := map[string]string{"slow.sh": "timed out", "junk.sh": "invalid output", "fail.sh": "boom", "ok.sh": ""}
	for path, fail := range want {
		vs := r.Script(context.Background(), Rule{ID: "s", Level: "error", Script: path}, doc())
		if len(vs) != 1 || vs[0].Fail != fail {
			t.Errorf("%s: fail %q, want %q (%+v)", path, vs[0].Fail, fail, vs)
		}
	}
}

func TestEngineCheckProgress(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(`
- id: a
  target: title
  regex_forbid: 'SQL'
- id: b
  target: title
  regex_forbid: 'nothing'
- id: off
  target: title
  regex_forbid: 'SQL'
  enabled: false
- id: s
  script: s.sh
  level: warning
`), 0o644)
	script(t, dir, "s.sh", "cat >/dev/null; echo '[{\"message\":\"from script\"}]'\n")
	e := NewEngine(dir, config.Default())
	type step struct{ done, total int }
	var steps []step
	vs := e.CheckDoc(context.Background(), doc(), func(done, total int) { steps = append(steps, step{done, total}) })
	if len(steps) != 4 || steps[0] != (step{0, 3}) || steps[3] != (step{3, 3}) {
		t.Fatalf("steps %+v", steps)
	}
	if len(vs) != 2 || vs[0].Rule != "a" || vs[1].Message != "from script" {
		t.Fatalf("violations %+v", vs)
	}
}
