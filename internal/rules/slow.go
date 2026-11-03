package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"yars/internal/config"
)

// Runner evaluates script and AI rules. Scripts live in Dir (.yars/rules).
type Runner struct {
	Dir           string
	AIConf        config.AIConfig
	HTTP          *http.Client
	ScriptTimeout time.Duration
	AITimeout     time.Duration
	Getenv        func(string) string
	cache         sync.Map // cache key -> []Violation
}

func NewRunner(dir string, ai config.AIConfig) *Runner {
	return &Runner{Dir: dir, AIConf: ai, HTTP: &http.Client{}, ScriptTimeout: 10 * time.Second,
		AITimeout: 60 * time.Second, Getenv: os.Getenv}
}

func failed(r Rule, msg string) []Violation {
	return []Violation{{Rule: r.ID, Level: r.Level, Message: "rule failed: " + msg, Target: "rules"}}
}

// scriptPath resolves r.Script inside the rules dir (symlinks included).
func (rn *Runner) scriptPath(script string) (string, error) {
	if filepath.IsAbs(script) {
		return "", errors.New("script outside rules dir")
	}
	dir, err := filepath.EvalSymlinks(rn.Dir)
	if err != nil {
		return "", err
	}
	p, err := filepath.EvalSymlinks(filepath.Join(dir, script))
	if err != nil {
		if rel, rerr := filepath.Rel(dir, filepath.Join(dir, script)); rerr != nil || strings.HasPrefix(rel, "..") {
			return "", errors.New("script outside rules dir")
		}
		return "", err
	}
	if rel, err := filepath.Rel(dir, p); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("script outside rules dir")
	}
	return p, nil
}

// capWriter buffers up to max bytes and then fails, so a runaway script
// can't exhaust the server's memory.
// (No embedded bytes.Buffer: its ReadFrom would let io.Copy bypass Write.)
type capWriter struct {
	buf  bytes.Buffer
	max  int
	over bool
}

var errTooLarge = errors.New("output too large")

func (w *capWriter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.max {
		w.over = true
		return 0, errTooLarge
	}
	return w.buf.Write(p)
}

func (w *capWriter) String() string { return w.buf.String() }
func (w *capWriter) Bytes() []byte  { return w.buf.Bytes() }

type scriptResult struct {
	Message string `json:"message"`
	Quote   string `json:"quote"`
	Target  string `json:"target"`
}

func (rn *Runner) Script(ctx context.Context, r Rule, d Doc) []Violation {
	path, err := rn.scriptPath(r.Script)
	if err != nil {
		return failed(r, err.Error())
	}
	input, err := json.Marshal(d)
	if err != nil {
		return failed(r, err.Error())
	}
	ctx, cancel := context.WithTimeout(ctx, rn.ScriptTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)
	cmd.Dir = filepath.Dir(path)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	cmd.Stdin = bytes.NewReader(input)
	cmd.WaitDelay = time.Second
	out, stderr := &capWriter{max: 1 << 20}, &capWriter{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, stderr
	err = cmd.Run()
	if out.over {
		return failed(r, "output too large (limit 1 MB)")
	}
	if ctx.Err() == context.DeadlineExceeded {
		return failed(r, "timed out")
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return failed(r, quote(msg))
	}
	var res []scriptResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		return failed(r, "invalid output (want a JSON array): "+quote(out.String()))
	}
	var vs []Violation
	for _, x := range res {
		msg := x.Message
		if msg == "" {
			msg = r.message()
		}
		target := x.Target
		if target == "" {
			target = "finding"
		}
		vs = append(vs, r.v(target, msg, x.Quote))
	}
	return vs
}
