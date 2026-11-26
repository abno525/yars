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
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/lru"
)

// Runner evaluates script and AI rules. Scripts live in Dir (.yars/rules).
type Runner struct {
	Dir           string
	AIConf        config.AIConfig
	HTTP          *http.Client
	ScriptTimeout time.Duration
	AITimeout     time.Duration
	Getenv        func(string) string
	// Stored returns the AI settings saved on the admin page and their key
	// ("" values = not set there); nil = config.yaml only.
	Stored func() (config.AIConfig, string)
	// OnUsage, when set, is told about every provider call (never a cached
	// reply).
	OnUsage func(Usage)
	// Results, when set, keeps script and AI results across restarts; nil
	// keeps them in memory only (the push hook, yars lint).
	Results ResultStore

	cacheOnce sync.Once
	cache     *lru.Cache[string, aiResult]    // AI replies by prompt, provider, model, rule and text
	scripts   *lru.Cache[string, []Violation] // script results by rules, rule and input
	aiMu      sync.RWMutex                    // guards AIConf once SetAIConf replaces it
}

// SetAIConf replaces config.yaml's AI settings (a saved or pushed
// config.yaml).
func (rn *Runner) SetAIConf(c config.AIConfig) {
	rn.aiMu.Lock()
	rn.AIConf = c
	rn.aiMu.Unlock()
}

func (rn *Runner) aiConf() config.AIConfig {
	rn.aiMu.RLock()
	defer rn.aiMu.RUnlock()
	return rn.AIConf
}

func NewRunner(dir string, ai config.AIConfig) *Runner {
	return &Runner{Dir: dir, AIConf: ai, HTTP: &http.Client{}, ScriptTimeout: 10 * time.Second,
		AITimeout: 60 * time.Second, Getenv: os.Getenv}
}

func failed(r Rule, msg string) []Violation {
	return failedAs(r, msg, msg)
}

// failedAs reports a rule that could not run; fail is the stored reason.
func failedAs(r Rule, msg, fail string) []Violation {
	return []Violation{{Rule: r.ID, Level: r.Level, Message: "rule failed: " + msg, Target: "rules", Fail: fail}}
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
		if rel, rerr := filepath.Rel(dir, filepath.Join(dir, script)); rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
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

// scriptFormat is part of the script results' key: raise it when the
// violations kept for a run change form.
const scriptFormat = "1"

// Script runs a script rule on d, or returns what the same run gave before
// (Q16): one with the same rules folder (every file in it), script file,
// rule and input. Only a run that worked is kept, and only when the rules
// folder did not change since the check began. It returns at most
// MaxPerRule violations.
func (rn *Runner) Script(ctx context.Context, r Rule, d Doc) []Violation {
	path, err := rn.scriptPath(r.Script)
	if err != nil {
		return failed(r, err.Error())
	}
	input, err := json.Marshal(d)
	if err != nil {
		return failed(r, err.Error())
	}
	// enabled: true or left out runs the same (the bench clears it)
	kr := r
	kr.Enabled = nil
	def, _ := json.Marshal(kr) // plain fields: it cannot fail
	at := rulesAt(ctx, rn.Dir)
	ck := resultKey("script", scriptFormat, at.ver, path, r.ID, string(def), string(input))
	if vs, ok := rn.scriptCache().Get(ck); ok {
		return slices.Clone(vs)
	}
	var vs []Violation
	if rn.stored(ck, &vs) {
		rn.scriptCache().Add(ck, vs)
		return slices.Clone(vs)
	}
	vs, ok := rn.runScript(ctx, r, path, input)
	// kept only while the folder is as it was when the key's version was
	// taken (its signature: sizes and times, so a change undone in between
	// counts too): a script changed during the check ran as it is now, not
	// as the key says
	if ok && signatureHolds(rn.Dir, at.stamp) {
		rn.scriptCache().Add(ck, vs)
		rn.keep(ck, "script", vs)
	}
	return slices.Clone(vs)
}

// runScript runs the script at path with input on stdin; ok is false when
// the run did not work (the violation says why).
func (rn *Runner) runScript(ctx context.Context, r Rule, path string, input []byte) (vs []Violation, ok bool) {
	ctx, cancel := context.WithTimeout(ctx, rn.ScriptTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)
	cmd.Dir = filepath.Dir(path)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	cmd.Stdin = bytes.NewReader(input)
	cmd.WaitDelay = time.Second
	// its own process group: the timeout kills what the script started too
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	out, stderr := &capWriter{max: 1 << 20}, &capWriter{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, stderr
	err := cmd.Run()
	if out.over {
		return failed(r, "output too large (limit 1 MB)"), false
	}
	if ctx.Err() == context.DeadlineExceeded {
		return failed(r, "timed out"), false
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return failed(r, quote(msg)), false
	}
	var res []scriptResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		return failedAs(r, InvalidOutput+" (want a JSON array): "+quote(out.String()), InvalidOutput), false
	}
	for _, x := range res[:min(len(res), MaxPerRule)] {
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
	return vs, true
}
