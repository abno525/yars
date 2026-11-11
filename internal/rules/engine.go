package rules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"yars/internal/config"
	"yars/internal/finding"
)

// Engine binds a rules directory, config and slow runner, reloading the rule
// files whenever they change on disk (e.g. after a git pull or push).
type Engine struct {
	Dir    string
	Cfg    config.Config
	Runner SlowRunner
	// Budget bounds one whole lint run (all scripts and AI calls together).
	Budget time.Duration

	mu    sync.Mutex
	set   *Set
	stamp string
	ver   string // Version of set
	cfgMu sync.RWMutex
}

func NewEngine(dir string, cfg config.Config) *Engine {
	return &Engine{Dir: dir, Cfg: cfg, Runner: NewRunner(dir, cfg.AI), Budget: 90 * time.Second}
}

// conf is the current configuration.
func (e *Engine) conf() config.Config {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	return e.Cfg
}

// SetConfig replaces the configuration (Admin › Structure saved) and checks
// the rule targets again on the next use.
func (e *Engine) SetConfig(c config.Config) {
	e.cfgMu.Lock()
	e.Cfg = c
	e.cfgMu.Unlock()
	if rn, ok := e.Runner.(*Runner); ok {
		rn.SetAIConf(c.AI) // config.yaml's ai: too
	}
	e.mu.Lock()
	e.set = nil
	e.mu.Unlock()
}

// AIConfigured reports whether a provider and a key are set, so AI rules can
// run.
func (e *Engine) AIConfigured() bool {
	rn, ok := e.Runner.(*Runner)
	if !ok {
		return false
	}
	c, key, _ := rn.Effective()
	return c.Provider != "" && key != ""
}

// checkNames flags section:/details: targets that the config doesn't know
// (typos such as section:location would otherwise never fire).
func (e *Engine) checkNames(s *Set) {
	for _, r := range s.Rules {
		kind, name, ok := strings.Cut(r.Target, ":")
		if !ok {
			continue
		}
		c := e.conf()
		known := c.Sections
		if kind == "details" {
			known = c.DetailsRows
		}
		if !slices.Contains(known, name) {
			s.Problems = append(s.Problems, Violation{Rule: r.ID, Level: "warning", Target: "rules",
				Message: "rule target " + r.Target + " (" + r.File + ") is not a configured " + kind + " name; check the spelling"})
		}
	}
}

// signature is every file under the rules folder (sub-folders too: a script
// may live in one) with its size and time: it changes when any of them does.
func (e *Engine) signature() string {
	var parts []string
	filepath.WalkDir(e.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			rel, _ := filepath.Rel(e.Dir, p)
			parts = append(parts, fmt.Sprintf("%s:%d:%d", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano()))
		}
		return nil
	})
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// version is a SHA-256 over every file under the rules folder (path and
// contents, in path order), 16 hex characters; a folder without files has
// one too, so a run with no rules is out of date once rules are added.
func (e *Engine) version() string {
	var paths []string
	filepath.WalkDir(e.Dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			paths = append(paths, p)
		}
		return nil
	})
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(e.Dir, p)
		fmt.Fprintf(h, "%s\x00%d\x00", filepath.ToSlash(rel), len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Rules returns the current rule set, reloading it if files changed.
func (e *Engine) Rules() *Set {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reload()
	return e.set
}

// reload loads the rules again when the files changed (e.mu held).
func (e *Engine) reload() {
	if sig := e.signature(); e.set == nil || sig != e.stamp {
		s := Load(e.Dir)
		e.checkNames(s)
		e.set, e.stamp, e.ver = s, sig, e.version()
	}
}

// Version identifies the rules as loaded: a SHA-256 over every file under
// the rules folder (names and contents, in path order), 16 hex characters
// (Q13: a check run with other rules is out of date).
func (e *Engine) Version() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reload()
	return e.ver
}

// Lint checks a finding with the given rule kinds.
func (e *Engine) Lint(ctx context.Context, f *finding.Finding, kinds Kind) []Violation {
	return e.LintDoc(ctx, DocOf(f), kinds)
}

// LintDoc checks a finding document within the engine's time budget.
func (e *Engine) LintDoc(ctx context.Context, d Doc, kinds Kind) []Violation {
	if e.Budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.Budget)
		defer cancel()
	}
	return e.Rules().Run(ctx, d, e.conf(), kinds, e.Runner)
}

// Check runs every rule kind on a finding within the time budget, telling
// progress how many rules are done (see Set.RunProgress).
func (e *Engine) Check(ctx context.Context, f *finding.Finding, progress func(done, total int)) []Violation {
	return e.CheckDoc(ctx, DocOf(f), progress)
}

// RuleCount is how many rules a Check runs (the total of its progress).
func (e *Engine) RuleCount() int {
	n := 0
	for _, r := range e.Rules().Rules {
		if r.counts(All, e.Runner) {
			n++
		}
	}
	return n
}

// CheckRules lists the rules a Check runs, in order.
func (e *Engine) CheckRules() []Rule { return e.Rules().Runs(All, e.Runner) }

// CheckWith runs every rule kind (or only h.Only) on a finding within the
// time budget, telling h about each rule.
func (e *Engine) CheckWith(ctx context.Context, f *finding.Finding, h Hooks) []Violation {
	if e.Budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.Budget)
		defer cancel()
	}
	return e.Rules().RunWith(ctx, DocOf(f), e.conf(), All, e.Runner, h)
}

// CheckDoc is Check on a finding document.
func (e *Engine) CheckDoc(ctx context.Context, d Doc, progress func(done, total int)) []Violation {
	if e.Budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.Budget)
		defer cancel()
	}
	return e.Rules().RunProgress(ctx, d, e.conf(), All, e.Runner, progress)
}

// LintSection returns fast-rule hints for a section body being edited.
func (e *Engine) LintSection(f *finding.Finding, section, body string) []Violation {
	return e.Rules().RunSection(DocOf(f), e.conf(), section, body)
}

// DirFor returns the rules directory of a data repo.
func DirFor(dataDir string) string { return filepath.Join(dataDir, ".yars", "rules") }
