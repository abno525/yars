package rules

import (
	"context"
	"fmt"
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
}

func NewEngine(dir string, cfg config.Config) *Engine {
	return &Engine{Dir: dir, Cfg: cfg, Runner: NewRunner(dir, cfg.AI), Budget: 90 * time.Second}
}

// checkNames flags section:/details: targets that the config doesn't know
// (typos such as section:location would otherwise never fire).
func (e *Engine) checkNames(s *Set) {
	for _, r := range s.Rules {
		kind, name, ok := strings.Cut(r.Target, ":")
		if !ok {
			continue
		}
		known := e.Cfg.Sections
		if kind == "details" {
			known = e.Cfg.DetailsRows
		}
		if !slices.Contains(known, name) {
			s.Problems = append(s.Problems, Violation{Rule: r.ID, Level: "warning", Target: "rules",
				Message: "rule target " + r.Target + " (" + r.File + ") is not a configured " + kind + " name; check the spelling"})
		}
	}
}

func (e *Engine) signature() string {
	ents, _ := os.ReadDir(e.Dir)
	var parts []string
	for _, en := range ents {
		if info, err := en.Info(); err == nil {
			parts = append(parts, fmt.Sprintf("%s:%d:%d", en.Name(), info.Size(), info.ModTime().UnixNano()))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// Rules returns the current rule set, reloading it if files changed.
func (e *Engine) Rules() *Set {
	e.mu.Lock()
	defer e.mu.Unlock()
	if sig := e.signature(); e.set == nil || sig != e.stamp {
		s := Load(e.Dir)
		e.checkNames(s)
		e.set, e.stamp = s, sig
	}
	return e.set
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
	return e.Rules().Run(ctx, d, e.Cfg, kinds, e.Runner)
}

// LintSection returns fast-rule hints for a section body being edited.
func (e *Engine) LintSection(f *finding.Finding, section, body string) []Violation {
	return e.Rules().RunSection(DocOf(f), e.Cfg, section, body)
}

// DirFor returns the rules directory of a data repo.
func DirFor(dataDir string) string { return filepath.Join(dataDir, ".yars", "rules") }
