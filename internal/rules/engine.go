package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"yars/internal/config"
	"yars/internal/finding"
)

// Engine binds a rules directory, config and slow runner, reloading the rule
// files whenever they change on disk (e.g. after a git pull or push).
type Engine struct {
	Dir    string
	Cfg    config.Config
	Runner SlowRunner

	mu    sync.Mutex
	set   *Set
	stamp string
}

func NewEngine(dir string, cfg config.Config) *Engine {
	return &Engine{Dir: dir, Cfg: cfg, Runner: NewRunner(dir, cfg.AI)}
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
		e.set, e.stamp = Load(e.Dir), sig
	}
	return e.set
}

// Lint checks a finding with the given rule kinds.
func (e *Engine) Lint(ctx context.Context, f *finding.Finding, kinds Kind) []Violation {
	return e.Rules().Run(ctx, DocOf(f), e.Cfg, kinds, e.Runner)
}

// LintSection returns fast-rule hints for a section body being edited.
func (e *Engine) LintSection(f *finding.Finding, section, body string) []Violation {
	return e.Rules().RunSection(DocOf(f), e.Cfg, section, body)
}

// DirFor returns the rules directory of a data repo.
func DirFor(dataDir string) string { return filepath.Join(dataDir, ".yars", "rules") }
