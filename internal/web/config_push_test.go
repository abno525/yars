package web

import (
	"slices"
	"testing"

	"yars/internal/rules"
)

// A configuration a git push applies (Store.SetConfig, from ReceivePush)
// reaches the pages and the check rules at once, as an Admin › Structure
// save does.
func TestPushedConfigReachesPages(t *testing.T) {
	e := setup(t)
	e.srv.Rules = rules.NewEngine(t.TempDir(), e.srv.conf())
	c := e.srv.conf()
	c.Sections = append(slices.Clone(c.Sections), "Proof")
	e.srv.Store.SetConfig(c)
	if got := e.srv.conf().Sections; !slices.Contains(got, "Proof") {
		t.Fatalf("pages' sections %v", got)
	}
	if got := e.srv.Rules.Cfg.Sections; !slices.Contains(got, "Proof") {
		t.Fatalf("rules' sections %v", got)
	}
}
