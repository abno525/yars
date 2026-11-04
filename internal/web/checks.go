package web

import (
	"net/http"

	"yars/internal/rules"
	"yars/internal/store"
)

type checksView struct {
	Enabled, Full    bool
	Items            []rules.Violation
	Errors, Warnings int
	RunURL           string
}

func (s *Server) checksFor(r *http.Request, ref store.FindingRef, kinds rules.Kind) checksView {
	v := checksView{RunURL: findingURL(ref.EngID, ref.Dir) + "/checks", Full: kinds&rules.Slow != 0}
	if s.Rules == nil {
		return v
	}
	v.Enabled = true
	v.Items = s.Rules.Lint(r.Context(), ref.F, kinds)
	for _, it := range v.Items {
		if it.Level == "error" {
			v.Errors++
		} else {
			v.Warnings++
		}
	}
	return v
}

// checksRun runs every rule kind, including scripts and AI, on demand.
func (s *Server) checksRun(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	s.exec(w, "finding.html", "checks_panel", s.checksFor(r, ref, rules.All))
}
