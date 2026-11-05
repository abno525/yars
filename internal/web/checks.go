package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"yars/internal/auth"
	"yars/internal/db"
	"yars/internal/rules"
	"yars/internal/store"
)

// checkRow is one violation in the checks panel.
type checkRow struct {
	Rule, Level, Message, Quote, Where string
	CanDismiss                         bool
	By, At                             string // dismissed rows: who and when
}

type checksView struct {
	Enabled                       bool
	URL, DismissURL, UndismissURL string
	// State of the latest run: "" (none), running, done, failed, invalid
	// (a script printed no JSON) or stale (the finding changed since).
	State, StateLabel, Error string
	Running                  bool
	ReadOnly                 bool   // archived engagement: no Check, no Dismiss
	Button                   string // "Check", or "Checking 4/6" while running
	Rows, Dismissed          []checkRow
	Errors, Warnings         int // rows not dismissed
	// Gate: the fast rules' errors that are not dismissed; they block
	// submit and approve like the store's gate.
	Gate []string
}

var checkStateLabel = map[string]string{"running": "Running", "done": "Done", "failed": "Failed",
	"invalid": "Invalid output", "stale": "Stale"}

func (s *Server) routesChecks(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/f/{fid}/checks", s.checksGet)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/checks", s.checksRun)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/checks/dismiss", s.checksDismiss(true))
	mux.HandleFunc("POST /e/{eng}/f/{fid}/checks/undismiss", s.checksDismiss(false))
}

// where names the part of the finding a violation is about.
func where(target string) string {
	if name, ok := strings.CutPrefix(target, "section:"); ok {
		return name
	}
	if name, ok := strings.CutPrefix(target, "details:"); ok {
		return name
	}
	return target
}

// checksFor builds the checks panel: the latest run's results (the fast
// rules' results now while none is finished), split into open and dismissed
// rows, with what the viewer may dismiss.
func (s *Server) checksFor(r *http.Request, ref store.FindingRef) checksView {
	base := findingURL(ref.EngID, ref.Dir) + "/checks"
	v := checksView{URL: base, DismissURL: base + "/dismiss", UndismissURL: base + "/undismiss", Button: "Check"}
	if s.Rules == nil {
		return v
	}
	v.Enabled = true
	u := auth.UserFrom(r.Context())
	items := s.Rules.Lint(r.Context(), ref.F, rules.Fast)
	st, err := s.Store.CheckStatus(ref.EngID, ref.Dir)
	if err != nil && !errors.Is(err, store.ErrNoDB) {
		v.State, v.Error = "failed", err.Error()
	}
	ds := st.Dismissed
	dismissed := func(it rules.Violation) (db.Dismissal, bool) {
		d, ok := ds[db.DismissKey(it.Rule, store.QuoteHash(it.Quote))]
		return d, ok
	}
	for _, it := range items {
		if _, ok := dismissed(it); !ok && it.Level == "error" {
			v.Gate = append(v.Gate, it.Message)
		}
	}
	if st.HasRun {
		v.Error = st.Run.Error
		switch {
		case st.Running:
			v.State, v.Running = "running", true
			v.Button = fmt.Sprintf("Checking %d/%d", st.Run.Done, st.Run.Total)
		case st.Stale:
			v.State = "stale"
		case st.Run.State == db.RunFailed && st.Run.Error == rules.InvalidOutput:
			v.State = "invalid"
		default:
			v.State = st.Run.State
		}
		if !st.Running {
			items = nil
			for _, x := range st.Results {
				items = append(items, rules.Violation{Rule: x.Rule, Level: x.Level, Message: x.Message, Target: x.Target, Quote: x.Quote})
			}
		}
	}
	v.StateLabel = checkStateLabel[v.State]
	v.ReadOnly = s.Store.Archived(ref.EngID)
	for _, it := range items {
		row := checkRow{Rule: it.Rule, Level: it.Level, Message: it.Message, Quote: it.Quote, Where: where(it.Target)}
		notice := it.Target == "rules" || it.Target == "ai"
		if d, ok := dismissed(it); ok && !notice {
			row.By, row.At = d.By, stamp(d.At)
			row.CanDismiss = !v.ReadOnly && store.CanDismiss(u, ref.F.Meta, d.Level)
			v.Dismissed = append(v.Dismissed, row)
			continue
		}
		row.CanDismiss = !v.ReadOnly && !notice && store.CanDismiss(u, ref.F.Meta, it.Level)
		if it.Level == "error" {
			v.Errors++
		} else {
			v.Warnings++
		}
		v.Rows = append(v.Rows, row)
	}
	return v
}

// stamp shows a stored RFC 3339 time like the chat does.
func stamp(at string) string {
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return at
	}
	return t.Local().Format("2006-01-02 15:04")
}

// checksGet answers the checks panel alone (live refreshes).
func (s *Server) checksGet(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	s.exec(w, "finding.html", "checks_panel", s.checksFor(r, ref))
}

// checksRun starts a run of every rule kind (scripts and AI included) in
// the background and answers the panel, running.
func (s *Server) checksRun(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	if s.Rules == nil {
		http.NotFound(w, r)
		return
	}
	if _, err := s.Store.StartCheck(ref.EngID, ref.Dir, auth.UserFrom(r.Context())); err != nil {
		s.fail(w, err)
		return
	}
	s.exec(w, "finding.html", "checks_panel", s.checksFor(r, ref))
}

// checksDismiss dismisses (on) or restores the violation (rule, quote) and
// answers the panel.
func (s *Server) checksDismiss(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ref, ok := s.cvssRef(w, r)
		if !ok {
			return
		}
		u := auth.UserFrom(r.Context())
		rule, quote := r.FormValue("rule"), r.FormValue("quote")
		var err error
		if on {
			err = s.Store.Dismiss(ref.EngID, ref.Dir, rule, quote, u)
		} else {
			err = s.Store.Undismiss(ref.EngID, ref.Dir, rule, quote, u)
		}
		if errors.Is(err, store.ErrInvalidValue) {
			http.Error(w, strings.TrimPrefix(err.Error(), store.ErrInvalidValue.Error()+": "), http.StatusBadRequest)
			return
		}
		if err != nil {
			s.fail(w, err)
			return
		}
		s.exec(w, "finding.html", "checks_panel", s.checksFor(r, ref))
	}
}
