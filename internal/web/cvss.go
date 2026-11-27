package web

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/cvss"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

type cvssMetric struct {
	Key, Name          string
	Values             []cvss.Value
	Selected, Standard string
	SelectedName       string
	StandardName       string // the team standard's value name
	NonStandard        bool
	// Reason is kept for every metric (typed or stored) so a reason survives
	// toggling the metric back to standard and away again.
	Reason string
	// Cut: the stored reason was taken out of the field, since the metric
	// is no longer at the value it explains (cvssFromForm).
	Cut bool
}

// cutField prefixes the editor's hidden mark of a metric whose stored
// reason was taken out of its field.
const cutField = "reasoncut_"

type cvssReason struct{ Key, Metric, Standard, Value, Reason string }

// cvssView feeds both the read panel and the calculator editor.
type cvssView struct {
	Metrics                  []cvssMetric
	Vector, Score, Rating    string
	Foreign, Error, Base     string
	SevBase                  string
	RowBases                 map[string]string // each row's base (store.CVSSRowHashes): the editor's
	Complete, HasStored, OOB bool
	Locked                   bool
	ReadOnly                 bool // archived engagement: no Comment either
	// Unsaved: the editor as drawn is not what it opened with. Each metric
	// click draws it again with the server's values, so the browser's guard
	// sees no changed field; the form says it (data-unsaved).
	Unsaved                   bool
	Missing                   []string
	Reasons                   []cvssReason
	Severity                  string
	Severities                []string
	ViewURL, EditURL, CalcURL string
	SaveURL, SeverityURL      string
	LiveURL                   string // the read panel's live refresh
}

func (s *Server) routesCVSS(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/f/{fid}/cvss", s.cvssGet)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/cvss/edit", s.cvssEdit)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/cvss/calc", s.cvssCalc)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/cvss", s.cvssSave)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/severity", s.severitySave)
}

// buildCVSS renders sel (selected metric values) and reasons into a view.
func (s *Server) buildCVSS(ref store.FindingRef, sel cvss.Vector, reasons map[string]string) cvssView {
	m := ref.F.Meta
	cfg := s.conf()
	base := findingURL(ref.EngID, ref.Dir)
	v := cvssView{
		Base: store.CVSSHash(m), RowBases: store.CVSSRowHashes(m), SevBase: store.SeverityHash(m), Severity: cvss.Derive(m.CVSS, m.Severity), Severities: cfg.Severities,
		ViewURL: base + "/cvss", EditURL: base + "/cvss/edit", CalcURL: base + "/cvss/calc",
		SaveURL: base + "/cvss", SeverityURL: base + "/severity", ReadOnly: s.Store.Archived(ref.EngID),
		LiveURL: s.liveURL(base+"/cvss", ref),
	}
	if _, err := cvss.Parse(m.CVSS); err == nil {
		v.HasStored = true
	} else if strings.TrimSpace(m.CVSS) != "" {
		v.Foreign = m.CVSS
	}
	for _, mt := range cvss.Metrics {
		std := cfg.CVSS.Standard[mt.Key]
		cm := cvssMetric{Key: mt.Key, Name: mt.Name, Values: mt.Values, Selected: sel[mt.Key], Standard: std,
			SelectedName: cvss.ValueName(mt.Key, sel[mt.Key]), StandardName: cvss.ValueName(mt.Key, std), Reason: reasons[mt.Key]}
		if cm.Selected != "" && cfg.NonStandard(mt.Key, cm.Selected) {
			cm.NonStandard = true
			v.Reasons = append(v.Reasons, cvssReason{Key: mt.Key, Metric: mt.Name, Standard: cm.StandardName, Value: cvss.ValueName(mt.Key, cm.Selected), Reason: cm.Reason})
			if strings.TrimSpace(cm.Reason) == "" {
				v.Missing = append(v.Missing, mt.Name)
			}
		}
		v.Metrics = append(v.Metrics, cm)
	}
	v.Vector = sel.String()
	if len(sel) == 0 {
		v.Vector = ""
	}
	if sel.Complete() {
		v.Complete = true
		sc, _ := cvss.Score(sel)
		v.Score, v.Rating = cvss.FormatScore(sc), cvss.Rating(sc)
	}
	return v
}

// cvssPanel is the read view of the stored CVSS state.
func (s *Server) cvssPanel(ref store.FindingRef) cvssView {
	sel, err := cvss.Parse(ref.F.Meta.CVSS)
	if err != nil {
		sel = cvss.Vector{}
	}
	return s.buildCVSS(ref, sel, ref.F.Meta.CVSSReasons)
}

// cvssStart is the editor's initial state: stored vector, else team standards.
func (s *Server) cvssStart(ref store.FindingRef) cvssView {
	sel, err := cvss.Parse(ref.F.Meta.CVSS)
	if err != nil {
		sel = cvss.Vector{}
		for _, mt := range cvss.Metrics {
			if std, ok := s.conf().CVSS.Standard[mt.Key]; ok {
				sel[mt.Key] = std
			}
		}
	}
	return s.buildCVSS(ref, sel, ref.F.Meta.CVSSReasons)
}

// fromForm reads radios, an optional pasted vector, and reason_<KEY> fields.
func (s *Server) cvssFromForm(ref store.FindingRef, form url.Values) cvssView {
	sel := cvss.Vector{}
	for _, mt := range cvss.Metrics {
		if val := form.Get(mt.Key); cvss.Valid(mt.Key, val) {
			sel[mt.Key] = val
		}
	}
	var pasteErr error
	pasted30 := false
	if p := strings.TrimSpace(form.Get("paste")); p != "" {
		var pv cvss.Vector
		if pv, pasteErr = cvss.ParsePartial(p); pasteErr == nil {
			sel = pv
			pasted30 = cvss.Version(p) == "3.0"
		}
	}
	// A stored reason explains the stored value of its metric. At another
	// value the editor does not offer it: the field is emptied once (cut),
	// and what it holds after that is the user's. Back at the stored value
	// an emptied field shows the stored reason again.
	stored := ref.F.Meta.CVSSReasons
	was, err := cvss.ParsePartial(ref.F.Meta.CVSS)
	if err != nil {
		was = cvss.Vector{}
	}
	reasons, cut := map[string]string{}, map[string]bool{}
	for _, mt := range cvss.Metrics {
		k := mt.Key
		posted, has := form.Get("reason_"+k), form.Has("reason_"+k)
		marked := form.Has(cutField + k)
		r := stored[k]
		if has {
			r = posted
		}
		if stored[k] != "" {
			switch moved := sel[k] != was[k]; {
			case moved && marked && has:
				cut[k] = true
			case moved && (!has || strings.TrimSpace(posted) == stored[k]):
				r, cut[k] = "", true
			case !moved && marked && strings.TrimSpace(r) == "":
				r = stored[k]
			}
		}
		if has || r != "" {
			reasons[k] = r
		}
	}
	v := s.buildCVSS(ref, sel, reasons)
	for i := range v.Metrics {
		v.Metrics[i].Cut = cut[v.Metrics[i].Key]
	}
	// against what the editor opens with, not the stored vector: a finding
	// without one opens with the team standards picked
	if start := s.cvssStart(ref); v.Vector != start.Vector || !slices.Equal(v.Reasons, start.Reasons) {
		v.Unsaved = true
	}
	if b := form.Get("base"); b != "" {
		v.Base = b
	}
	// the bases the editor was opened with go along each recalculation
	if posted := cvssBases(form); len(posted) > 0 {
		v.RowBases = posted
	}
	switch {
	case pasteErr != nil:
		v.Error = "Could not read pasted vector: " + pasteErr.Error()
	case pasted30:
		// taken as the 3.1 vector of the same metrics (the score is the same)
		v.Error = said30
	}
	return v
}

// said30 is the message line after a CVSS:3.0 vector was pasted: in the
// editor after Apply, and in the panel after a Save that took the paste.
const said30 = "CVSS:3.0 vector, stored as CVSS:3.1"

func (s *Server) cvssRef(w http.ResponseWriter, r *http.Request) (store.FindingRef, bool) {
	ref, err := s.Store.Finding(r.PathValue("eng"), r.PathValue("fid"))
	if err != nil {
		s.fail(w, err)
		return ref, false
	}
	return ref, true
}

// editRef loads the finding and answers 403 unless the user may edit it.
func (s *Server) editRef(w http.ResponseWriter, r *http.Request) (store.FindingRef, bool) {
	ref, ok := s.cvssRef(w, r)
	return ref, ok && s.allowEdit(w, r, ref)
}

// locked reports whether the user may not change the finding: its status,
// or an archived engagement.
func (s *Server) locked(r *http.Request, ref store.FindingRef) bool {
	return !workflow.CanEdit(auth.UserFrom(r.Context()), ref.F.Meta) || s.Store.Archived(ref.EngID)
}

// liveRef is cvssRef for a read panel's GET: a live refresh of a panel
// that is still current gets 204; one of a finding that is gone reloads
// the page (HX-Refresh), which then says so.
func (s *Server) liveRef(w http.ResponseWriter, r *http.Request) (store.FindingRef, bool) {
	ref, err := s.Store.Finding(r.PathValue("eng"), r.PathValue("fid"))
	if err != nil {
		if r.URL.Query().Get("live") != "" && errors.Is(err, store.ErrNotFound) {
			w.Header().Set("HX-Refresh", "true")
		}
		s.fail(w, err)
		return ref, false
	}
	return ref, !s.unchanged(w, r, ref)
}

func (s *Server) cvssGet(w http.ResponseWriter, r *http.Request) {
	if ref, ok := s.liveRef(w, r); ok {
		v := s.cvssPanel(ref)
		v.Locked = s.locked(r, ref)
		s.exec(w, "finding.html", "cvss_panel", v)
	}
}

func (s *Server) cvssEdit(w http.ResponseWriter, r *http.Request) {
	if ref, ok := s.editRef(w, r); ok {
		s.exec(w, "finding.html", "cvss_editor", s.cvssStart(ref))
	}
}

func (s *Server) cvssCalc(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.editRef(w, r) // the editor's: refused where the editor is
	if !ok {
		return
	}
	r.ParseForm()
	s.exec(w, "finding.html", "cvss_editor", s.cvssFromForm(ref, r.PostForm))
}

func (s *Server) cvssSave(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.editRef(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	form := r.PostForm
	v := s.cvssFromForm(ref, form)
	vector := ""
	reasons := map[string]string{}
	said := "" // the saved panel's message line
	if form.Get("action") != "clear" {
		if v.Error == said30 { // Save takes the paste field without Apply
			said = said30
		}
		if !v.Complete {
			v.Error = "All 8 base metrics required"
			s.execStatus(w, http.StatusBadRequest, "finding.html", "cvss_editor", v)
			return
		}
		vector = v.Vector
		for _, m := range v.Metrics {
			// the reason as the editor shows it: a stored one is not sent
			// along for another value (cvssFromForm)
			if m.NonStandard && form.Has("reason_"+m.Key) {
				reasons[m.Key] = m.Reason
			}
		}
	}
	var err error
	if bases := cvssBases(form); len(bases) > 0 {
		// per row: only the rows the user changed are written, each checked
		// against the base it was read with
		ch := store.CVSSChange{Reasons: map[string]string{}, Bases: map[string]string{}}
		if b, ok := bases[store.CVSSRow]; !ok || store.RowHash(vector) != b {
			ch.Vector, ch.Bases[store.CVSSRow] = &vector, b
		}
		sel, _ := cvss.ParsePartial(vector)
		for k, val := range reasons {
			// the user's change: the reason, or the value it explains
			if b, ok := bases[k]; !ok || store.ReasonHash(sel[k], val) != b {
				ch.Reasons[k], ch.Bases[k] = val, b
			}
		}
		if form.Get("action") == "clear" && ch.Vector == nil && len(ref.F.Meta.CVSSReasons) > 0 {
			// reasons without a vector (a pushed file): the clear takes them
			ch.Vector, ch.Bases[store.CVSSRow] = &vector, bases[store.CVSSRow]
		}
		switch {
		case ch.Vector == nil && len(ch.Reasons) == 0:
		case ch.Vector == nil && v.HasStored:
			_, err = s.Store.UpdateCVSSRows(ref.EngID, ref.Dir, ch, auth.UserFrom(r.Context()))
		default:
			if ch.Vector == nil {
				ch.Vector, ch.Bases[store.CVSSRow] = &vector, bases[store.CVSSRow]
			}
			_, err = s.Store.UpdateCVSSRows(ref.EngID, ref.Dir, ch, auth.UserFrom(r.Context()))
		}
	} else {
		err = s.Store.UpdateCVSS(ref.EngID, ref.Dir, vector, reasons, form.Get("base"), auth.UserFrom(r.Context()))
	}
	switch {
	case errors.Is(err, store.ErrConflict):
		v.Error = conflictText
		v.Base, v.RowBases = store.CVSSHash(ref.F.Meta), store.CVSSRowHashes(ref.F.Meta)
		s.execStatus(w, http.StatusConflict, "finding.html", "cvss_editor", v)
		return
	case errors.Is(err, store.ErrInvalidValue):
		v.Error = err.Error()
		s.execStatus(w, http.StatusBadRequest, "finding.html", "cvss_editor", v)
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	s.panelSaying(w, ref, said)
}

// conflictText is the conflict state of an editor: it never blames anyone
// (the change may be the user's own, in another tab or by MCP).
const conflictText = "The finding changed since you read it"

// cvssBases reads the editor's per-row bases (base:cvss, base:<METRIC>).
func cvssBases(form url.Values) map[string]string {
	out := map[string]string{}
	for k, vs := range form {
		if name, ok := strings.CutPrefix(k, baseField); ok && len(vs) > 0 {
			out[name] = vs[0]
		}
	}
	return out
}

func (s *Server) panelAfterWrite(w http.ResponseWriter, ref store.FindingRef) {
	s.panelSaying(w, ref, "")
}

// panelSaying is the read panel after a write, with said ("" for none) on
// its message line.
func (s *Server) panelSaying(w http.ResponseWriter, ref store.FindingRef, said string) {
	ref, err := s.Store.Finding(ref.EngID, ref.Dir)
	if err != nil {
		s.fail(w, err)
		return
	}
	v := s.cvssPanel(ref)
	v.OOB = true
	v.Error = said
	s.exec(w, "finding.html", "cvss_panel", v)
}

func (s *Server) severitySave(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.editRef(w, r)
	if !ok {
		return
	}
	err := s.Store.UpdateSeverity(ref.EngID, ref.Dir, r.FormValue("severity"), r.FormValue("base"), auth.UserFrom(r.Context()))
	if errors.Is(err, store.ErrConflict) {
		// Show the current (other person's) severity so the user can decide again.
		v := s.cvssPanel(ref)
		v.OOB = true
		v.Error = conflictText
		s.execStatus(w, http.StatusConflict, "finding.html", "cvss_panel", v)
		return
	}
	if errors.Is(err, store.ErrInvalidValue) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.panelAfterWrite(w, ref)
}
