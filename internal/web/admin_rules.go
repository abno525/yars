package web

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/index"
	"yars/internal/rules"
	"yars/internal/store"
)

// maxScript bounds an uploaded rule script.
const maxScript = 1 << 20

type option struct {
	Value, Label string
	On           bool
	Muted        bool // shown greyed (an archived engagement)
}

// ruleRow is one rule in the admin table.
type ruleRow struct {
	ID, Message, Kind, KindLabel, Level, Target, File string
	On, Editing                                       bool
	Class                                             string // off (disabled), editing
}

// ruleForm is the rule editor: the values shown and the field errors (by
// field: id, pattern, check, script, ai, form).
type ruleForm struct {
	New                              bool
	Old, File                        string
	ID, Kind, Level, Target, Message string
	Mode, Pattern, Check, Script, AI string
	ICase                            bool
	Targets                          []option
	Builtins                         []rules.Builtin
	Errs                             map[string]string
}

// benchView is the test bench: its choices, and the result of a run on
// one finding (Rows) or on a whole engagement (All: one row per finding).
type benchView struct {
	Rules, Engs, Findings []option
	Ran, All              bool
	Hits                  int
	Rows                  []checkRow
	FRows                 []benchFinding
	Summary               string // "4 hits in 3 of 5 findings"
	At                    string // when it ran (HH:MM)
}

// benchFinding is one finding of an engagement run: its hits and the first
// quote.
type benchFinding struct {
	ID, Title, URL, Quote string
	Hits                  int
}

type rulesAdmin struct {
	Rows     []ruleRow
	Problems []string
	Filters  []link
	Edit     string
	Form     ruleForm
	Bench    benchView
	// RequireCheck: Sign off and Approve wait for a check run (a setting)
	RequireCheck bool
}

var kindLabels = map[string]string{"pattern": "Pattern", "builtin": "Built-in", "script": "Script", "ai": "AI"}

func (s *Server) routesAdminRules(mux *http.ServeMux) {
	h := func(f http.HandlerFunc) http.HandlerFunc {
		return s.adminOnly(func(w http.ResponseWriter, r *http.Request) {
			if s.Rules == nil {
				http.NotFound(w, r)
				return
			}
			f(w, r)
		})
	}
	mux.HandleFunc("GET /admin/rules", h(s.rulesPage))
	mux.HandleFunc("POST /admin/rules/save", h(s.ruleSave))
	mux.HandleFunc("POST /admin/rules/toggle", h(s.ruleToggle))
	mux.HandleFunc("POST /admin/rules/delete", h(s.ruleDelete))
	mux.HandleFunc("POST /admin/rules/require-check", h(s.requireCheckToggle))
	mux.HandleFunc("GET /admin/rules/bench", h(s.ruleBench))
	mux.HandleFunc("GET /admin/rules/bench/findings", h(s.benchFindings))
}

// targetLabel names a rule target for people.
func targetLabel(t string) string {
	switch {
	case t == "":
		return "Whole finding"
	case t == "title":
		return "Title"
	case t == "text":
		return "All text"
	case t == "sections":
		return "All sections"
	case t == "details":
		return "All details"
	case strings.HasPrefix(t, "section:"):
		return strings.TrimPrefix(t, "section:")
	case strings.HasPrefix(t, "details:"):
		return "Details · " + strings.TrimPrefix(t, "details:")
	}
	return t
}

// targetOptions lists the targets a rule can have, cur selected (kept even
// when the config no longer knows it).
func targetOptions(cfg config.Config, cur string) []option {
	vals := []string{"", "title", "text", "sections", "details"}
	for _, n := range cfg.Sections {
		vals = append(vals, "section:"+n)
	}
	for _, n := range cfg.DetailsRows {
		vals = append(vals, "details:"+n)
	}
	if !slices.Contains(vals, cur) {
		vals = append(vals, cur)
	}
	var out []option
	for _, v := range vals {
		out = append(out, option{Value: v, Label: targetLabel(v), On: v == cur})
	}
	return out
}

// formOf fills the editor from a saved rule.
func (s *Server) formOf(r rules.Rule) ruleForm {
	f := ruleForm{Old: r.ID, File: r.File, ID: r.ID, Kind: r.KindName(), Level: r.Level, Target: r.Target, Message: r.Message,
		Mode: "forbid", Pattern: r.RegexForbid, Check: r.Check, Script: r.Script, AI: r.AI}
	if r.RegexRequire != "" {
		f.Mode, f.Pattern = "require", r.RegexRequire
	}
	if p, ok := strings.CutPrefix(f.Pattern, "(?i)"); ok {
		f.Pattern, f.ICase = p, true
	}
	return f
}

func newRuleForm() ruleForm {
	return ruleForm{New: true, Kind: "pattern", Level: "error", Target: "text", Mode: "forbid"}
}

// fill completes a form with its choices.
func (s *Server) fill(f *ruleForm) {
	f.Targets = targetOptions(s.conf(), f.Target)
	f.Builtins = rules.Builtins
	if f.Errs == nil {
		f.Errs = map[string]string{}
	}
}

// rulesView builds the Rules tab around form f (the rule being edited, or a
// new one).
func (s *Server) rulesView(r *http.Request, p *page, f ruleForm) error {
	set := s.Rules.Rules()
	v := &p.Admin.Rules
	level := r.URL.Query().Get("level")
	if level != "error" && level != "warning" {
		level = ""
	}
	counts := map[string]int{}
	for _, x := range set.Rules {
		counts[x.Level]++
		if level != "" && x.Level != level {
			continue
		}
		row := ruleRow{ID: x.ID, Message: x.Message, Kind: x.KindName(), KindLabel: kindLabels[x.KindName()],
			Level: x.Level, Target: targetLabel(x.Target), File: x.File, On: x.On(), Editing: !f.New && x.ID == f.Old}
		var cls []string
		if !row.On {
			cls = append(cls, "off")
		}
		if row.Editing {
			cls = append(cls, "editing")
		}
		row.Class = strings.Join(cls, " ")
		v.Rows = append(v.Rows, row)
	}
	for _, pr := range set.Problems {
		v.Problems = append(v.Problems, pr.Message)
	}
	for _, l := range []struct{ key, label string }{{"", "All"}, {"error", "Errors"}, {"warning", "Warnings"}} {
		n := counts[l.key]
		if l.key == "" {
			n = len(set.Rules)
		}
		u := "/admin/rules"
		if l.key != "" {
			u += "?level=" + l.key
		}
		v.Filters = append(v.Filters, link{Label: l.label, URL: u, Active: l.key == level, Count: n})
	}
	v.RequireCheck = s.Store.RequireCheck()
	s.fill(&f)
	v.Form = f
	if !f.New {
		v.Edit = f.Old
	}
	// the bench: the rule being edited (else the first), the first engagement
	b := &v.Bench
	for i, x := range set.Rules {
		b.Rules = append(b.Rules, option{Value: x.ID, Label: x.ID, On: x.ID == f.Old || (f.New && i == 0)})
	}
	if p.engsErr != nil { // no bench rather than one over no engagements
		return p.engsErr
	}
	for i, e := range p.Engagements {
		b.Engs = append(b.Engs, option{Value: e.ID, Label: e.Name, On: i == 0})
	}
	if len(p.Engagements) > 0 {
		var err error
		if b.Findings, err = s.findingOptions(p.Engagements[0].ID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) findingOptions(eng string) ([]option, error) {
	rows, err := s.Index.Rows(index.Query{EngID: eng})
	if err != nil {
		return nil, err
	}
	var out []option
	for i, x := range rows {
		out = append(out, option{Value: x.Dir, Label: x.ID + " " + x.Title, On: i == 0})
	}
	return out, nil
}

func (s *Server) rulesPage(w http.ResponseWriter, r *http.Request) {
	p, err := s.adminBase(r, "rules")
	if err != nil {
		s.fail(w, err)
		return
	}
	f := newRuleForm()
	if id := r.URL.Query().Get("edit"); id != "" {
		x, ok := s.Rules.Rule(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		f = s.formOf(x)
	}
	if err := s.rulesView(r, p, f); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "admin.html", p)
}

// ruleErr is a problem with one field of the editor ("form" for the rule
// as a whole).
type ruleErr struct{ field, msg string }

func (e *ruleErr) Error() string { return e.msg }

var levels = []string{"error", "warning"}

// ruleFromForm reads the editor. It returns the form as typed, the rule,
// the uploaded script (name and content, if any) and the field errors.
func (s *Server) ruleFromForm(r *http.Request) (ruleForm, rules.Rule, string, []byte, map[string]string) {
	errs := map[string]string{}
	f := ruleForm{Old: r.FormValue("old"), ID: strings.TrimSpace(r.FormValue("id")), Kind: r.FormValue("kind"), Level: r.FormValue("level"),
		Target: r.FormValue("target"), Message: strings.TrimSpace(r.FormValue("message")), Mode: r.FormValue("mode"),
		Pattern: r.FormValue("pattern"), ICase: r.FormValue("icase") == "1", Check: r.FormValue("check"), AI: strings.TrimSpace(r.FormValue("ai"))}
	f.New = f.Old == ""
	if f.Mode != "require" {
		f.Mode = "forbid"
	}
	var old rules.Rule
	if !f.New {
		var ok bool
		if old, ok = s.Rules.Rule(f.Old); !ok {
			errs["form"] = "rule " + f.Old + " not found"
		}
		f.File, f.Script = old.File, old.Script
	}
	rule := rules.Rule{ID: f.ID, Level: f.Level, Message: f.Message, Target: f.Target, Enabled: old.Enabled}
	if !store.ValidID(f.ID) {
		errs["id"] = "letters, digits, . _ -"
	}
	if !slices.Contains(levels, f.Level) {
		errs["form"] = "level must be error or warning"
	}
	var scriptName string
	var script []byte
	switch f.Kind {
	case "pattern":
		p := f.Pattern
		if f.ICase {
			p = "(?i)" + p
		}
		if f.Pattern == "" {
			errs["pattern"] = "required"
		} else if _, err := regexp.Compile(p); err != nil {
			errs["pattern"] = err.Error()
		}
		if f.Mode == "require" {
			rule.RegexRequire, rule.RequireNonempty = p, old.RequireNonempty
		} else {
			rule.RegexForbid = p
		}
	case "builtin":
		if !slices.ContainsFunc(rules.Builtins, func(b rules.Builtin) bool { return b.ID == f.Check }) {
			errs["check"] = "choose a check"
		}
		rule.Check = f.Check
	case "script":
		file, hdr, err := r.FormFile("script")
		switch {
		case err == nil:
			defer file.Close()
			scriptName = filepath.Base(hdr.Filename)
			if !store.ValidID(scriptName) || strings.HasSuffix(scriptName, ".yaml") || strings.HasSuffix(scriptName, ".yml") {
				errs["script"] = "invalid file name"
				break
			}
			if script, err = io.ReadAll(io.LimitReader(file, maxScript+1)); err != nil || len(script) > maxScript {
				errs["script"] = "file too large"
				break
			}
			if len(script) == 0 {
				script = []byte{}
			}
			f.Script = scriptName
		case f.Script == "":
			errs["script"] = "upload a script"
		}
		rule.Script = f.Script
	case "ai":
		if f.AI == "" {
			errs["ai"] = "required"
		}
		rule.AI = f.AI
	default:
		errs["form"] = "choose a kind"
	}
	if len(errs) == 0 {
		if err := rule.Validate(); err != nil {
			errs["form"] = err.Error()
		}
	}
	return f, rule, scriptName, script, errs
}

const rulesRel = ".yars/rules/"

// editRules changes rule files with one commit: fn gets the rules as they
// are on disk and the reader of current files. The change is refused when
// loading the folder afterwards shows a problem it did not have before
// (rules.NewProblems, as a git push is).
func (s *Server) editRules(msg string, u config.User, fn func(cur *rules.Set, read func(string) ([]byte, error)) ([]store.SettingsFile, error)) error {
	dir := rules.DirFor(s.Store.Repo().Dir)
	var before *rules.Set
	return s.Store.EditSettings(msg, author(u), func(read func(string) ([]byte, error)) ([]store.SettingsFile, error) {
		before = rules.Load(dir)
		return fn(before, read)
	}, func() error {
		if ps := rules.NewProblems(before, rules.Load(dir)); len(ps) > 0 {
			return &ruleErr{"form", ps[0].Message}
		}
		return nil
	})
}

func findRule(set *rules.Set, id string) (rules.Rule, bool) {
	i := slices.IndexFunc(set.Rules, func(r rules.Rule) bool { return r.ID == id })
	if i < 0 {
		return rules.Rule{}, false
	}
	return set.Rules[i], true
}

// readRuleFile reads a rule file (nil when it does not exist).
func readRuleFile(read func(string) ([]byte, error), file string) ([]byte, error) {
	b, err := read(rulesRel + file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

func (s *Server) ruleSave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2*maxScript)
	u := auth.UserFrom(r.Context())
	f, rule, scriptName, script, errs := s.ruleFromForm(r)
	if len(errs) == 0 {
		err := s.editRules("rules: save "+rule.ID, u, func(cur *rules.Set, read func(string) ([]byte, error)) ([]store.SettingsFile, error) {
			file := rule.ID + ".yaml"
			if !f.New {
				old, ok := findRule(cur, f.Old)
				if !ok {
					return nil, &ruleErr{"form", "rule " + f.Old + " not found"}
				}
				file = old.File
			}
			if _, taken := findRule(cur, rule.ID); taken && rule.ID != f.Old {
				return nil, &ruleErr{"id", "id already used"}
			}
			b, err := readRuleFile(read, file)
			if err != nil {
				return nil, err
			}
			nb, err := rules.SetRule(b, f.Old, &rule)
			if err != nil {
				return nil, &ruleErr{"form", file + ": " + err.Error()}
			}
			files := []store.SettingsFile{{Path: rulesRel + file, Data: nb}}
			if script != nil {
				files = append(files, store.SettingsFile{Path: rulesRel + scriptName, Data: script, Exec: true})
			}
			return files, nil
		})
		var re *ruleErr
		switch {
		case err == nil:
			http.Redirect(w, r, "/admin/rules?edit="+rule.ID, http.StatusSeeOther)
			return
		case errors.As(err, &re):
			errs[re.field] = re.msg
		default:
			s.fail(w, err)
			return
		}
	}
	p, err := s.adminBase(r, "rules")
	if err != nil {
		s.fail(w, err)
		return
	}
	f.Errs = errs
	if err := s.rulesView(r, p, f); err != nil {
		s.fail(w, err)
		return
	}
	s.renderStatus(w, http.StatusBadRequest, "admin.html", p)
}

// back is where a table action returns: the editor that was open.
func back(r *http.Request) string {
	if id := r.FormValue("edit"); id != "" {
		return "/admin/rules?edit=" + id
	}
	return "/admin/rules"
}

func (s *Server) ruleToggle(w http.ResponseWriter, r *http.Request) {
	id, on := r.FormValue("id"), r.FormValue("on") == "1"
	verb := "disable"
	if on {
		verb = "enable"
	}
	err := s.editRules("rules: "+verb+" "+id, auth.UserFrom(r.Context()), func(cur *rules.Set, read func(string) ([]byte, error)) ([]store.SettingsFile, error) {
		x, ok := findRule(cur, id)
		if !ok {
			return nil, store.ErrNotFound
		}
		if x.On() == on {
			return nil, nil
		}
		x.Enabled = nil
		if !on {
			off := false
			x.Enabled = &off
		}
		b, err := readRuleFile(read, x.File)
		if err != nil {
			return nil, err
		}
		nb, err := rules.SetRule(b, id, &x)
		if err != nil {
			return nil, err
		}
		return []store.SettingsFile{{Path: rulesRel + x.File, Data: nb}}, nil
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, back(r), http.StatusSeeOther)
}

// requireCheckToggle turns Require Check (before Sign off and Approve) on
// or off; audited by the store.
func (s *Server) requireCheckToggle(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.SetRequireCheck(r.FormValue("on") == "1", auth.UserFrom(r.Context()).Username); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, back(r), http.StatusSeeOther)
}

func (s *Server) ruleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	err := s.editRules("rules: delete "+id, auth.UserFrom(r.Context()), func(cur *rules.Set, read func(string) ([]byte, error)) ([]store.SettingsFile, error) {
		x, ok := findRule(cur, id)
		if !ok {
			return nil, store.ErrNotFound
		}
		b, err := readRuleFile(read, x.File)
		if err != nil {
			return nil, err
		}
		nb, err := rules.SetRule(b, id, nil)
		if err != nil {
			return nil, err
		}
		return []store.SettingsFile{{Path: rulesRel + x.File, Data: nb}}, nil
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/admin/rules", http.StatusSeeOther)
}

// ruleBench runs one saved rule on one finding and answers the result;
// nothing is stored.
func (s *Server) ruleBench(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	x, ok := s.Rules.Rule(q.Get("rule"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if q.Get("all") == "1" {
		s.ruleBenchAll(w, r, x, q.Get("eng"))
		return
	}
	ref, err := s.Store.Finding(q.Get("eng"), q.Get("fid"))
	if err != nil {
		s.fail(w, err)
		return
	}
	v := benchView{Ran: true}
	for _, it := range s.Rules.RunRule(benchCaller(r, ref), x, rules.DocOf(ref.F)) {
		v.Rows = append(v.Rows, checkRow{Rule: it.Rule, Level: it.Level, Message: it.Message, Quote: it.Quote, Where: where(it.Target)})
	}
	v.Hits = len(v.Rows)
	s.exec(w, "admin.html", "bench_out", v)
}

// benchCaller is the request's context naming the admin and the finding a
// bench run is for (AI usage, D24).
func benchCaller(r *http.Request, ref store.FindingRef) context.Context {
	return rules.WithCaller(r.Context(), rules.Caller{User: auth.UserFrom(r.Context()).Username, Eng: ref.EngID, Fid: ref.F.Meta.ID})
}

// ruleBenchAll runs one saved rule on every finding of an engagement;
// nothing is stored.
func (s *Server) ruleBenchAll(w http.ResponseWriter, r *http.Request, x rules.Rule, eng string) {
	if !store.ValidID(eng) {
		http.NotFound(w, r)
		return
	}
	if _, ok := s.Index.Engagement(eng); !ok {
		http.NotFound(w, r)
		return
	}
	rows, err := s.Index.Rows(index.Query{EngID: eng})
	if err != nil {
		s.fail(w, err)
		return
	}
	v := benchView{Ran: true, All: true, At: time.Now().Format("15:04")}
	with := 0
	for _, row := range rows {
		ref, err := s.Store.Finding(eng, row.Dir)
		if err != nil {
			s.fail(w, err)
			return
		}
		f := benchFinding{ID: row.ID, Title: row.Title, URL: findingURL(eng, row.Dir)}
		for _, it := range s.Rules.RunRule(benchCaller(r, ref), x, rules.DocOf(ref.F)) {
			if f.Hits == 0 {
				f.Quote = it.Quote
			}
			f.Hits++
		}
		if f.Hits > 0 {
			with++
		}
		v.Hits += f.Hits
		v.FRows = append(v.FRows, f)
	}
	v.Summary = plural(v.Hits, "hit") + " in " + strconv.Itoa(with) + " of " + plural(len(rows), "finding")
	s.exec(w, "admin.html", "bench_out", v)
}

// benchFindings answers the bench's finding select for an engagement.
func (s *Server) benchFindings(w http.ResponseWriter, r *http.Request) {
	eng := r.URL.Query().Get("eng")
	if !store.ValidID(eng) {
		http.NotFound(w, r)
		return
	}
	opts, err := s.findingOptions(eng)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.exec(w, "admin.html", "bench_findings", benchView{Findings: opts})
}
