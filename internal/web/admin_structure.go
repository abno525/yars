package web

import (
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/cvss"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/index"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/store"
)

// structList is one editable list of Admin › Structure.
type structList struct {
	Key, Field, Title, Placeholder string
	Items                          []structItem
	New                            string
}

type structItem struct {
	Value  string
	Was    string // the name on disk this row had; "" = added
	Used   string // "" = not counted
	Locked bool   // a CVSS rating: can't be renamed or removed
	Last   bool
	Sev    bool // shows its colour
}

type structMetric struct {
	Key, Name  string
	Values     []cvss.Value
	Std, Was   string // the standard as edited; as saved ("" = none)
	NonStd     int
	HasStdData bool
}

type structView struct {
	Lists   []structList
	Metrics []structMetric
	Version string
	Changes string
	Error   string
	Saved   string // commit of the last save
	Base    string // hash of config.yaml the page was made from
}

const configRel = ".yars/config.yaml"

// the lists, in page order: form field, title
var structLists = []struct{ key, field, title, placeholder string }{
	{"section", "section", "Sections", "New section"},
	{"detail", "detail", "Details rows", "New details row"},
	{"severity", "severity", "Severities", "New severity"},
	{"report", "report", "Report sections", "New report section"},
}

func (s *Server) routesAdminStructure(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/structure", s.adminOnly(s.structurePage))
	mux.HandleFunc("POST /admin/structure", s.adminOnly(s.structurePost))
}

func listOf(c config.Config, key string) []string {
	switch key {
	case "section":
		return c.Sections
	case "detail":
		return c.DetailsRows
	case "severity":
		return c.Severities
	}
	return c.ReportSections
}

func setList(c *config.Config, key string, v []string) {
	switch key {
	case "section":
		c.Sections = v
	case "detail":
		c.DetailsRows = v
	case "severity":
		c.Severities = v
	default:
		c.ReportSections = v
	}
}

// structWas holds, per list key and beside the list, the name each row had
// when the page was made ("" = none: an added row). It is what tells a
// rename from a removal with an addition.
type structWas map[string][]string

// structFromForm reads the edited structure (empty names dropped) and each
// row's original name as posted, read as pairs so a dropped row takes its
// original with it. A form without the originals has none.
func structFromForm(form url.Values, cur config.Config) (config.Config, structWas) {
	c := cur
	was := structWas{}
	for _, l := range structLists {
		var v, w []string
		orig := form["was_"+l.field]
		if len(orig) != len(form[l.field]) {
			orig = nil
		}
		for i, x := range form[l.field] {
			if x = strings.TrimSpace(x); x != "" {
				v = append(v, x)
				if orig != nil {
					w = append(w, strings.TrimSpace(orig[i]))
				} else {
					w = append(w, "")
				}
			}
		}
		setList(&c, l.key, v)
		was[l.key] = w
	}
	c.CVSS.Version = form.Get("version")
	if c.CVSS.Version == "" {
		c.CVSS.Version = cur.CVSS.Version
	}
	c.CVSS.Standard = map[string]string{}
	for _, m := range cvss.Metrics {
		if v := form.Get("std_" + m.Key); v != "" && v != "-" {
			c.CVSS.Standard[m.Key] = v
		}
	}
	return c, was
}

// cleanWas is was with only the originals that can be one, against the
// structure on disk. The names come from the client, so a row is a rename
// (original differs from its name) only when the original is a name on disk
// that no row holds any more, one row alone claims it, the new name is not
// on disk, and it is not a locked rating severity. Any other row is itself
// when its name is on disk, and added ("") when not.
func cleanWas(c config.Config, was structWas, disk config.Config) structWas {
	out := structWas{}
	for _, l := range structLists {
		names, on := listOf(c, l.key), listOf(disk, l.key)
		claims := map[string]int{}
		for i := range names {
			if i < len(was[l.key]) {
				claims[was[l.key][i]]++
			}
		}
		w := make([]string, len(names))
		for i, x := range names {
			o := ""
			if i < len(was[l.key]) {
				o = was[l.key][i]
			}
			locked := l.key == "severity" && slices.Contains(config.RatingSeverities, o)
			switch {
			case slices.Contains(on, x):
				w[i] = x
			case o != "" && slices.Contains(on, o) && !slices.Contains(names, o) && claims[o] == 1 && !locked:
				w[i] = o
			}
		}
		out[l.key] = w
	}
	return out
}

// renamesOf is the renames (old → new) per list key: the rows whose
// original differs from their name. was must be clean (cleanWas).
func renamesOf(c config.Config, was structWas) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, l := range structLists {
		for i, x := range listOf(c, l.key) {
			if o := was[l.key][i]; o != "" && o != x {
				if out[l.key] == nil {
					out[l.key] = map[string]string{}
				}
				out[l.key][o] = x
			}
		}
	}
	return out
}

// applyOp moves, removes or adds one list item, with its original name.
func applyOp(c *config.Config, was structWas, op string, form url.Values) {
	parts := strings.Split(op, ":")
	if len(parts) < 2 {
		return
	}
	key := parts[1]
	if !slices.ContainsFunc(structLists, func(l struct{ key, field, title, placeholder string }) bool { return l.key == key }) {
		return
	}
	v := slices.Clone(listOf(*c, key))
	w := was[key]
	if parts[0] == "add" {
		if x := strings.TrimSpace(form.Get("new_" + key)); x != "" {
			v = append(v, x)
			was[key] = append(w, "")
		}
		setList(c, key, v)
		return
	}
	if len(parts) != 3 {
		return
	}
	i, err := strconv.Atoi(parts[2])
	if err != nil || i < 0 || i >= len(v) {
		return
	}
	switch parts[0] {
	case "up":
		if i > 0 {
			v[i-1], v[i] = v[i], v[i-1]
			w[i-1], w[i] = w[i], w[i-1]
		}
	case "down":
		if i+1 < len(v) {
			v[i+1], v[i] = v[i], v[i+1]
			w[i+1], w[i] = w[i], w[i+1]
		}
	case "del":
		if key != "severity" || !slices.Contains(config.RatingSeverities, v[i]) {
			v = slices.Delete(v, i, i+1)
			was[key] = slices.Delete(w, i, i+1)
		}
	}
	setList(c, key, v)
}

// changesOf counts what differs from the saved structure: per list the
// larger of names added and removed (a rename counts once), or one for a
// new order; plus each metric whose standard moved.
func changesOf(a, b config.Config) int {
	n := 0
	for _, l := range structLists {
		x, y := listOf(a, l.key), listOf(b, l.key)
		add, del := 0, 0
		for _, v := range y {
			if !slices.Contains(x, v) {
				add++
			}
		}
		for _, v := range x {
			if !slices.Contains(y, v) {
				del++
			}
		}
		switch {
		case add > 0 || del > 0:
			n += max(add, del)
		case !slices.Equal(x, y):
			n++
		}
	}
	for _, m := range cvss.Metrics {
		if a.CVSS.Standard[m.Key] != b.CVSS.Standard[m.Key] {
			n++
		}
	}
	if a.CVSS.Version != b.CVSS.Version {
		n++
	}
	return n
}

// checkStructure rejects names that can't be used (the rules a git push
// of config.yaml is held to as well).
func checkStructure(c config.Config) error { return store.CheckStructure(c) }

// diskStructure is the structure as config.yaml has it now (a push
// included) and a hash of the file's bytes: the base a save must match.
func (s *Server) diskStructure() (config.Config, string) {
	dir := s.Store.Repo().Dir
	c := s.conf()
	raw, err := os.ReadFile(config.ConfigPath(dir))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.log().Error("structure: config.yaml is not read", "err", err)
		return c, ""
	}
	// loaded after the bytes were hashed: at worst newer than the base,
	// which makes a save a conflict, never an overwrite
	if l, err := config.Load(dir); err != nil {
		s.log().Error("structure: config.yaml does not load", "err", err)
	} else {
		c.Sections, c.DetailsRows, c.Severities, c.ReportSections, c.CVSS = l.Sections, l.DetailsRows, l.Severities, l.ReportSections, l.CVSS
	}
	return c, store.BodyHash(string(raw))
}

// structureView shows the edited structure c against the saved one, each
// row with its original name (was, cleaned here; nil = no row was renamed).
func (s *Server) structureView(c, saved config.Config, was structWas) (structView, error) {
	was = cleanWas(c, was, saved)
	v := structView{Version: c.CVSS.Version}
	if n := changesOf(saved, c); n > 0 {
		v.Changes = plural(n, "change")
	}
	rows, err := s.Index.Rows(index.Query{})
	if err != nil {
		return v, err
	}
	sevUse, detUse := map[string]int{}, map[string]int{}
	nonStd := map[string]int{}
	for _, r := range rows {
		sevUse[r.Severity]++
		if r.Meta == nil {
			continue
		}
		for k, x := range r.Meta.Details {
			if strings.TrimSpace(x) != "" {
				detUse[k]++
			}
		}
		if vec, err := cvss.Parse(r.Meta.CVSS); err == nil {
			for _, m := range cvss.Metrics {
				if std, ok := c.CVSS.Standard[m.Key]; ok && vec[m.Key] != std {
					nonStd[m.Key]++
				}
			}
		}
	}
	for _, l := range structLists {
		sl := structList{Key: l.key, Field: l.field, Title: l.title, Placeholder: l.placeholder}
		items := listOf(c, l.key)
		for i, x := range items {
			it := structItem{Value: x, Was: was[l.key][i], Last: i == len(items)-1}
			switch l.key {
			case "severity":
				it.Used, it.Sev = strconv.Itoa(sevUse[x]), true
				it.Locked = slices.Contains(config.RatingSeverities, x)
			case "detail":
				it.Used = strconv.Itoa(detUse[x])
			}
			sl.Items = append(sl.Items, it)
		}
		v.Lists = append(v.Lists, sl)
	}
	for _, m := range cvss.Metrics {
		v.Metrics = append(v.Metrics, structMetric{Key: m.Key, Name: m.Name, Values: m.Values, Std: c.CVSS.Standard[m.Key],
			Was: saved.CVSS.Standard[m.Key], NonStd: nonStd[m.Key]})
	}
	return v, nil
}

// structureRender shows the edited structure c against disk (config.yaml
// as it is), with base the hash the page's save is checked against.
func (s *Server) structureRender(w http.ResponseWriter, r *http.Request, status int, c, disk config.Config, was structWas, base, errMsg, saved string) {
	s.adminPage(w, r, "structure", status, func(p *page) error {
		v, err := s.structureView(c, disk, was)
		if err != nil {
			return err
		}
		v.Error, v.Saved, v.Base = errMsg, saved, base
		p.Admin.Structure = v
		return nil
	})
}

func (s *Server) structurePage(w http.ResponseWriter, r *http.Request) {
	saved := r.URL.Query().Get("saved")
	if !isHexID(saved) {
		saved = ""
	}
	disk, base := s.diskStructure()
	s.structureRender(w, r, http.StatusOK, disk, disk, nil, base, "", saved)
}

func isHexID(h string) bool {
	if len(h) < 7 || len(h) > 40 {
		return false
	}
	for _, c := range h {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func (s *Server) structurePost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	disk, _ := s.diskStructure()
	c, was := structFromForm(r.PostForm, disk)
	base := r.PostForm.Get("base") // the page's, kept through moves and adds
	op := r.PostForm.Get("op")
	if op != "save" {
		applyOp(&c, was, op, r.PostForm)
		s.structureRender(w, r, http.StatusOK, c, disk, was, base, "", "")
		return
	}
	if err := checkStructure(c); err != nil {
		s.structureRender(w, r, http.StatusBadRequest, c, disk, was, base, err.Error(), "")
		return
	}
	// the renames of this save: the rows that kept their identity under a
	// new name, and nothing else
	renames := renamesOf(c, cleanWas(c, was, disk))
	// Q10: a name findings or templates still use cannot be removed (a
	// rename is not a removal: the rename reaches them below)
	if msg, err := s.removedInUse(disk, c, renames); err != nil || msg != "" {
		if err != nil {
			msg = err.Error()
		}
		s.structureRender(w, r, http.StatusBadRequest, c, disk, was, base, msg, "")
		return
	}
	// Q10: nor a rename that would stop at a finding or template (text under
	// both names): tried before the save, so none is left behind
	for _, l := range renameLists(renames) {
		if err := s.Store.RenameConflict(l.list, l.renames); err != nil {
			s.structureRender(w, r, http.StatusBadRequest, c, disk, was, base, err.Error(), "")
			return
		}
	}
	u := auth.UserFrom(r.Context())
	dir := s.Store.Repo().Dir
	var loaded config.Config
	// the rule targets that name a renamed section or details row follow it
	// in the same commit: the structure and the rules change together or
	// not at all (no database row belongs to a rule's target)
	targets := ruleTargets(renames)
	rulesDir := rules.DirFor(dir)
	var rulesBefore *rules.Set
	retargeted := 0
	err := s.Store.EditSettings("config: report structure", author(u), func(read func(string) ([]byte, error)) ([]store.SettingsFile, error) {
		raw, err := read(configRel)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if store.BodyHash(string(raw)) != base {
			return nil, store.ErrConflict
		}
		b, err := config.SetStructure(raw, c)
		if err != nil {
			return nil, err
		}
		files := []store.SettingsFile{{Path: configRel, Data: b}}
		if retargeted = 0; len(targets) > 0 {
			rulesBefore = rules.Load(rulesDir)
			rf, n, err := retargetRules(rulesDir, read, targets)
			if err != nil {
				return nil, err
			}
			files, retargeted = append(files, rf...), n
		}
		return files, nil
	}, func() error {
		var err error
		if loaded, err = config.Load(dir); err != nil {
			return err
		}
		// as the rule editor and a push: no change that breaks a rule file
		if rulesBefore != nil {
			if ps := rules.NewProblems(rulesBefore, rules.Load(rulesDir)); len(ps) > 0 {
				return errors.New(ps[0].Message)
			}
		}
		return nil
	})
	if errors.Is(err, store.ErrConflict) {
		// the page shows the edits against the file as it is now; saving
		// again overwrites it knowingly
		now, nowBase := s.diskStructure()
		// (a row whose original is gone from the new file reads as added)
		s.structureRender(w, r, http.StatusConflict, c, now, was, nowBase, "The structure changed since you read it", "")
		return
	}
	if err != nil {
		s.structureRender(w, r, http.StatusBadRequest, c, disk, was, base, strings.TrimPrefix(err.Error(), "config: "), "")
		return
	}
	if retargeted > 0 {
		// counts only: a rule's ID and a section's name are the admin's text
		s.log().Info("structure: rule targets follow the rename", "user", u.Username, "rules", retargeted)
	}
	// read again as it is on disk now, in order with a push's: never a
	// stale copy applied after a newer one
	if now, err := s.Store.ReloadConfig(); err == nil {
		loaded = now
	} else {
		s.setConfig(loaded)
	}
	// the renames of the form, less any the file on disk no longer holds (a
	// push that came in between): the old name gone and the new one there
	for _, l := range structLists {
		on := listOf(loaded, l.key)
		for o, n := range renames[l.key] {
			if slices.Contains(on, o) || !slices.Contains(on, n) {
				delete(renames[l.key], o)
			}
		}
	}
	head, _ := gitrepo.ReadHead(dir)
	// renamed report sections keep their text in every engagement
	if rn := renames["report"]; len(rn) > 0 {
		if err := s.Store.RenameReportSections(rn, author(u)); err != nil {
			s.log().Error("structure: report sections are not renamed", "user", u.Username, "err", err)
		}
	}
	// Q10: renamed sections, details rows and severities are renamed inside
	// every finding and template
	done := 0
	for _, l := range renameLists(renames) {
		changed, err := s.Store.RenameNames(l.list, l.renames, author(u))
		done += len(changed)
		if err != nil {
			now, nowBase := s.diskStructure()
			s.structureRender(w, r, http.StatusInternalServerError, now, now, nil, nowBase,
				"Renamed in "+plural(done, "finding")+"; then: "+err.Error(), "")
			return
		}
	}
	if len(head) > 7 {
		head = head[:7]
	}
	http.Redirect(w, r, "/admin/structure?saved="+head, http.StatusSeeOther)
}

// ruleTargets are the rule targets a save's renames change: section:<old>
// and details:<old> to the new name. Severities are no targets.
func ruleTargets(renames map[string]map[string]string) map[string]string {
	out := map[string]string{}
	for key, prefix := range map[string]string{"section": "section:", "detail": "details:"} {
		for o, n := range renames[key] {
			if o != n {
				out[prefix+o] = prefix + n
			}
		}
	}
	return out
}

// retargetRules gives every rule file of the rules folder dir whose rules
// name a target of targets its new content (rules.Retarget), read through
// read; n is how many rules changed. A file that does not read as a list of
// rules is left as it is: it reports its own problem on every check.
func retargetRules(dir string, read func(string) ([]byte, error), targets map[string]string) (files []store.SettingsFile, n int, err error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !(strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")) {
			continue
		}
		b, err := read(rulesRel + name)
		if err != nil {
			return nil, 0, err
		}
		nb, changed, err := rules.Retarget(b, targets)
		if err != nil || changed == 0 {
			continue
		}
		files = append(files, store.SettingsFile{Path: rulesRel + name, Data: nb})
		n += changed
	}
	return files, n, nil
}

// nameRenames is one list's renames (old → new) for Store.RenameNames.
type nameRenames struct {
	list    string // "section", "details row", "severity"
	renames map[string]string
}

// renameLists is the renames of the finding sections, details rows and
// severities (renamesOf), under the names Store.RenameNames knows.
func renameLists(renames map[string]map[string]string) []nameRenames {
	var out []nameRenames
	for _, l := range []nameRenames{
		{"section", renames["section"]},
		{"details row", renames["detail"]},
		{"severity", renames["severity"]},
	} {
		if len(l.renames) > 0 {
			out = append(out, l)
		}
	}
	return out
}

// removedInUse is the refusal for a structure that removes a name findings
// or templates still use (NameUse.String of the first, as a push gives it),
// "" when none does. Renamed names do not count: they are renamed in place.
func (s *Server) removedInUse(was, now config.Config, renames map[string]map[string]string) (string, error) {
	chk := now
	chk.Sections = slices.Clone(now.Sections)
	chk.DetailsRows = slices.Clone(now.DetailsRows)
	chk.Severities = slices.Clone(now.Severities)
	for _, l := range renameLists(renames) {
		for old := range l.renames {
			switch l.list {
			case "section":
				chk.Sections = append(chk.Sections, old)
			case "details row":
				chk.DetailsRows = append(chk.DetailsRows, old)
			case "severity":
				chk.Severities = append(chk.Severities, old)
			}
		}
	}
	tpls, err := s.Store.Templates()
	if err != nil {
		return "", err
	}
	extra := map[string]*finding.Finding{}
	for _, t := range tpls {
		extra["template "+t.Slug+".md"] = t.F
	}
	uses, err := s.Store.DroppedInUse(was, chk, extra)
	if err != nil || len(uses) == 0 {
		return "", err
	}
	return uses[0].String(), nil
}
