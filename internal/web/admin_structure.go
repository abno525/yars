package web

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/cvss"
	"yars/internal/gitrepo"
	"yars/internal/index"
	"yars/internal/store"
)

// structList is one editable list of Admin › Structure.
type structList struct {
	Key, Field, Title, Placeholder string
	Items                          []structItem
	New                            string
}

type structItem struct {
	Value  string
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

// structFromForm reads the edited structure (empty names dropped).
func structFromForm(form url.Values, cur config.Config) config.Config {
	c := cur
	for _, l := range structLists {
		var v []string
		for _, x := range form[l.field] {
			if x = strings.TrimSpace(x); x != "" {
				v = append(v, x)
			}
		}
		setList(&c, l.key, v)
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
	return c
}

// applyOp moves, removes or adds one list item.
func applyOp(c *config.Config, op string, form url.Values) {
	parts := strings.Split(op, ":")
	if len(parts) < 2 {
		return
	}
	key := parts[1]
	if !slices.ContainsFunc(structLists, func(l struct{ key, field, title, placeholder string }) bool { return l.key == key }) {
		return
	}
	v := slices.Clone(listOf(*c, key))
	if parts[0] == "add" {
		if x := strings.TrimSpace(form.Get("new_" + key)); x != "" {
			v = append(v, x)
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
		}
	case "down":
		if i+1 < len(v) {
			v[i+1], v[i] = v[i], v[i+1]
		}
	case "del":
		if key != "severity" || !slices.Contains(config.RatingSeverities, v[i]) {
			v = slices.Delete(v, i, i+1)
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

// renamesOf pairs the names that left a list with the names that joined
// it, in order, when as many left as joined (old → new); otherwise a
// rename can't be told from a removal and an addition, and none is made.
func renamesOf(was, now []string) map[string]string {
	var gone, added []string
	for _, x := range was {
		if !slices.Contains(now, x) {
			gone = append(gone, x)
		}
	}
	for _, x := range now {
		if !slices.Contains(was, x) {
			added = append(added, x)
		}
	}
	if len(gone) == 0 || len(gone) != len(added) {
		return nil
	}
	out := map[string]string{}
	for i, x := range gone {
		out[x] = added[i]
	}
	return out
}

// checkStructure rejects names that can't be used.
func checkStructure(c config.Config) error {
	files := map[string]string{} // report section file → name
	for _, x := range c.ReportSections {
		f := store.ReportFile(x)
		if o, ok := files[f]; ok && !strings.EqualFold(o, x) {
			return fmt.Errorf("Report sections: %q and %q share a file name", o, x)
		}
		files[f] = x
	}
	for _, l := range structLists {
		seen := map[string]bool{}
		v := listOf(c, l.key)
		if len(v) == 0 && l.key != "detail" {
			return fmt.Errorf("%s: at least one", l.title)
		}
		for _, x := range v {
			k := strings.ToLower(x)
			switch {
			case seen[k]:
				return fmt.Errorf("%s: %q twice", l.title, x)
			case strings.ContainsAny(x, "\r\n") || strings.HasPrefix(x, "#") || len([]rune(x)) > 80:
				return fmt.Errorf("%s: %q is not a valid name", l.title, x)
			case l.key == "severity" && (x != strings.ToLower(x) || strings.ContainsAny(x, " /")):
				return fmt.Errorf("%s: %q must be one lowercase word", l.title, x)
			}
			seen[k] = true
		}
	}
	for k, v := range c.CVSS.Standard {
		if !cvss.Valid(k, v) {
			return fmt.Errorf("CVSS %s: invalid value %q", k, v)
		}
	}
	return nil
}

// diskStructure is the structure as config.yaml has it now (a push
// included) and a hash of the file's bytes: the base a save must match.
func (s *Server) diskStructure() (config.Config, string) {
	dir := s.Store.Repo().Dir
	c := s.conf()
	raw, err := os.ReadFile(config.ConfigPath(dir))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("structure: %v", err)
		return c, ""
	}
	// loaded after the bytes were hashed: at worst newer than the base,
	// which makes a save a conflict, never an overwrite
	if l, err := config.Load(dir); err != nil {
		log.Printf("structure: %v", err)
	} else {
		c.Sections, c.DetailsRows, c.Severities, c.ReportSections, c.CVSS = l.Sections, l.DetailsRows, l.Severities, l.ReportSections, l.CVSS
	}
	return c, store.BodyHash(string(raw))
}

// structureView shows the edited structure c against the saved one.
func (s *Server) structureView(c, saved config.Config) (structView, error) {
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
			it := structItem{Value: x, Last: i == len(items)-1}
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
func (s *Server) structureRender(w http.ResponseWriter, r *http.Request, status int, c, disk config.Config, base, errMsg, saved string) {
	s.adminPage(w, r, "structure", status, func(p *page) error {
		v, err := s.structureView(c, disk)
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
	s.structureRender(w, r, http.StatusOK, disk, disk, base, "", saved)
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
	c := structFromForm(r.PostForm, disk)
	base := r.PostForm.Get("base") // the page's, kept through moves and adds
	op := r.PostForm.Get("op")
	if op != "save" {
		applyOp(&c, op, r.PostForm)
		s.structureRender(w, r, http.StatusOK, c, disk, base, "", "")
		return
	}
	if err := checkStructure(c); err != nil {
		s.structureRender(w, r, http.StatusBadRequest, c, disk, base, err.Error(), "")
		return
	}
	u := auth.UserFrom(r.Context())
	dir := s.Store.Repo().Dir
	var loaded config.Config
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
		return []store.SettingsFile{{Path: configRel, Data: b}}, nil
	}, func() error {
		var err error
		loaded, err = config.Load(dir)
		return err
	})
	if errors.Is(err, store.ErrConflict) {
		// the page shows the edits against the file as it is now; saving
		// again overwrites it knowingly
		now, nowBase := s.diskStructure()
		s.structureRender(w, r, http.StatusConflict, c, now, nowBase, "Structure changed by someone else", "")
		return
	}
	if err != nil {
		s.structureRender(w, r, http.StatusBadRequest, c, disk, base, strings.TrimPrefix(err.Error(), "config: "), "")
		return
	}
	was := disk.ReportSections
	s.setConfig(loaded)
	head, _ := gitrepo.ReadHead(dir)
	// renamed report sections keep their text in every engagement
	if rn := renamesOf(was, loaded.ReportSections); len(rn) > 0 {
		if err := s.Store.RenameReportSections(rn, author(u)); err != nil {
			log.Printf("rename report sections: %v", err)
		}
	}
	if len(head) > 7 {
		head = head[:7]
	}
	http.Redirect(w, r, "/admin/structure?saved="+head, http.StatusSeeOther)
}
