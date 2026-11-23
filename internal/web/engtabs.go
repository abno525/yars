package web

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"yars/internal/auth"
	"yars/internal/index"
	"yars/internal/store"
	"yars/internal/workflow"
)

// engTabs is the tab bar under an engagement's title; On is the open tab.
type engTabs struct {
	Items []link
	On    string
}

// overviewView is the Overview tab: tiles and bars only (R1).
type overviewView struct {
	Tiles     []tile
	SevTiles  []tile // one per configured severity with its count, then "—" for unscored drafts (an empty slot when there are none)
	Bars      boardBars
	OpenTotal int
}

type tile struct {
	Label, Value string
	Slot         bool // an empty place kept for a tile
}

// chartRow is one bar of a chart: W is its share in percent of the
// largest row (the bar's length).
type chartRow struct {
	Key  string
	N    int
	W    string
	Pct  int
	Zero bool
}

// reportView is the Report tab: the report-level sections and the totals.
type reportView struct {
	Panels   []panel
	Severity []chartRow
	Total    int
}

// engSettingsView is the Settings tab.
type engSettingsView struct {
	CanEdit bool // the General details (directors)
	CanTeam bool // the team (directors and admins)
	Error   string
	Form    store.Engagement
	Members []option // Value = user, Label = role
	Others  []option
	// TeamCols is the team table's column count: User, Role, Action; the
	// simple workflow has no Role column
	TeamCols int
}

func (s *Server) routesEngTabs(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/overview", s.engOverview)
	mux.HandleFunc("GET /e/{eng}/report", s.engReport)
	mux.HandleFunc("GET /e/{eng}/report/s/{section}", s.reportSection)
	mux.HandleFunc("GET /e/{eng}/report/s/{section}/edit", s.reportSectionEdit)
	mux.HandleFunc("POST /e/{eng}/report/s/{section}", s.reportSectionSave)
	mux.HandleFunc("GET /e/{eng}/settings", s.engSettings)
	mux.HandleFunc("POST /e/{eng}/settings", s.engSettingsSave)
	mux.HandleFunc("POST /e/{eng}/settings/team", s.engTeamAdd)
	mux.HandleFunc("POST /e/{eng}/settings/team/remove", s.engTeamRemove)
}

// tabsFor fills the tab bar with tab ("findings", "board", "overview",
// "report", "settings") on. Team board counts the notes with something
// new to the user; it needs the database (not on a local clone).
func (s *Server) tabsFor(p *page, tab string) error {
	sum, err := s.Index.Summary(p.Eng.ID)
	if err != nil {
		return err
	}
	base := "/e/" + p.Eng.ID
	p.ETab.On = tab
	p.ETab.Items = append(p.ETab.Items, link{Key: "findings", Label: "Findings · " + strconv.Itoa(sum.Total), URL: base, Active: tab == "findings"})
	if s.Store.DB() != nil {
		n, err := s.Store.UnseenCount(p.User, p.Eng.ID)
		if err != nil {
			return err
		}
		p.ETab.Items = append(p.ETab.Items, link{Key: "board", Label: "Team board", URL: base + "/board", Active: tab == "board", Count: n, Keys: "T B"})
	}
	// the keys open the tabs (keys.js yarsFire); e is Export's, in the head
	for _, t := range []struct{ key, label, url, keys string }{
		{"overview", "Overview", base + "/overview", "O"}, {"report", "Report", base + "/report", "R"}, {"settings", "Settings", base + "/settings", "S"},
	} {
		p.ETab.Items = append(p.ETab.Items, link{Key: t.key, Label: t.label, URL: t.url, Active: t.key == tab, Keys: t.keys})
	}
	return nil
}

// tabPage is the common data of an engagement tab.
func (s *Server) tabPage(r *http.Request, tab string) (*page, error) {
	p, err := s.base(r, r.PathValue("eng"))
	if err != nil {
		return nil, err
	}
	if err := s.tabsFor(p, tab); err != nil {
		return nil, err
	}
	if p.Eng.Type == "retest" {
		p.IsRetest = true
		p.Source, _ = s.Store.Engagement(p.Eng.Source)
	}
	return p, nil
}

// chartOf turns counts into chart rows scaled to the largest.
func chartOf(cs []index.Count) []chartRow {
	top := 0
	for _, c := range cs {
		top = max(top, c.N)
	}
	out := make([]chartRow, 0, len(cs))
	for _, c := range cs {
		r := chartRow{Key: c.Key, N: c.N, Pct: c.Pct, Zero: c.N == 0, W: "0"}
		if top > 0 {
			r.W = pctStr(c.N, top)
		}
		out = append(out, r)
	}
	return out
}

func (s *Server) engOverview(w http.ResponseWriter, r *http.Request) {
	p, err := s.tabPage(r, "overview")
	if err != nil {
		s.fail(w, err)
		return
	}
	sum, err := s.Index.Summary(p.Eng.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	rows, err := s.Index.Rows(index.Query{EngID: p.Eng.ID})
	if err != nil {
		s.fail(w, err)
		return
	}
	v := overviewView{Bars: overviewBars(sum)}
	for _, row := range rows {
		v.OpenTotal += row.OpenThreads
	}
	v.Tiles = []tile{
		{Label: "Findings", Value: strconv.Itoa(sum.Total)}, {Label: "Complete or reported", Value: strconv.Itoa(sum.Done)},
		{Label: "Progress", Value: strconv.Itoa(sum.Progress) + " %"}, {Label: "Open threads", Value: strconv.Itoa(v.OpenTotal)},
	}
	for _, c := range sum.Severities {
		v.SevTiles = append(v.SevTiles, tile{Label: workflow.StatusTitle(c.Key), Value: strconv.Itoa(c.N)})
	}
	if sum.Unscored > 0 {
		v.SevTiles = append(v.SevTiles, tile{Label: "—", Value: strconv.Itoa(sum.Unscored)})
	} else {
		v.SevTiles = append(v.SevTiles, tile{Slot: true}) // its place kept: nothing moves when one comes
	}
	p.Overview = v
	s.render(w, "eng_overview.html", p)
}

// reportPanel is one report-level section as a panel (no Comment; no Edit
// while archived).
func (s *Server) reportPanel(eng, name string) (panel, error) {
	body, err := s.Store.ReportSection(eng, name)
	if err != nil {
		return panel{}, err
	}
	p := panel{Name: name, Anchor: anchor(name), Raw: strings.Trim(body, "\n"), Base: store.BodyHash(body), ReadOnly: true}
	if strings.TrimSpace(body) != "" {
		p.HTML = s.renderMD(body)
	}
	base := "/e/" + eng + "/report/s/" + url.PathEscape(name)
	p.SaveURL, p.PreviewURL = base, "/e/"+eng+"/preview"
	if !s.Store.Archived(eng) {
		p.EditURL = base + "/edit"
	}
	return p, nil
}

func (s *Server) engReport(w http.ResponseWriter, r *http.Request) {
	p, err := s.tabPage(r, "report")
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, n := range s.conf().ReportSections {
		pn, err := s.reportPanel(p.Eng.ID, n)
		if err != nil {
			s.fail(w, err)
			return
		}
		p.Report.Panels = append(p.Report.Panels, pn)
	}
	sum, err := s.Index.Summary(p.Eng.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	// the total is the sum of the rows: findings with a configured severity (R10)
	p.Report.Severity = chartOf(sum.Severities)
	for _, c := range sum.Severities {
		p.Report.Total += c.N
	}
	s.render(w, "eng_report.html", p)
}

// reportName checks the {section} is a configured report section.
func (s *Server) reportName(w http.ResponseWriter, r *http.Request) (string, bool) {
	eng, name := r.PathValue("eng"), r.PathValue("section")
	if _, err := s.Store.Engagement(eng); err != nil {
		s.fail(w, err)
		return "", false
	}
	if !slices.Contains(s.conf().ReportSections, name) {
		http.NotFound(w, r)
		return "", false
	}
	return name, true
}

func (s *Server) reportSection(w http.ResponseWriter, r *http.Request) {
	name, ok := s.reportName(w, r)
	if !ok {
		return
	}
	pn, err := s.reportPanel(r.PathValue("eng"), name)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.exec(w, "eng_report.html", "panel", pn)
}

func (s *Server) reportSectionEdit(w http.ResponseWriter, r *http.Request) {
	name, ok := s.reportName(w, r)
	if !ok {
		return
	}
	eng := r.PathValue("eng")
	if s.Store.Archived(eng) {
		s.fail(w, store.ErrArchived)
		return
	}
	pn, err := s.reportPanel(eng, name)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.exec(w, "eng_report.html", "editor", pn)
}

func (s *Server) reportSectionSave(w http.ResponseWriter, r *http.Request) {
	name, ok := s.reportName(w, r)
	if !ok {
		return
	}
	eng, body := r.PathValue("eng"), r.FormValue("body")
	err := s.Store.UpdateReportSection(eng, name, body, r.FormValue("base"), author(auth.UserFrom(r.Context())))
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrInvalidBody) {
		pn, perr := s.reportPanel(eng, name)
		if perr != nil {
			s.fail(w, perr)
			return
		}
		pn.Raw, pn.Error = body, err.Error()
		status := http.StatusBadRequest
		if errors.Is(err, store.ErrConflict) {
			status, pn.Error = http.StatusConflict, "The section changed since you read it"
			pn.Current, pn.Conflict = pn.HTML, true
		}
		s.execStatus(w, status, "eng_report.html", "editor", pn)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	pn, err := s.reportPanel(eng, name)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.exec(w, "eng_report.html", "panel", pn)
}

func (s *Server) renderEngSettings(w http.ResponseWriter, r *http.Request, status int, form *store.Engagement, errMsg string) {
	p, err := s.tabPage(r, "settings")
	if err != nil {
		s.fail(w, err)
		return
	}
	v := engSettingsView{CanEdit: canManage(p.User) && !p.Archive.On, CanTeam: canEngs(p.User) && !p.Archive.On, Error: errMsg, Form: p.Eng, TeamCols: 3}
	if s.flow().Simple {
		v.TeamCols = 2
	}
	if form != nil {
		v.Form = *form
	}
	members, err := s.Store.Members(p.Eng.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	users, err := s.Store.DB().Users()
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, u := range users {
		o := option{Value: u.Username, Label: u.Role}
		if slices.Contains(members, u.Username) {
			v.Members = append(v.Members, o)
		} else if !u.Disabled {
			v.Others = append(v.Others, o)
		}
	}
	p.EngSettings = v
	s.renderStatus(w, status, "eng_settings.html", p)
}

func (s *Server) engSettings(w http.ResponseWriter, r *http.Request) {
	s.renderEngSettings(w, r, http.StatusOK, nil, "")
}

func (s *Server) engSettingsSave(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("eng")
	e, err := s.Store.Engagement(eng)
	if err != nil {
		s.fail(w, err)
		return
	}
	e.Name, e.Client, e.Start, e.End = r.FormValue("name"), r.FormValue("client"), r.FormValue("start"), r.FormValue("end")
	err = s.Store.UpdateEngagement(e, auth.UserFrom(r.Context()))
	if errors.Is(err, store.ErrInvalidValue) {
		s.renderEngSettings(w, r, http.StatusBadRequest, &e, strings.TrimPrefix(err.Error(), store.ErrInvalidValue.Error()+": "))
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/e/"+eng+"/settings", http.StatusSeeOther)
}

func (s *Server) engTeamAdd(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("eng")
	u, ok := s.Auth.Lookup(r.FormValue("user"))
	if !ok {
		http.Error(w, "unknown user", http.StatusBadRequest)
		return
	}
	if err := s.Store.AddMembers(eng, []string{u.Username}, auth.UserFrom(r.Context())); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/e/"+eng+"/settings", http.StatusSeeOther)
}

func (s *Server) engTeamRemove(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("eng")
	if _, err := s.Store.Engagement(eng); err != nil {
		s.fail(w, err)
		return
	}
	if err := s.Store.RemoveMember(eng, r.FormValue("user"), auth.UserFrom(r.Context())); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/e/"+eng+"/settings", http.StatusSeeOther)
}
