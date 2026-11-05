package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/cvss"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/index"
	"yars/internal/rules"
	"yars/internal/store"
	"yars/internal/workflow"
)

type args map[string]any

func (a args) str(k string) string {
	v, _ := a[k].(string)
	return v
}

func (a args) need(keys ...string) error {
	for _, k := range keys {
		if strings.TrimSpace(a.str(k)) == "" {
			return fmt.Errorf("missing argument %q", k)
		}
	}
	return nil
}

type param struct{ name, desc string }

type tool struct {
	name, desc string
	// action is what a scoped token needs to call the tool ("" = read)
	action string
	// serverOnly: the tool needs the server's database (workflow, chat,
	// checks, notifications); on a local clone it answers ErrNoDB
	serverOnly bool
	required   []param
	optional   []param
	boolArgs   []param
	run        func(s *Server, ctx context.Context, u config.User, a args) (string, error)
}

// actionOf is the token action a call needs: the tool's, except that
// set_field on reviewers needs "reviewers" and marking a finding reported
// (the delivery to the client) needs "export".
func actionOf(t tool, a args) string {
	if t.name == "set_field" && a.str("field") == "reviewers" {
		return "reviewers"
	}
	if t.name == "transition" && a.str("action") == string(workflow.Report) {
		return "export"
	}
	if t.action == "" {
		return db.ScopeRead
	}
	return t.action
}

var actionLabel = map[string]string{"read": "read", "create": "create findings", "edit": "edit findings",
	"comment": "comment or resolve", "status": "change status", "reviewers": "assign reviewers",
	"checks": "run checks", "export": "export"}

func (t tool) schema() map[string]any {
	props := map[string]any{}
	var req []string
	for _, p := range t.required {
		props[p.name] = map[string]any{"type": "string", "description": p.desc}
		req = append(req, p.name)
	}
	for _, p := range t.optional {
		props[p.name] = map[string]any{"type": "string", "description": p.desc}
	}
	for _, p := range t.boolArgs {
		props[p.name] = map[string]any{"type": "boolean", "description": p.desc}
	}
	s := map[string]any{"type": "object", "properties": props}
	if len(req) > 0 {
		s["required"] = req
	}
	return s
}

// ParamDoc describes one argument of a tool.
type ParamDoc struct {
	Name, Type, Desc string
	Required         bool
}

// ToolDoc describes a tool for the developer docs: generated from the
// definitions below, so it can't drift. Action is the token action it needs
// ("read" for reading tools).
type ToolDoc struct {
	Name, Desc, Action string
	ServerOnly         bool
	Params             []ParamDoc
}

// Catalog lists the tools in the order tools/list returns them.
func Catalog() []ToolDoc {
	var out []ToolDoc
	for _, t := range tools {
		d := ToolDoc{Name: t.name, Desc: t.desc, Action: actionOf(t, args{}), ServerOnly: t.serverOnly}
		for _, p := range t.required {
			d.Params = append(d.Params, ParamDoc{p.name, "string", p.desc, true})
		}
		for _, p := range t.optional {
			d.Params = append(d.Params, ParamDoc{p.name, "string", p.desc, false})
		}
		for _, p := range t.boolArgs {
			d.Params = append(d.Params, ParamDoc{p.name, "boolean", p.desc, false})
		}
		out = append(out, d)
	}
	return out
}

// ProtocolVersions are the MCP versions the server speaks, newest first.
func ProtocolVersions() []string { return slices.Clone(protocols) }

var (
	pEng     = param{"engagement", "engagement ID, e.g. 2026-11-acme-webapp"}
	pFinding = param{"finding", "finding ID (F-001) or directory name (F-001-sql-injection)"}
)

func asJSON(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	return string(b), err
}

// explain turns store/workflow errors into messages for the assistant.
func explain(err error) string {
	var d *workflow.Denied
	switch {
	case errors.As(err, &d):
		return "not allowed: " + d.Reason
	case errors.Is(err, store.ErrConflict):
		return "the finding changed meanwhile (someone else edited it); read_finding again and retry"
	case errors.Is(err, store.ErrNotFound):
		return "not found"
	case errors.Is(err, store.ErrArchived):
		return "not allowed: " + store.ErrArchived.Error()
	}
	return err.Error()
}

var findingID = regexp.MustCompile(`^F-\d+$`)

// resolve finds a finding by directory name or by ID.
func (s *Server) resolve(eng, f string) (store.FindingRef, error) {
	if !store.ValidID(eng) || !store.ValidID(f) {
		return store.FindingRef{}, store.ErrNotFound
	}
	if ref, err := s.Store.Finding(eng, f); err == nil {
		return ref, nil
	}
	if findingID.MatchString(f) {
		refs, err := s.Store.ListFindings(eng)
		if err != nil {
			return store.FindingRef{}, err
		}
		for _, r := range refs {
			if r.F.Meta.ID == f {
				return r, nil
			}
		}
	}
	return store.FindingRef{}, store.ErrNotFound
}

func (s *Server) ref(a args) (store.FindingRef, error) {
	if err := a.need("engagement", "finding"); err != nil {
		return store.FindingRef{}, err
	}
	return s.resolve(a.str("engagement"), a.str("finding"))
}

var tools = []tool{
	{name: "list_engagements", desc: "List the engagements you work on (pentests and retests). Archived engagements are read only.",
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			es, err := s.Store.ListEngagements()
			if err != nil {
				return "", err
			}
			vis, err := s.Store.Visible(u)
			if err != nil {
				return "", err
			}
			tk, hasTok := tokenFrom(ctx)
			type eng struct {
				ID       string `json:"id"`
				Name     string `json:"name"`
				Client   string `json:"client,omitempty"`
				Type     string `json:"type"`
				Source   string `json:"source,omitempty"`
				Archived bool   `json:"archived,omitempty"`
			}
			out := []eng{}
			for _, e := range es {
				if (vis != nil && !vis[e.ID]) || (hasTok && !tk.AllowsEng(e.ID)) {
					continue
				}
				out = append(out, eng{e.ID, e.Name, e.Client, e.Type, e.Source, e.Archived})
			}
			return asJSON(out)
		}},
	{name: "list_findings", desc: "List the findings of an engagement, optionally filtered by status or severity.",
		required: []param{pEng}, optional: []param{{"status", "draft | verification | complete | reported | withdrawn (withdrawn findings are listed only with this filter)"}, {"severity", "critical | high | medium | low | info"}},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			if err := a.need("engagement"); err != nil {
				return "", err
			}
			if _, err := s.Store.Engagement(a.str("engagement")); err != nil {
				return "", err
			}
			rows, err := s.Index.Rows(index.Query{EngID: a.str("engagement"), Status: a.str("status"), Severity: a.str("severity"), Sort: "severity"})
			if err != nil {
				return "", err
			}
			type row struct {
				ID           string   `json:"id"`
				Dir          string   `json:"dir"`
				Title        string   `json:"title"`
				Status       string   `json:"status"`
				Severity     string   `json:"severity,omitempty"`
				Score        string   `json:"cvss_score,omitempty"`
				Author       string   `json:"author"`
				Reviewers    []string `json:"reviewers,omitempty"`
				OpenThreads  int      `json:"open_threads,omitempty"`
				RetestResult string   `json:"retest_result,omitempty"`
			}
			out := []row{}
			for _, r := range rows {
				out = append(out, row{r.ID, r.Dir, r.Title, r.Status, r.Severity, r.Score, r.Author, r.Reviewers, r.OpenThreads, r.RetestResult})
			}
			return asJSON(out)
		}},
	{name: "read_finding", desc: "Read one finding: its workflow state (status, reviewers, clearances, return reason, retest), the raw finding.md content (YAML front matter + ## sections; workflow state is not in the file), section names with base hashes for safe edits, open chat threads and style-rule violations.",
		required: []param{pEng, pFinding},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			ref, err := s.ref(a)
			if err != nil {
				return "", err
			}
			type sec struct {
				Name string `json:"name"`
				Base string `json:"base"`
			}
			type msg struct {
				User string `json:"user"`
				Text string `json:"text"`
			}
			type thread struct {
				ID      string `json:"id"`
				User    string `json:"user"`
				Section string `json:"section,omitempty"`
				Text    string `json:"text"`
				Replies []msg  `json:"replies"`
			}
			type state struct {
				Status       string            `json:"status"`
				Reviewers    []string          `json:"reviewers"`
				ClearedBy    []string          `json:"cleared_by"`
				Returned     *finding.Returned `json:"returned,omitempty"`
				Withdrawn    *finding.Returned `json:"withdrawn,omitempty"`
				RetestSource string            `json:"retest_source,omitempty"`
				RetestResult string            `json:"retest_result,omitempty"`
			}
			m := ref.F.Meta
			st := state{Status: m.Status, Reviewers: append([]string{}, m.Reviewers...), ClearedBy: append([]string{}, m.ClearedBy...), Returned: m.Returned, Withdrawn: m.Withdrawn}
			if m.Retest != nil {
				st.RetestSource, st.RetestResult = m.Retest.Source, m.Retest.Result
			}
			out := struct {
				Engagement  string            `json:"engagement"`
				Dir         string            `json:"dir"`
				State       state             `json:"state"`
				Markdown    string            `json:"finding_md"`
				Sections    []sec             `json:"sections"`
				CVSSBase    string            `json:"cvss_base"`
				DetailsBase string            `json:"details_base"`
				Assets      []finding.Asset   `json:"assets"`
				AssetsBase  string            `json:"assets_base"`
				CanEdit     bool              `json:"can_edit"`
				Threads     []thread          `json:"open_threads"`
				Violations  []rules.Violation `json:"violations"`
			}{Engagement: ref.EngID, Dir: ref.Dir, State: st, Markdown: string(ref.F.Bytes()), CVSSBase: store.CVSSHash(ref.F.Meta),
				DetailsBase: store.DetailsHash(ref.F.Meta), Assets: append([]finding.Asset{}, ref.F.Meta.Assets...), AssetsBase: store.AssetsHash(ref.F.Meta),
				CanEdit: workflow.CanEdit(u, ref.F.Meta), Threads: []thread{}, Violations: []rules.Violation{}}
			for _, sct := range ref.F.Sections {
				out.Sections = append(out.Sections, sec{sct.Name, store.BodyHash(sct.Body)})
			}
			msgs, _ := s.Store.Chat(ref.EngID, ref.Dir)
			for _, it := range chat.Timeline(msgs) {
				if it.Thread != nil && !it.Thread.Resolved {
					t := it.Thread
					th := thread{ID: t.Root.ID, User: t.Root.User, Section: t.Root.Section, Text: t.Root.Text, Replies: []msg{}}
					for _, r := range t.Replies {
						th.Replies = append(th.Replies, msg{r.User, r.Text})
					}
					out.Threads = append(out.Threads, th)
				}
			}
			if s.Rules != nil {
				out.Violations = append(out.Violations, s.Rules.Lint(ctx, ref.F, rules.Fast)...)
			}
			return asJSON(out)
		}},
	{name: "list_templates", desc: "List the finding templates (.yars/templates): slug, title, severity and how many findings were made from each. Pass a slug to create_finding as template.",
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			ts, err := s.Store.Templates()
			if err != nil {
				return "", err
			}
			uses, err := s.Index.TemplateUse()
			if err != nil {
				return "", err
			}
			type tpl struct {
				Slug     string `json:"slug"`
				Title    string `json:"title"`
				Severity string `json:"severity,omitempty"`
				CVSS     string `json:"cvss,omitempty"`
				Uses     int    `json:"uses"`
			}
			out := []tpl{}
			for _, t := range ts {
				m := t.F.Meta
				out = append(out, tpl{t.Slug, m.Title, m.Severity, m.CVSS, uses[t.Slug]})
			}
			return asJSON(out)
		}},
	{name: "create_finding", action: "create", desc: "Create a new draft finding in an engagement, empty or from a template (its sections, severity, CVSS and details).",
		required: []param{pEng, {"title", "finding title"}}, optional: []param{{"template", "template slug from list_templates"}},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			if err := a.need("engagement", "title"); err != nil {
				return "", err
			}
			var ref store.FindingRef
			var err error
			if slug := a.str("template"); slug != "" {
				ref, err = s.Store.CreateFindingFrom(a.str("engagement"), a.str("title"), slug, u.GitAuthor())
			} else {
				ref, err = s.Store.CreateFinding(a.str("engagement"), a.str("title"), u.GitAuthor())
			}
			if err != nil {
				return "", err
			}
			return asJSON(map[string]string{"id": ref.F.Meta.ID, "dir": ref.Dir})
		}},
	{name: "update_section", action: "edit", desc: "Replace the Markdown body of one ## section. Pass base (from read_finding) to refuse the edit if someone changed it meanwhile. Use ### or deeper headings inside the body.",
		required: []param{pEng, pFinding, {"section", "section name, e.g. Impact"}, {"body", "new Markdown body"}},
		optional: []param{{"base", "section base hash from read_finding"}},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			ref, err := s.ref(a)
			if err != nil {
				return "", err
			}
			if err := a.need("section"); err != nil {
				return "", err
			}
			// same rule as the web: a configured section or one already in the file
			valid := slices.Clone(s.Cfg.Sections)
			for _, sct := range ref.F.Sections {
				if !slices.Contains(valid, sct.Name) {
					valid = append(valid, sct.Name)
				}
			}
			if !slices.Contains(valid, a.str("section")) {
				return "", fmt.Errorf("unknown section %q; valid sections: %s", a.str("section"), strings.Join(valid, ", "))
			}
			if err := s.Store.UpdateSection(ref.EngID, ref.Dir, a.str("section"), a.str("body"), a.str("base"), u); err != nil {
				return "", err
			}
			return "updated " + a.str("section"), nil
		}},
	{name: "set_field", action: "edit", desc: "Set a field: title, severity (no CVSS vector), cvss (vector or empty to clear), cvss_reason.<METRIC> (explanation for a non-standard value, e.g. cvss_reason.AC), details.<Row> (details table, e.g. details.Location), reviewers (comma-separated usernames), retest_result (fixed | not_fixed | partially_fixed), assets (the whole affected-asset list as JSON: [{\"host\":\"app.example\",\"url\":\"https://app.example/x\",\"port\":\"443\",\"note\":\"…\"}], [] to clear). Use transition for status.",
		required: []param{pEng, pFinding, {"field", "field name"}, {"value", "new value"}},
		optional: []param{{"base", "cvss_base (cvss, cvss_reason.*), details_base (details.*) or assets_base (assets) from read_finding; refuses the edit if someone changed it meanwhile"}},
		run:      setField},
	{name: "transition", action: "status", serverOnly: true, desc: "Move a finding through the workflow: submit (draft→verification), return (verification→draft, needs reason), clear or sign_off (reviewer sign-off), approve (director: verification→complete), reopen (complete→verification), report (director: complete→reported), withdraw (author while draft or verification, director also when complete or reported; needs reason; takes it out of the report), revise (author or director: withdrawn→draft).",
		required: []param{pEng, pFinding, {"action", "submit | return | clear | sign_off | approve | reopen | report | withdraw | revise"}},
		optional: []param{{"reason", "required for return and withdraw"}},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			ref, err := s.ref(a)
			if err != nil {
				return "", err
			}
			act, ok := workflow.ParseAction(a.str("action"))
			if !ok {
				return "", errors.New("unknown action (submit, return, clear or sign_off, approve, reopen, report, withdraw, revise)")
			}
			if act == workflow.Report && !workflow.AtLeast(u, "director") {
				return "", &workflow.Denied{Reason: "only a director can mark reported"}
			}
			if err := s.Store.Transition(ref.EngID, ref.Dir, act, a.str("reason"), u); err != nil {
				return "", err
			}
			_, to := workflow.Target(act)
			return string(act) + " done; status is now " + to, nil
		}},
	{name: "add_chat_message", action: "comment", serverOnly: true, desc: "Post a message in the finding's chat, optionally about a section or as a reply to a thread. @name mentions notify that person.",
		required: []param{pEng, pFinding, {"text", "Markdown message"}},
		optional: []param{{"section", "section the message is about"}, {"reply", "thread ID to reply to"}},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			ref, err := s.ref(a)
			if err != nil {
				return "", err
			}
			m, err := s.Store.PostChat(ref.EngID, ref.Dir, chat.Message{Text: a.str("text"), Section: a.str("section"), Reply: a.str("reply")}, u)
			if err != nil {
				return "", err
			}
			return asJSON(map[string]string{"id": m.ID})
		}},
	{name: "resolve_thread", action: "comment", serverOnly: true, desc: "Mark a chat thread as resolved.",
		required: []param{pEng, pFinding, {"thread", "thread ID"}},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			ref, err := s.ref(a)
			if err != nil {
				return "", err
			}
			if err := a.need("thread"); err != nil {
				return "", err
			}
			if _, err := s.Store.PostChat(ref.EngID, ref.Dir, chat.Message{Resolves: a.str("thread")}, u); err != nil {
				return "", err
			}
			return "resolved", nil
		}},
	{name: "lint_finding", desc: "Check a finding against the team's style rules (regex and built-in checks; with all=true also script and AI rules). Violations a reviewer dismissed are marked dismissed and do not block submit or approve.",
		required: []param{pEng, pFinding}, boolArgs: []param{{"all", "also run script and AI rules (slower)"}},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			ref, err := s.ref(a)
			if err != nil {
				return "", err
			}
			if s.Rules == nil {
				return "[] (no rules configured)", nil
			}
			kinds := rules.Fast
			if all, _ := a["all"].(bool); all {
				kinds = rules.All
			}
			ds, err := s.Store.Dismissals(ref.EngID, ref.F.Meta.ID)
			if err != nil {
				return "", err
			}
			// dismissed violations no longer block submit or approve
			type marked struct {
				rules.Violation
				Dismissed   bool   `json:"dismissed,omitempty"`
				DismissedBy string `json:"dismissed_by,omitempty"`
			}
			out := []marked{}
			for _, v := range s.Rules.Lint(ctx, ref.F, kinds) {
				m := marked{Violation: v}
				if d, ok := ds[db.DismissKey(v.Rule, store.QuoteHash(v.Quote))]; ok {
					m.Dismissed, m.DismissedBy = true, d.By
				}
				out = append(out, m)
			}
			return asJSON(out)
		}},
	{name: "start_check", action: "checks", serverOnly: true, desc: "Start a stored check run of every rule (fast, script and AI) on a finding, as the Check button does. It runs in the background; each new violation is posted as a chat comment. Read the outcome with get_check_results.",
		required: []param{pEng, pFinding},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			ref, err := s.ref(a)
			if err != nil {
				return "", err
			}
			run, err := s.Store.StartCheck(ref.EngID, ref.Dir, u)
			if err != nil {
				return "", err
			}
			return asJSON(map[string]any{"run_id": run.ID, "state": run.State, "done": run.Done, "total": run.Total})
		}},
	{name: "get_check_results", serverOnly: true, desc: "The finding's latest check run: state (running, done, failed), progress, whether the finding changed since (stale), and its results with dismissals.",
		required: []param{pEng, pFinding},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			ref, err := s.ref(a)
			if err != nil {
				return "", err
			}
			st, err := s.Store.CheckStatus(ref.EngID, ref.Dir)
			if err != nil {
				return "", err
			}
			type result struct {
				Rule      string `json:"rule"`
				Level     string `json:"level"`
				Message   string `json:"message"`
				Target    string `json:"target"`
				Quote     string `json:"quote,omitempty"`
				Thread    string `json:"thread,omitempty"`
				Dismissed bool   `json:"dismissed,omitempty"`
			}
			out := struct {
				HasRun   bool     `json:"has_run"`
				RunID    int64    `json:"run_id,omitempty"`
				State    string   `json:"state,omitempty"`
				Running  bool     `json:"running,omitempty"`
				Stale    bool     `json:"stale"`
				Done     int      `json:"done"`
				Total    int      `json:"total"`
				Error    string   `json:"error,omitempty"`
				By       string   `json:"by,omitempty"`
				Started  string   `json:"started,omitempty"`
				Finished string   `json:"finished,omitempty"`
				Results  []result `json:"results"`
			}{HasRun: st.HasRun, Stale: st.Stale, Running: st.Running, Results: []result{}}
			if st.HasRun {
				r := st.Run
				out.RunID, out.State, out.Done, out.Total, out.Error, out.By, out.Started, out.Finished = r.ID, r.State, r.Done, r.Total, r.Error, r.By, r.Started, r.Finished
			}
			for _, x := range st.Results {
				_, dis := st.Dismissed[db.DismissKey(x.Rule, x.QuoteHash)]
				out.Results = append(out.Results, result{x.Rule, x.Level, x.Message, x.Target, x.Quote, x.Thread, dis})
			}
			return asJSON(out)
		}},
	{name: "list_notifications", serverOnly: true, desc: "Your notifications, newest first (at most 50): returned to you, review requested, replies, approvals, mentions, finished checks.",
		boolArgs: []param{{"unread", "only unread ones"}},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			unread, _ := a["unread"].(bool)
			l, err := s.Store.Notifications(u, unread, 50)
			if err != nil {
				return "", err
			}
			tk, hasTok := tokenFrom(ctx)
			type note struct {
				ID         int64  `json:"id"`
				Event      string `json:"event"`
				Engagement string `json:"engagement"`
				Finding    string `json:"finding,omitempty"`
				Dir        string `json:"dir,omitempty"`
				Title      string `json:"title,omitempty"`
				By         string `json:"by,omitempty"`
				Text       string `json:"text,omitempty"`
				At         string `json:"at"`
				Read       bool   `json:"read"`
			}
			out := []note{}
			for _, n := range l {
				if hasTok && !tk.AllowsEng(n.Eng) {
					continue
				}
				out = append(out, note{n.ID, n.Event, n.Eng, n.Fid, n.Dir, n.Title, n.Actor, n.Text, n.TS, n.Read})
			}
			return asJSON(out)
		}},
}

var toolByName = func() map[string]tool {
	m := map[string]tool{}
	for _, t := range tools {
		m[t.name] = t
	}
	return m
}()

func setField(s *Server, ctx context.Context, u config.User, a args) (string, error) {
	ref, err := s.ref(a)
	if err != nil {
		return "", err
	}
	if err := a.need("field"); err != nil {
		return "", err
	}
	field, value, base := a.str("field"), a.str("value"), a.str("base")
	st, eng, dir := s.Store, ref.EngID, ref.Dir
	switch {
	case field == "title":
		err = st.UpdateTitle(eng, dir, value, u)
	case field == "severity":
		err = st.UpdateSeverity(eng, dir, value, "", u)
	case field == "cvss":
		err = st.UpdateCVSS(eng, dir, value, nil, base, u)
	case strings.HasPrefix(field, "cvss_reason."):
		key := strings.ToUpper(strings.TrimPrefix(field, "cvss_reason."))
		if !slices.ContainsFunc(cvss.Metrics, func(m cvss.Metric) bool { return m.Key == key }) {
			return "", fmt.Errorf("%s is not a CVSS base metric (AV, AC, PR, UI, S, C, I, A)", key)
		}
		if _, err := cvss.Parse(ref.F.Meta.CVSS); err != nil {
			return "", errors.New("set a CVSS vector first")
		}
		if base == "" { // the vector was read outside the lock: never write back a stale one
			base = store.CVSSHash(ref.F.Meta)
		}
		err = st.UpdateCVSS(eng, dir, ref.F.Meta.CVSS, map[string]string{key: value}, base, u)
	case strings.HasPrefix(field, "details."):
		row := strings.TrimPrefix(field, "details.")
		if !slices.Contains(s.Cfg.DetailsRows, row) {
			return "", fmt.Errorf("unknown details row %q; rows: %s", row, strings.Join(s.Cfg.DetailsRows, ", "))
		}
		err = st.UpdateDetails(eng, dir, map[string]string{row: value}, base, u)
	case field == "reviewers":
		var names []string
		for _, n := range strings.Split(value, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
		if s.Users != nil {
			for _, n := range names {
				i := slices.IndexFunc(s.Users(), func(x config.User) bool { return x.Username == n })
				if i < 0 || !workflow.ReviewerCandidate(s.Users()[i], ref.F.Meta) {
					return "", fmt.Errorf("%s is not a reviewer or director account (or is the author)", n)
				}
			}
		}
		err = st.SetReviewers(eng, dir, names, u)
	case field == "retest_result":
		err = st.SetRetestResult(eng, dir, value, u)
	case field == "assets":
		var list []finding.Asset
		if jerr := json.Unmarshal([]byte(value), &list); jerr != nil {
			return "", fmt.Errorf("assets must be a JSON list of {host, url, port, note}: %v", jerr)
		}
		err = st.UpdateAssets(eng, dir, list, base, u)
	case field == "status":
		return "", errors.New("use the transition tool to change the status")
	default:
		return "", fmt.Errorf("unknown field %q", field)
	}
	if err != nil {
		return "", err
	}
	return "set " + field, nil
}
