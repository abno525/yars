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
	required   []param
	optional   []param
	boolArgs   []param
	run        func(s *Server, ctx context.Context, u config.User, a args) (string, error)
}

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
	{name: "list_engagements", desc: "List all engagements (pentests and retests).",
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			es, err := s.Store.ListEngagements()
			if err != nil {
				return "", err
			}
			type eng struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Client string `json:"client,omitempty"`
				Type   string `json:"type"`
				Source string `json:"source,omitempty"`
			}
			out := []eng{}
			for _, e := range es {
				out = append(out, eng{e.ID, e.Name, e.Client, e.Type, e.Source})
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
				CanEdit     bool              `json:"can_edit"`
				Threads     []thread          `json:"open_threads"`
				Violations  []rules.Violation `json:"violations"`
			}{Engagement: ref.EngID, Dir: ref.Dir, State: st, Markdown: string(ref.F.Bytes()), CVSSBase: store.CVSSHash(ref.F.Meta),
				DetailsBase: store.DetailsHash(ref.F.Meta), CanEdit: workflow.CanEdit(u, ref.F.Meta), Threads: []thread{}, Violations: []rules.Violation{}}
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
	{name: "create_finding", desc: "Create a new draft finding in an engagement.",
		required: []param{pEng, {"title", "finding title"}},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			if err := a.need("engagement", "title"); err != nil {
				return "", err
			}
			ref, err := s.Store.CreateFinding(a.str("engagement"), a.str("title"), u.GitAuthor())
			if err != nil {
				return "", err
			}
			return asJSON(map[string]string{"id": ref.F.Meta.ID, "dir": ref.Dir})
		}},
	{name: "update_section", desc: "Replace the Markdown body of one ## section. Pass base (from read_finding) to refuse the edit if someone changed it meanwhile. Use ### or deeper headings inside the body.",
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
	{name: "set_field", desc: "Set a field: title, severity (no CVSS vector), cvss (vector or empty to clear), cvss_reason.<METRIC> (explanation for a non-standard value, e.g. cvss_reason.AC), details.<Row> (details table, e.g. details.Location), reviewers (comma-separated usernames), retest_result (fixed | not_fixed | partially_fixed). Use transition for status.",
		required: []param{pEng, pFinding, {"field", "field name"}, {"value", "new value"}},
		optional: []param{{"base", "cvss_base (cvss, cvss_reason.*) or details_base (details.*) from read_finding; refuses the edit if someone changed it meanwhile"}},
		run:      setField},
	{name: "transition", desc: "Move a finding through the workflow: submit (draft→verification), return (verification→draft, needs reason), clear or sign_off (reviewer sign-off), approve (director: verification→complete), reopen (complete→verification), report (director: complete→reported), withdraw (author while draft or verification, director also when complete or reported; needs reason; takes it out of the report), revise (author or director: withdrawn→draft).",
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
	{name: "add_chat_message", desc: "Post a message in the finding's chat, optionally about a section or as a reply to a thread.",
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
	{name: "resolve_thread", desc: "Mark a chat thread as resolved.",
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
	{name: "lint_finding", desc: "Check a finding against the team's style rules (regex and built-in checks; with all=true also script and AI rules).",
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
			vs := s.Rules.Lint(ctx, ref.F, kinds)
			if vs == nil {
				vs = []rules.Violation{}
			}
			return asJSON(vs)
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
