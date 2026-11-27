package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/cvss"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/index"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

type args map[string]any

func (a args) str(k string) string {
	v, _ := a[k].(string)
	return v
}

func (a args) need(keys ...string) error {
	for _, k := range keys {
		if strings.TrimSpace(a.str(k)) == "" {
			return invalid("missing argument %q", k)
		}
	}
	return nil
}

// badType names the first required argument of t that is left out, or the
// first declared one whose JSON type is wrong (null included), so it is
// refused instead of read as "" or false. An empty string stays valid.
func (t tool) badType(a args) string {
	for _, p := range t.required {
		if _, ok := a[p.name]; !ok {
			return fmt.Sprintf("missing argument %q", p.name)
		}
	}
	for _, ps := range [][]param{t.required, t.optional} {
		for _, p := range ps {
			if v, ok := a[p.name]; ok {
				if _, isStr := v.(string); !isStr {
					return fmt.Sprintf("argument %q must be a string", p.name)
				}
			}
		}
	}
	for _, p := range t.boolArgs {
		if v, ok := a[p.name]; ok {
			if _, isBool := v.(bool); !isBool {
				return fmt.Sprintf("argument %q must be a boolean", p.name)
			}
		}
	}
	return ""
}

type param struct{ name, desc string }

type tool struct {
	name, desc string
	// action is what a scoped token needs to call the tool ("" = read);
	// also is a second action it needs too (fix_checks rewrites text: edit)
	action, also string
	// serverOnly: the tool needs the server's database (workflow, chat,
	// checks, notifications); on a local clone it answers ErrNoDB
	serverOnly bool
	required   []param
	optional   []param
	boolArgs   []param
	run        func(s *Server, ctx context.Context, u config.User, a args) (string, error)
	// simple is the tool's text in the simple workflow (nil: the same)
	simple *toolText
}

// toolText is a tool's text as the simple workflow words it: its
// description ("" keeps the tool's) and its parameters' by name (one left
// out keeps its own).
type toolText struct {
	desc   string
	params map[string]string
}

// in is t as workflow f words it: the simple workflow's text where t has
// one, else t itself.
func (t tool) in(f workflow.Flow) tool {
	if !f.Simple || t.simple == nil {
		return t
	}
	if t.simple.desc != "" {
		t.desc = t.simple.desc
	}
	reword := func(ps []param) []param {
		out := slices.Clone(ps) // the tool's own stay as they are
		for i, p := range out {
			if d, ok := t.simple.params[p.name]; ok {
				out[i].desc = d
			}
		}
		return out
	}
	t.required, t.optional, t.boolArgs = reword(t.required), reword(t.optional), reword(t.boolArgs)
	return t
}

// actionOf is the token action a call needs: the tool's, except that
// set_field on reviewers needs "reviewers", marking a finding reported
// (the delivery to the client) needs "export" and lint_finding with all=true
// (script and AI rules) needs "checks". Taking reported back (unreport,
// revert) needs "status", as withdraw does: it delivers nothing.
func actionOf(t tool, a args) string {
	if t.name == "set_field" && a.str("field") == "reviewers" {
		return "reviewers"
	}
	if all, _ := a["all"].(bool); t.name == "lint_finding" && all {
		return "checks"
	}
	if act, ok := workflow.ParseAction(a.str("action")); t.name == "transition" && ok && act == workflow.Report {
		return "export"
	}
	if t.action == "" {
		return db.ScopeRead
	}
	return t.action
}

// actionIn is actionOf in workflow f. The simple workflow has no reviewers,
// nor a token action for them (Settings › Tokens offers none): set_field on
// reviewers is an edit there, which the store refuses.
func actionIn(f workflow.Flow, t tool, a args) string {
	act := actionOf(t, a)
	if act == "reviewers" && !f.HasReviewers() {
		return t.action
	}
	return act
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
	Also               string // a second action a token needs ("" = none)
	ServerOnly         bool
	Params             []ParamDoc
}

// Catalog lists the tools in the order tools/list returns them, as the
// standard workflow words them.
func Catalog() []ToolDoc { return CatalogFor(workflow.Flow{}) }

// CatalogFor lists the tools as tools/list returns them in workflow f.
func CatalogFor(f workflow.Flow) []ToolDoc {
	var out []ToolDoc
	for _, t := range tools {
		t = t.in(f)
		d := ToolDoc{Name: t.name, Desc: t.desc, Action: actionOf(t, args{}), Also: t.also, ServerOnly: t.serverOnly}
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

// actionNames lists the actions transition takes in workflow f, as an
// unknown action's refusal names them: clear with its alias sign_off, and
// revert (the step back, by status) after unreport.
func actionNames(f workflow.Flow) string {
	var names []string
	for _, act := range f.Actions() {
		switch act {
		case workflow.Clear:
			names = append(names, "clear or sign_off")
		case workflow.Unreport:
			names = append(names, string(act), "revert")
		default:
			names = append(names, string(act))
		}
	}
	return strings.Join(names, ", ")
}

// missingBase is the refusal of a sign-off, an approval or a completion
// called without base, in workflow f's words: the argument and where its
// value comes from.
func missingBase(f workflow.Flow) string {
	if f.Simple {
		return `missing argument "base": call read_finding and pass its hash as base, so that you complete the version you read`
	}
	return `missing argument "base": call read_finding and pass its hash as base, so that you sign off or approve the version you read`
}

// explain turns store/workflow errors into messages for the assistant.
func explain(err error) string {
	var d *workflow.Denied
	var r refusal
	switch {
	case errors.As(err, &r):
		return r.msg
	case errors.Is(err, store.ErrConflict): // a Denied too: a stale base, a race with an edit
		return "the finding changed since you read it; read_finding again and retry"
	case errors.As(err, &d):
		return "not allowed: " + d.Reason
	case errors.Is(err, store.ErrNotFound):
		return "not found"
	case errors.Is(err, store.ErrArchived):
		return "not allowed: " + store.ErrArchived.Error()
	case errors.Is(err, store.ErrInvalidValue):
		// the store's words, as the website shows them
		return strings.TrimPrefix(err.Error(), store.ErrInvalidValue.Error()+": ")
	}
	return err.Error()
}

var (
	findingID = regexp.MustCompile(`^F-\d+$`)
	// anyID is a finding id in any case, or its number alone ("f-7", "7")
	anyID = regexp.MustCompile(`^(?i:f-)?(\d+)$`)
	// folderNum is the number a folder name starts with (F-001-sqli: 1)
	folderNum = regexp.MustCompile(`^F-(\d+)(?:-|$)`)
)

// errAmbiguous: a finding id names more than one folder.
var errAmbiguous = errors.New("ambiguous")

// normalID turns "f-7", "F-7", "f-007" or "7" into "F-007" (at least three
// digits); other names (a folder name) are returned unchanged.
func normalID(s string) string {
	m := anyID.FindStringSubmatch(s)
	if m == nil {
		return s
	}
	n := strings.TrimLeft(m[1], "0")
	if len(n) > 9 { // no finding has such a number
		return s
	}
	k := 0
	fmt.Sscan(n, &k)
	return fmt.Sprintf("F-%03d", k)
}

// ambiguous names the folders an id could mean.
type ambiguous struct {
	id   string
	dirs []string
}

func (e ambiguous) Error() string {
	return fmt.Sprintf("%s names more than one finding folder (%s); use the folder name", e.id, strings.Join(e.dirs, ", "))
}

func (e ambiguous) Is(target error) bool { return target == errAmbiguous }

// resolve finds a finding by folder name or by ID (R2: in any case, with or
// without its zeros). An ID names the folder called just that (as given or
// in its normal form), else every folder of that number and every finding
// whose front-matter ID it is (the index); more than one is ambiguous,
// never the first. Only the one found is read, so a finding that does not
// parse says why.
func (s *Server) resolve(eng, raw string) (store.FindingRef, error) {
	f := normalID(raw)
	if !store.ValidID(eng) || !store.ValidID(raw) || !store.ValidID(f) {
		return store.FindingRef{}, store.ErrNotFound
	}
	if !findingID.MatchString(f) {
		return s.Store.Finding(eng, f)
	}
	dirs, err := s.Store.FindingDirs(eng)
	if err != nil {
		return store.FindingRef{}, err
	}
	for _, name := range []string{raw, f} {
		if slices.Contains(dirs, name) {
			return s.Store.Finding(eng, name) // a folder called just that
		}
	}
	num := strings.TrimLeft(strings.TrimPrefix(f, "F-"), "0")
	hits := map[string]bool{}
	for _, d := range dirs {
		if m := folderNum.FindStringSubmatch(d); m != nil && strings.TrimLeft(m[1], "0") == num {
			hits[d] = true
		}
	}
	for _, d := range s.idFolders(eng, f) {
		hits[d] = true
	}
	found := slices.Sorted(maps.Keys(hits))
	switch len(found) {
	case 0:
		return store.FindingRef{}, store.ErrNotFound
	case 1:
		return s.Store.Finding(eng, found[0])
	}
	return store.FindingRef{}, ambiguous{id: f, dirs: found}
}

// idFolders are the folders of eng whose front-matter ID is f, in any form
// (the index's rows, withdrawn findings too).
func (s *Server) idFolders(eng, f string) []string {
	if s.Index == nil {
		return nil
	}
	var out []string
	for _, st := range []string{"", workflow.Withdrawn} {
		rows, err := s.Index.Rows(index.Query{EngID: eng, Status: st})
		if err != nil {
			continue
		}
		for _, r := range rows {
			if normalID(r.ID) == f {
				out = append(out, r.Dir)
			}
		}
	}
	return out
}

func (s *Server) ref(a args) (store.FindingRef, error) {
	if err := a.need("engagement", "finding"); err != nil {
		return store.FindingRef{}, err
	}
	return s.resolve(a.str("engagement"), a.str("finding"))
}

// tools are every tool, in the order tools/list gives them.
var tools = slices.Concat(coreTools, readingTools, writingTools)

var coreTools = []tool{
	{name: "list_engagements", desc: "List the engagements you work on (pentests and retests). Archived engagements are read only.",
		optional: []param{pLimit, pCursor},
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
			return listPage(a, out)
		}},
	{name: "list_findings", desc: "List the findings of an engagement, optionally filtered by status or severity or searched (q), most severe first, a page at a time.",
		required: []param{pEng}, optional: []param{{"status", "one of draft, verification, complete, reported, withdrawn (withdrawn findings are listed only with this filter)"}, {"severity", "one of the configured severities (by default critical, high, medium, low, info)"},
			{"q", "search: the findings whose ID (as written: F-002), title or an asset's host or URL holds this text, in any case"}, pLimit, pCursor},
		simple: &toolText{params: map[string]string{"status": "one of draft, complete, reported, withdrawn (withdrawn findings are listed only with this filter)"}},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			if err := a.need("engagement"); err != nil {
				return "", err
			}
			// R2: an unknown filter is refused with the valid values, not
			// answered with an empty list
			if st, valid := a.str("status"), s.flow().AllStatuses(); st != "" && !slices.Contains(valid, st) {
				return "", invalid("unknown status %q; valid statuses: %s", st, strings.Join(valid, ", "))
			}
			if sev, valid := a.str("severity"), s.conf().Severities; sev != "" && !slices.Contains(valid, sev) {
				return "", invalid("unknown severity %q; valid severities: %s", sev, strings.Join(valid, ", "))
			}
			if _, err := s.Store.Engagement(a.str("engagement")); err != nil {
				return "", err
			}
			rows, err := s.Index.Rows(index.Query{EngID: a.str("engagement"), Status: a.str("status"), Severity: a.str("severity"), Text: strings.TrimSpace(a.str("q")), Sort: "severity"})
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
			return listPage(a, out)
		}},
	{name: "read_finding", desc: "Read one finding: its workflow state (status, reviewers, clearances, return reason, retest), the raw finding.md content (YAML front matter + ## sections; workflow state is not in the file), the file's hash (transition's base) and attachments_hash (transition's attachments_base), each section's name, body and base hash for safe edits, open chat threads (an AI reply is marked ai), style-rule violations, and allowed_actions: every action of the status with whether you may take it now (enabled), why not (reason) and what it needs (needs: reason or base).",
		required: []param{pEng, pFinding},
		simple:   &toolText{desc: "Read one finding: its workflow state (status, withdrawal, retest), the raw finding.md content (YAML front matter + ## sections; workflow state is not in the file), the file's hash (transition's base) and attachments_hash (transition's attachments_base), each section's name, body and base hash for safe edits, open chat threads (an AI reply is marked ai), style-rule violations, and allowed_actions: every action of the status with whether you may take it now (enabled), why not (reason) and what it needs (needs: reason or base)."},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			ref, err := s.ref(a)
			if err != nil {
				return "", err
			}
			type sec struct {
				Name string `json:"name"`
				Base string `json:"base"`
				Body string `json:"body"`
			}
			type msg struct {
				User string `json:"user"`
				Text string `json:"text"`
				AI   bool   `json:"ai,omitempty"` // the AI wrote it for user (Fix with AI)
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
				Engagement  string             `json:"engagement"`
				Dir         string             `json:"dir"`
				State       state              `json:"state"`
				Markdown    string             `json:"finding_md"`
				Hash        string             `json:"hash"`             // the file's as stored, its full SHA-256: transition's base
				Files       string             `json:"attachments_hash"` // the attachments' as they are: transition's attachments_base
				Sections    []sec              `json:"sections"`
				CVSSBase    string             `json:"cvss_base"`
				DetailsBase string             `json:"details_base"`
				Bases       map[string]string  `json:"field_bases"`
				Assets      []finding.Asset    `json:"assets"`
				AssetsBase  string             `json:"assets_base"`
				CanEdit     bool               `json:"can_edit"`
				Threads     []thread           `json:"open_threads"`
				Violations  []rules.Violation  `json:"violations"`
				Allowed     []workflow.Allowed `json:"allowed_actions"`
			}{Engagement: ref.EngID, Dir: ref.Dir, State: st, Markdown: string(ref.F.Bytes()), Hash: ref.Full, CVSSBase: store.CVSSHash(ref.F.Meta),
				DetailsBase: store.DetailsHash(ref.F.Meta), Assets: append([]finding.Asset{}, ref.F.Meta.Assets...), AssetsBase: store.AssetsHash(ref.F.Meta),
				CanEdit: workflow.CanEdit(u, ref.F.Meta), Threads: []thread{}, Violations: []rules.Violation{}, Bases: s.fieldBases(ref.F.Meta)}
			// the group bases carry each row's own: sent again with every
			// edit, each is checked against its row only
			out.DetailsBase = rowsToken(out.Bases, "details.")
			out.CVSSBase = rowsToken(out.Bases, "cvss")
			if out.Files, err = s.Store.AttachmentsHash(ref.EngID, ref.Dir); err != nil {
				return "", err
			}
			if e, err := s.Store.Engagement(ref.EngID); err != nil || e.Archived {
				out.CanEdit = false // every write is refused while archived
			}
			if tk, ok := tokenFrom(ctx); ok && !tk.Allows("edit") {
				out.CanEdit = false // the token may not edit, whatever the account may
			}
			for _, sct := range ref.F.Sections {
				out.Sections = append(out.Sections, sec{sct.Name, store.BodyHash(sct.Body), sct.Body})
			}
			out.Allowed = s.allowedActions(ctx, u, ref)
			msgs, _ := s.Store.Chat(ref.EngID, ref.Dir)
			for _, it := range chat.Timeline(msgs) {
				if it.Thread != nil && !it.Thread.Resolved {
					t := it.Thread
					th := thread{ID: t.Root.ID, User: t.Root.User, Section: t.Root.Section, Text: t.Root.Text, Replies: []msg{}}
					for _, r := range t.Replies {
						th.Replies = append(th.Replies, msg{r.User, r.Text, r.Kind == chat.KindAI})
					}
					out.Threads = append(out.Threads, th)
				}
			}
			if s.Rules != nil {
				out.Violations = append(out.Violations, s.Rules.Lint(ctx, ref.F, rules.Fast)...)
			}
			return ok(out)
		}},
	{name: "list_templates", desc: "List the finding templates (.yars/templates): slug, title, severity and how many findings were made from each. Pass a slug to create_finding as template.",
		optional: []param{pLimit, pCursor},
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
			return listPage(a, out)
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
				if errors.Is(err, store.ErrNotFound) {
					if _, eerr := s.Store.Engagement(a.str("engagement")); eerr == nil {
						return "", refuse("not_found", fmt.Sprintf("unknown template %q; see list_templates", slug))
					}
				}
			} else {
				ref, err = s.Store.CreateFinding(a.str("engagement"), a.str("title"), u.GitAuthor())
			}
			if err != nil {
				return "", err
			}
			return ok(struct {
				ID  string `json:"id"`
				Dir string `json:"dir"`
			}{ref.F.Meta.ID, ref.Dir})
		}},
	{name: "update_section", action: "edit", desc: "Replace the Markdown body of one ## section. Pass base (from read_finding) to refuse the edit if the section changed since you read it. Use ### or deeper headings inside the body.",
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
			valid := slices.Clone(s.conf().Sections)
			for _, sct := range ref.F.Sections {
				if !slices.Contains(valid, sct.Name) {
					valid = append(valid, sct.Name)
				}
			}
			if !slices.Contains(valid, a.str("section")) {
				return "", invalid("unknown section %q; valid sections: %s", a.str("section"), strings.Join(valid, ", "))
			}
			if err := s.Store.UpdateSection(ref.EngID, ref.Dir, a.str("section"), a.str("body"), a.str("base"), u); err != nil {
				return "", err
			}
			return okMsg("updated " + a.str("section"))
		}},
	{name: "set_field", action: "edit", desc: "Set a field: title, severity (no CVSS vector), cvss (vector or empty to clear; a metric whose value changes loses its cvss_reason, and clearing removes every reason), cvss_reason.<METRIC> (explanation for a non-standard value, e.g. cvss_reason.AC), details.<Row> (details table, e.g. details.Location), reviewers (comma-separated usernames; replaces the whole list, so a reviewer who is not the author or a director must include the current names and cannot add themselves; with base, the list's field_bases entry, it is refused when the list changed since, so nobody added meanwhile is dropped), retest_result (fixed | not_fixed | partially_fixed), assets (the whole affected-asset list as JSON: [{\"host\":\"app.example\",\"url\":\"https://app.example/x\",\"port\":\"443\",\"note\":\"…\"}], [] to clear). Use transition for status.",
		required: []param{pEng, pFinding, {"field", "field name"}, {"value", "new value"}},
		optional: []param{{"base", "the field's entry in field_bases from read_finding (details.*, cvss, cvss_reason.*: refused only if that one row changed since; each set_field answer gives the row's new base; after cvss, one base for the vector and every reason), or cvss_base, details_base or assets_base (assets); refuses the edit if it changed since you read it"}},
		simple:   &toolText{desc: "Set a field: title, severity (no CVSS vector), cvss (vector or empty to clear; a metric whose value changes loses its cvss_reason, and clearing removes every reason), cvss_reason.<METRIC> (explanation for a non-standard value, e.g. cvss_reason.AC), details.<Row> (details table, e.g. details.Location), retest_result (fixed | not_fixed | partially_fixed), assets (the whole affected-asset list as JSON: [{\"host\":\"app.example\",\"url\":\"https://app.example/x\",\"port\":\"443\",\"note\":\"…\"}], [] to clear). Use transition for status."},
		run:      setField},
	{name: "transition", action: "status", serverOnly: true, desc: "Move a finding through the workflow: submit (draft→verification), return (verification→draft, needs reason), clear or sign_off (an assigned reviewer or a director; a director also on their own finding), approve (director, after a sign-off by an assigned reviewer other than them: verification→complete), reopen (author or director: complete→verification, needs reason), report (author or director: complete→reported), unreport (author or director: reported→complete, needs reason; the approval stays), revert (the step back from where the finding is: reopen or unreport), withdraw (author while draft or verification, director also when complete or reported; needs reason; takes it out of the report), revise (author or director: withdrawn→draft), take_back (author or director: verification→draft, no reason; sign-offs start over). The statuses are draft, verification, complete, reported, withdrawn. clear, sign_off and approve need base, the hash from read_finding: they are refused without it, and when the finding changed since you read it. With attachments_base (read_finding's attachments_hash) they are refused when an attachment changed since, too.",
		required: []param{pEng, pFinding, {"action", "submit | return | clear | sign_off | approve | reopen | report | unreport | revert | withdraw | revise | take_back"}},
		optional: []param{{"reason", "required for return, withdraw, reopen, unreport and revert"},
			{"base", "the hash from read_finding: required for clear, sign_off and approve, which are refused if the finding changed since you read it (other actions ignore it)"},
			{"attachments_base", "attachments_hash from read_finding: clear, sign_off and approve are refused if an attachment was added, replaced or removed since you read it (other actions ignore it)"}},
		simple: &toolText{desc: "Move a finding through the simple workflow, draft → complete → reported: complete (draft→complete), reopen (complete→draft, needs reason), report (complete→reported), unreport (reported→complete, needs reason; the completion stays), revert (the step back from where the finding is: reopen or unreport), withdraw (from draft, complete or reported; needs reason; takes it out of the report), revise (withdrawn→draft). The statuses are draft, complete, reported, withdrawn. complete needs base, the hash from read_finding: it is refused without it, and when the finding changed since you read it. With attachments_base (read_finding's attachments_hash) it is refused when an attachment changed since, too.",
			params: map[string]string{"action": "complete | reopen | report | unreport | revert | withdraw | revise",
				"reason":           "required for withdraw, reopen, unreport and revert",
				"base":             "the hash from read_finding: required for complete, which is refused if the finding changed since you read it (other actions ignore it)",
				"attachments_base": "attachments_hash from read_finding: complete is refused if an attachment was added, replaced or removed since you read it (other actions ignore it)"}},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			ref, err := s.ref(a)
			if err != nil {
				return "", err
			}
			f := s.flow()
			act, ok := workflow.ParseAction(a.str("action"))
			if from, _ := f.Target(act); ok && from == nil && !f.Simple {
				// complete, the simple workflow's: unknown in the standard one,
				// as before it came. The simple workflow refuses the standard
				// one's steps by name (Check: not part of the simple workflow).
				ok = false
			}
			if !ok && strings.EqualFold(strings.TrimSpace(a.str("action")), "revert") {
				// R4: the step back from the finding's status
				if act, ok = workflow.RevertOf(ref.F.Meta.Status); !ok {
					// as reopen or unreport on that status: not allowed
					return "", refuse("not_allowed", "nothing to revert: the finding is "+ref.F.Meta.Status)
				}
			}
			if !ok {
				return "", invalid("unknown action (%s)", actionNames(f))
			}
			// who may take an action is the workflow's (the store asks it), as
			// on the website: an agent follows its account's rules.
			// A missing reason is a missing argument, once the role and the
			// status allow the action and nothing else refuses it first (a
			// clone, the archive: the store's own refusals come then)
			if workflow.NeedsReason(act) && strings.TrimSpace(a.str("reason")) == "" && f.Check(u, ref.F.Meta, act) == nil &&
				s.Store.DB() != nil && !s.Store.Archived(ref.EngID) {
				what := map[workflow.Action]string{workflow.Return: "return", workflow.Withdraw: "withdraw"}[act]
				if what == "" {
					what = "revert"
				}
				return "", refuse("invalid", "a reason is required to "+what+" a finding")
			}
			// base: the version read, as the website's page sends it (kept for
			// a sign-off, an approval or a completion only). Such a step
			// without it would sign a version nobody named, so it never
			// reaches the store: what refuses the step anyway is said first,
			// in the store's order, then the missing argument
			base := strings.TrimSpace(a.str("base"))
			if store.SignsOff(act) && base == "" {
				switch err := f.Check(u, ref.F.Meta, act); {
				case s.Store.DB() == nil:
					return "", store.ErrNoDB
				case s.Store.Archived(ref.EngID):
					return "", store.ErrArchived
				case err != nil:
					return "", err
				}
				return "", refuse("invalid", missingBase(f))
			}
			// attachments_base: the attachments as read (not compared when
			// left out)
			if err := s.Store.TransitionSeen(ref.EngID, ref.Dir, act, a.str("reason"), base, strings.TrimSpace(a.str("attachments_base")), u); err != nil {
				return "", err
			}
			_, to := f.Target(act)
			return okMsg(string(act) + " done; status is now " + to)
		}},
	{name: "add_chat_message", action: "comment", serverOnly: true, desc: "Post a message in the finding's chat, optionally about a section or as a reply to a thread. @name mentions notify that person.",
		required: []param{pEng, pFinding, {"text", "Markdown message"}},
		optional: []param{{"section", "section the message is about (ignored with reply: the thread carries it)"}, {"reply", "thread ID to reply to"}},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			ref, err := s.ref(a)
			if err != nil {
				return "", err
			}
			m, err := s.Store.PostChat(ref.EngID, ref.Dir, chat.Message{Text: a.str("text"), Section: a.str("section"), Reply: a.str("reply")}, u)
			if err != nil {
				return "", err
			}
			return ok(struct {
				ID string `json:"id"`
			}{m.ID})
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
			return okMsg("resolved")
		}},
	{name: "lint_finding", desc: "Check a finding against the team's style rules (regex and built-in checks; with all=true also script and AI rules). Violations a reviewer dismissed are marked dismissed and do not block submit or approve. On the server all=true is a stored check run, as start_check starts: it waits in the queue, posts each new violation as a chat comment and is refused on an archived engagement. The answer waits for the run and has its run_id and state; when the run is still queued or running it lists nothing and says so: read get_check_results then.",
		required: []param{pEng, pFinding}, boolArgs: []param{{"all", "also run script and AI rules (slower; on the server a stored check run)"}},
		simple: &toolText{desc: "Check a finding against the team's style rules (regex and built-in checks; with all=true also script and AI rules). Violations someone dismissed are marked dismissed and do not block complete. On the server all=true is a stored check run, as start_check starts: it waits in the queue, posts each new violation as a chat comment and is refused on an archived engagement. The answer waits for the run and has its run_id and state; when the run is still queued or running it lists nothing and says so: read get_check_results then."},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			ref, err := s.ref(a)
			if err != nil {
				return "", err
			}
			if s.Rules == nil {
				return ok(struct {
					Items   []any  `json:"items"`
					Next    string `json:"next"`
					Message string `json:"message"`
				}{[]any{}, "", "no rules configured"})
			}
			kinds := rules.Fast
			if all, _ := a["all"].(bool); all {
				if s.Store.DB() != nil {
					// on the server every rule is a check run: it takes its
					// place in the queue and is refused where a write is
					return s.lintByCheck(ctx, ref, u)
				}
				// a clone (yars mcp) has no database: no queue, no archive
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
			// AI calls are recorded for the token's user on this finding (D24)
			for _, v := range s.Rules.Lint(rules.WithCaller(ctx, rules.Caller{User: u.Username, Eng: ref.EngID, Fid: ref.F.Meta.ID}), ref.F, kinds) {
				m := marked{Violation: v}
				if d, ok := db.Lookup(ds, v.Rule, v.Target, v.Quote); ok {
					m.Dismissed, m.DismissedBy = true, d.By
				}
				out = append(out, m)
			}
			return list(out, "")
		}},
	{name: "start_check", action: "checks", serverOnly: true, desc: "Start a stored check run of every rule (fast, script and AI) on a finding, as the Check button does. It runs in the background; while the server runs as many checks as it allows, it waits in a queue (state queued). Each new violation is posted as a chat comment. Read the outcome with get_check_results.",
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
			return ok(struct {
				RunID int64  `json:"run_id"`
				State string `json:"state"`
				Done  int    `json:"done"`
				Total int    `json:"total"`
			}{run.ID, run.State, run.Done, run.Total})
		}},
	{name: "get_check_results", serverOnly: true, desc: "The finding's latest check run: state (queued, running, done, failed), progress, whether the finding changed since (stale), and its results with dismissals.",
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
				_, dis := db.Lookup(st.Dismissed, x.Rule, x.Target, x.Quote)
				out.Results = append(out.Results, result{x.Rule, x.Level, x.Message, x.Target, x.Quote, x.Thread, dis})
			}
			return ok(out)
		}},
	{name: "list_notifications", serverOnly: true, desc: "Your notifications, newest first, a page at a time (the cursor is the id of the last one given, so marking some read between pages skips none): returned to you, review requested, replies, approvals, mentions, finished checks, tokens about to expire.",
		optional: []param{pLimit, pCursor}, boolArgs: []param{{"unread", "only unread ones"}},
		simple: &toolText{desc: "Your notifications, newest first, a page at a time (the cursor is the id of the last one given, so marking some read between pages skips none): replies, completions, mentions, finished checks, tokens about to expire."},
		run: func(s *Server, ctx context.Context, u config.User, a args) (string, error) {
			unread, _ := a["unread"].(bool)
			limit, before, err := pageArgs(a)
			if err != nil {
				return "", err
			}
			// paged by id in the query (the cursor is the last id given), with
			// the token's engagements: marking some read, or new ones
			// arriving, between two calls neither skips nor repeats any
			tk, hasTok := tokenFrom(ctx)
			var engs []string
			if hasTok {
				engs = tk.Engagements
			}
			l, err := s.Store.NotificationPage(u, unread, engs, int64(before), limit+1)
			if err != nil {
				return "", err
			}
			next := ""
			if len(l) > limit {
				l = l[:limit]
				next = strconv.FormatInt(l[limit-1].ID, 10)
			}
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
			title := func(eng, fid, then string) string { return then }
			if s.Index != nil {
				title = s.Index.CurrentTitles() // the title now, as the web shows it
			}
			f := s.flow()
			for _, n := range l {
				out = append(out, note{n.ID, eventIn(f, n.Event), n.Eng, n.Fid, n.Dir, title(n.Eng, n.Fid, n.Title), n.Actor, n.Text, n.TS, n.Read})
			}
			return list(out, next)
		}},
}

// eventIn is a notification's event as workflow f names it: the simple one
// has no approval, so what Complete tells the author (notify.Approved, the
// web's "Completed") is "completed" there.
func eventIn(f workflow.Flow, event string) string {
	if f.Simple && event == "approved" {
		return "completed"
	}
	return event
}

var toolByName = func() map[string]tool {
	m := map[string]tool{}
	for _, t := range tools {
		m[t.name] = t
	}
	return m
}()

// fieldBases are the per-row bases of set_field, by field name: each
// details row (configured or present), cvss and each cvss_reason, and the
// reviewer list. An edit is refused only when its own row changed since it
// was read.
func (s *Server) fieldBases(m finding.Meta) map[string]string {
	out := map[string]string{}
	for _, row := range s.conf().DetailsRows {
		out["details."+row] = store.RowHash(m.Details[row])
	}
	for row, v := range m.Details {
		out["details."+row] = store.RowHash(v)
	}
	maps.Copy(out, cvssBases(store.CVSSRowHashes(m)))
	if s.flow().HasReviewers() {
		out["reviewers"] = store.ReviewersHash(m)
	}
	return out
}

// cvssBases names the CVSS row bases (store.CVSSRowHashes) by field.
func cvssBases(rows map[string]string) map[string]string {
	out := map[string]string{}
	for k, b := range rows {
		if k == store.CVSSRow {
			out["cvss"] = b
		} else {
			out["cvss_reason."+k] = b
		}
	}
	return out
}

// rowsPrefix marks a base that carries the per-row bases of a group of
// fields (read_finding's details_base and cvss_base): an assistant that
// sends the same one with each edit is checked per row.
const rowsPrefix = "rows."

// rowsToken packs the bases of the fields with prefix pre.
func rowsToken(bases map[string]string, pre ...string) string {
	sub := map[string]string{}
	for k, v := range bases {
		for _, p := range pre {
			if strings.HasPrefix(k, p) {
				sub[k] = v
			}
		}
	}
	b, _ := json.Marshal(sub)
	return rowsPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// rowBase is the base of field in base: its entry when base is a rows
// token (none: "", unchecked), else base itself; table reports a plain
// base, which may also be the whole table's.
func rowBase(base, field string) (row string, table bool) {
	tok, ok := strings.CutPrefix(base, rowsPrefix)
	if !ok {
		return base, base != ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	var m map[string]string
	if err != nil || json.Unmarshal(raw, &m) != nil {
		return base, true // unreadable: refused as a stale base
	}
	if b, ok := m[field]; ok {
		return b, false
	}
	return store.RowHash(""), false // not there when it was read: empty
}

// cvssChange is the change of one CVSS row (key: store.CVSSRow or a
// metric) checked against base: a rows token's entry for field, or a plain
// base (the row's own, or the whole cvss_base).
func cvssChange(base, field, key string, vector *string, reasons map[string]string) store.CVSSChange {
	ch := store.CVSSChange{Vector: vector, Reasons: reasons}
	rb, table := rowBase(base, field)
	ch.Bases = map[string]string{key: rb}
	if table {
		ch.Table = base
	}
	return ch
}

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
		// base: this row's field_bases entry, or the whole cvss_base
		var nb map[string]string
		nb, err = st.UpdateCVSSRows(eng, dir, cvssChange(base, field, store.CVSSRow, &value, nil), u)
		if err == nil {
			// a reason's base covers its metric's value: the vector's edit
			// changes them, so the answer carries every CVSS row's base
			msg := "set cvss"
			if v, perr := cvss.Parse(value); perr == nil && cvss.Version(value) == "3.0" {
				// taken, and written as this server's version: said, not silent
				msg += "; the CVSS:3.0 vector is stored as " + v.String()
			}
			return okBase(msg, rowsToken(cvssBases(nb), "cvss"))
		}
	case strings.HasPrefix(field, "cvss_reason."):
		key := strings.ToUpper(strings.TrimPrefix(field, "cvss_reason."))
		if !slices.ContainsFunc(cvss.Metrics, func(m cvss.Metric) bool { return m.Key == key }) {
			return "", invalid("%s is not a CVSS base metric (AV, AC, PR, UI, S, C, I, A)", key)
		}
		if _, err := cvss.Parse(ref.F.Meta.CVSS); err != nil {
			return "", invalid("set a CVSS vector first")
		}
		// the vector is read inside the change: never written back stale
		var nb map[string]string
		nb, err = st.UpdateCVSSRows(eng, dir, cvssChange(base, "cvss_reason."+key, key, nil, map[string]string{key: value}), u)
		if err == nil {
			return okBase("set cvss_reason."+key, nb[key])
		}
	case strings.HasPrefix(field, "details."):
		row := strings.TrimPrefix(field, "details.")
		if rows := s.conf().DetailsRows; !slices.Contains(rows, row) {
			return "", invalid("unknown details row %q; rows: %s", row, strings.Join(rows, ", "))
		}
		// base: this row's field_bases entry, or the whole details_base
		var nb map[string]string
		if rb, table := rowBase(base, field); table {
			nb, err = st.UpdateDetailsBase(eng, dir, map[string]string{row: value}, base, u)
		} else {
			nb, err = st.UpdateDetailsRows(eng, dir, map[string]string{row: value}, map[string]string{row: rb}, u)
		}
		if err == nil {
			return okBase("set "+field, nb[row])
		}
	case field == "reviewers":
		var names []string
		for _, n := range strings.Split(value, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
		// the simple workflow has no reviewers: the store refuses any list
		// (not_allowed), so no name is checked as if it could be one
		if s.Users != nil && s.flow().HasReviewers() {
			users := s.Users()
			for _, n := range names {
				if m := ref.F.Meta; n == m.Author && slices.Contains(m.Reviewers, n) {
					continue // a director author's own sign-off: kept as it is (Q25)
				}
				ok := false
				if i := slices.IndexFunc(users, func(x config.User) bool { return x.Username == n }); i >= 0 {
					if ok, err = st.MayReview(users[i], eng, ref.F.Meta); err != nil {
						return "", err // the team read failed: not the name's fault
					}
				}
				if !ok {
					return "", invalid("%s is not a reviewer or director account on the engagement's team (or is the author)", n)
				}
			}
		}
		// base: field_bases.reviewers. The value replaces the list, so a list
		// changed since it was read is refused. A group's token (details_base,
		// cvss_base) holds no reviewers entry: not checked.
		if strings.HasPrefix(base, rowsPrefix) {
			base = ""
		}
		err = st.SetReviewersFrom(eng, dir, base, names, u)
	case field == "retest_result":
		err = st.SetRetestResult(eng, dir, value, u)
	case field == "assets":
		var list []finding.Asset
		if jerr := json.Unmarshal([]byte(value), &list); jerr != nil {
			return "", invalid("assets must be a JSON list of {host, url, port, note}: %v", jerr)
		}
		err = st.UpdateAssets(eng, dir, list, base, u)
	case field == "status":
		return "", invalid("use the transition tool to change the status")
	default:
		return "", invalid("unknown field %q", field)
	}
	if err != nil {
		return "", err
	}
	return okMsg("set " + field)
}

// okBase answers a set_field that gives a row's new base: the sentence of
// before ("set cvss; new base …") and the base on its own.
func okBase(what, base string) (string, error) {
	return ok(struct {
		Message string `json:"message"`
		Base    string `json:"base"`
	}{what + "; new base " + base, base})
}
