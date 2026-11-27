package mcp

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/history"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

// The reading tools of MCP v2 (M32 task 5): who the caller is, the
// structure, the team, a finding's chat, history and attachments, a
// template; and the actions read_finding offers.

var readingTools = []tool{
	{name: "whoami", desc: "Who you are here: username, role, whether you are an admin, and (over HTTP) your token's actions and engagements (an empty engagement list: every engagement of the account).",
		simple: &toolText{desc: "Who you are here: username, whether you are an admin, and (over HTTP) your token's actions and engagements (an empty engagement list: every engagement of the account)."},
		run:    whoami},
	{name: "get_config", desc: "The team's structure: the sections and details rows of a finding, the severities, the CVSS version and standard values (a different value needs a written reason), the statuses and the transition actions.",
		run: getConfig},
	{name: "list_team", serverOnly: true, desc: "The engagement's team: each member's username and role.",
		required: []param{pEng}, optional: []param{pLimit, pCursor},
		simple: &toolText{desc: "The engagement's team: each member's username."},
		run:    listTeam},
	{name: "read_chat", serverOnly: true, desc: "The finding's whole chat, oldest first, a page at a time: threads (with replies; an AI reply is marked ai, a check run's thread has kind check) and workflow events.",
		required: []param{pEng, pFinding}, optional: []param{pLimit, pCursor},
		run: readChat},
	{name: "list_history", desc: "The finding's versions, newest first, a page at a time: commit, author (ai: made by Fix with AI for that user), time and the parts that changed.",
		required: []param{pEng, pFinding}, optional: []param{pLimit, pCursor},
		run: listHistory},
	{name: "list_attachments", desc: "The finding's attachments: name, size, type (image or file) and whether an earlier version (before a redaction) is still in the history.",
		required: []param{pEng, pFinding}, optional: []param{pLimit, pCursor},
		run: listAttachments},
	{name: "read_template", desc: "One finding template's Markdown (front matter and sections) by its slug from list_templates.",
		required: []param{{"template", "template slug from list_templates"}},
		run:      readTemplate},
}

func whoami(s *Server, ctx context.Context, u config.User, a args) (string, error) {
	type token struct {
		Scopes      []string `json:"scopes"`
		Engagements []string `json:"engagements"`
	}
	role := u.Role
	if s.flow().Simple {
		role = "" // no roles: whether one is an admin is the only difference
	}
	out := struct {
		Username string `json:"username"`
		Role     string `json:"role,omitempty"`
		Admin    bool   `json:"admin"`
		Token    *token `json:"token,omitempty"`
	}{u.Username, role, u.IsAdmin, nil}
	if tk, ok := tokenFrom(ctx); ok {
		out.Token = &token{append([]string{}, tk.Scopes...), append([]string{}, tk.Engagements...)}
	}
	return ok(out)
}

func getConfig(s *Server, ctx context.Context, u config.User, a args) (string, error) {
	c, f := s.conf(), s.flow()
	actions := []string{}
	for _, act := range f.Actions() {
		actions = append(actions, string(act))
	}
	actions = append(actions, "revert") // the step back, by status
	return ok(struct {
		Workflow    string            `json:"workflow"` // standard or simple, as yars init set it up
		Sections    []string          `json:"sections"`
		DetailsRows []string          `json:"details_rows"`
		Severities  []string          `json:"severities"`
		CVSSVersion string            `json:"cvss_version"`
		Standard    map[string]string `json:"cvss_standard"`
		Statuses    []string          `json:"statuses"`
		Actions     []string          `json:"actions"`
	}{f.Name(), c.Sections, c.DetailsRows, c.Severities, c.CVSS.Version, c.CVSS.Standard, f.AllStatuses(), actions})
}

func listTeam(s *Server, ctx context.Context, u config.User, a args) (string, error) {
	if err := a.need("engagement"); err != nil {
		return "", err
	}
	if _, err := s.Store.Engagement(a.str("engagement")); err != nil {
		return "", err // a director sees every engagement: an unknown one is still not found
	}
	members, err := s.Store.Members(a.str("engagement"))
	if err != nil {
		return "", err
	}
	roles := map[string]string{}
	if s.Users != nil && !s.flow().Simple { // the simple workflow has no roles
		for _, x := range s.Users() {
			roles[x.Username] = x.Role
		}
	}
	type member struct {
		Username string `json:"username"`
		Role     string `json:"role,omitempty"`
	}
	slices.Sort(members)
	out := []member{}
	for _, m := range members {
		out = append(out, member{m, roles[m]})
	}
	return listPage(a, out)
}

// stamp is a time as the answers give it (RFC 3339, UTC); "" for none.
func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func readChat(s *Server, ctx context.Context, u config.User, a args) (string, error) {
	ref, err := s.ref(a)
	if err != nil {
		return "", err
	}
	if s.Store.DB() == nil {
		return "", store.ErrNoDB // the chat is the server's, not empty
	}
	msgs, err := s.Store.ChatOf(ref)
	if err != nil {
		return "", err
	}
	type reply struct {
		ID   string `json:"id"`
		User string `json:"user"`
		At   string `json:"at"`
		Text string `json:"text"`
		AI   bool   `json:"ai,omitempty"`
	}
	type item struct {
		Type       string  `json:"type"` // thread | event
		ID         string  `json:"id"`
		User       string  `json:"user"`
		At         string  `json:"at"`
		Section    string  `json:"section,omitempty"`
		Text       string  `json:"text,omitempty"`
		Event      string  `json:"event,omitempty"`
		Kind       string  `json:"kind,omitempty"` // check: a check run's thread
		Resolved   bool    `json:"resolved,omitempty"`
		ResolvedBy string  `json:"resolved_by,omitempty"`
		Replies    []reply `json:"replies,omitempty"`
	}
	out := []item{}
	for _, it := range chat.Timeline(msgs) {
		if e := it.Event; e != nil {
			out = append(out, item{Type: "event", ID: e.ID, User: e.User, At: stamp(e.TS), Event: e.Event, Text: e.Text})
			continue
		}
		t := it.Thread
		x := item{Type: "thread", ID: t.Root.ID, User: t.Root.User, At: stamp(t.Root.TS), Section: t.Root.Section, Text: t.Root.Text,
			Kind: t.Root.Kind, Resolved: t.Resolved, ResolvedBy: t.ResolvedBy, Replies: []reply{}}
		for _, r := range t.Replies {
			x.Replies = append(x.Replies, reply{r.ID, r.User, stamp(r.TS), r.Text, r.Kind == chat.KindAI})
		}
		out = append(out, x)
	}
	return listPage(a, out)
}

func listHistory(s *Server, ctx context.Context, u config.User, a args) (string, error) {
	ref, err := s.ref(a)
	if err != nil {
		return "", err
	}
	repo, err := s.Store.EngRepo(ref.EngID)
	if err != nil {
		return "", err
	}
	file := path.Join("findings", ref.Dir, "finding.md")
	var vs []history.Version
	if s.Store.DB() == nil {
		// a clone: its HEAD moves outside this process too (a pull, a hand
		// commit), which the store's head does not see; read git each time
		vs, err = history.Versions(repo, file)
	} else {
		// cached per engagement HEAD, as the history page does: paging does
		// not start git again
		var head string
		if head, err = s.Store.EngHead(ref.EngID); err == nil {
			vs, err = s.historyCache().Versions(repo, ref.EngID+"/"+ref.Dir, head, file)
		}
	}
	if err != nil {
		return "", err
	}
	idx := make([]int, len(vs))
	for i := range idx {
		idx[i] = i
	}
	pg, next, err := page(a, idx)
	if err != nil {
		return "", err
	}
	type version struct {
		Commit  string   `json:"commit"`
		Author  string   `json:"author"`
		AI      bool     `json:"ai,omitempty"`
		Time    string   `json:"time"`
		Subject string   `json:"subject"`
		Changed []string `json:"changed"`
	}
	out := []version{}
	for _, i := range pg { // what changed: worked out for the page only
		v := vs[i]
		changed := []string{"created"}
		if i+1 < len(vs) {
			if changed = history.Parts(vs[i+1].Raw, v.Raw); len(changed) == 0 {
				changed = []string{v.Subject}
			}
		}
		who, ai := history.Who(v.Author)
		out = append(out, version{v.Hash, who, ai, stamp(v.Time), v.Subject, changed})
	}
	return list(out, next)
}

// historyCache keeps findings' versions per engagement HEAD (as the web's
// history page does).
func (s *Server) historyCache() *history.Cache {
	s.histOnce.Do(func() { s.hist = history.NewCache(256) })
	return s.hist
}

func listAttachments(s *Server, ctx context.Context, u config.User, a args) (string, error) {
	ref, err := s.ref(a)
	if err != nil {
		return "", err
	}
	as, err := s.Store.AttachmentsOf(ref)
	if err != nil {
		return "", err
	}
	type att struct {
		Name     string `json:"name"`
		Size     int64  `json:"size"`
		Type     string `json:"type"` // image | file
		Modified string `json:"modified,omitempty"`
		// left out on a clone: the server's database knows it
		InHistory *bool `json:"earlier_version_in_history,omitempty"`
	}
	out := []att{}
	for _, x := range as {
		kind := "file"
		if x.Image {
			kind = "image"
		}
		var in *bool
		if s.Store.DB() != nil {
			in = &x.HasOriginal
		}
		out = append(out, att{x.Name, x.Size, kind, stamp(x.ModTime), in})
	}
	return listPage(a, out)
}

func readTemplate(s *Server, ctx context.Context, u config.User, a args) (string, error) {
	if err := a.need("template"); err != nil {
		return "", err
	}
	t, err := s.Store.Template(a.str("template"))
	if err != nil {
		return "", err
	}
	m := t.F.Meta
	return ok(struct {
		Slug     string `json:"slug"`
		Title    string `json:"title"`
		Severity string `json:"severity,omitempty"`
		CVSS     string `json:"cvss,omitempty"`
		Markdown string `json:"markdown"`
	}{t.Slug, m.Title, m.Severity, m.CVSS, string(t.F.Bytes())})
}

// writingTools are MCP v2's new writing tools (M32 task 6).
var writingTools = []tool{
	{name: "mark_notifications_read", serverOnly: true, desc: "Mark your notifications read: ids (comma-separated, from list_notifications) or all. Your own state: a read-only token may do it; a token limited to some engagements marks only theirs.",
		optional: []param{{"ids", "notification ids, comma-separated"}}, boolArgs: []param{{"all", "every unread notification"}},
		run: markRead},
	{name: "fix_checks", action: "checks", also: "edit", serverOnly: true, desc: "Fix with AI: the AI fixes the finding's open check results one by one in the background, answers each result's thread (marked AI) and a check run follows. Needs a finished check run on the current text and an AI provider; drafts and findings in verification only; a token needs run checks and edit findings. Read the outcome with get_check_results and read_chat.",
		required: []param{pEng, pFinding},
		simple:   &toolText{desc: "Fix with AI: the AI fixes the finding's open check results one by one in the background, answers each result's thread (marked AI) and a check run follows. Needs a finished check run on the current text and an AI provider; drafts only; a token needs run checks and edit findings. Read the outcome with get_check_results and read_chat."},
		run:      fixChecks},
}

func markRead(s *Server, ctx context.Context, u config.User, a args) (string, error) {
	d := s.Store.DB()
	if d == nil {
		return "", store.ErrNoDB
	}
	all, _ := a["all"].(bool)
	ids := strings.TrimSpace(a.str("ids"))
	if all == (ids != "") {
		return "", refuse("invalid", "give ids or all (true), one of them")
	}
	tk, hasTok := tokenFrom(ctx)
	if all {
		var engs []string
		if hasTok {
			engs = tk.Engagements
		}
		if err := d.MarkAllReadIn(u.Username, engs); err != nil {
			return "", err
		}
		return okMsg("marked all read")
	}
	var list []int64
	for _, p := range strings.Split(ids, ",") {
		id, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64)
		if err != nil || id <= 0 {
			return "", refuse("invalid", fmt.Sprintf("ids must be notification ids from list_notifications, comma-separated (not %q)", strings.TrimSpace(p)))
		}
		if !slices.Contains(list, id) {
			list = append(list, id)
		}
		if len(list) > maxLimit {
			return "", refuse("invalid", fmt.Sprintf("at most %d ids at a time (or all)", maxLimit))
		}
	}
	// every id is checked before any is marked: the caller's own, of the
	// token's engagements
	for _, id := range list {
		n, found, err := d.NotificationByID(u.Username, id)
		if err != nil {
			return "", err
		}
		if !found || (hasTok && !tk.AllowsEng(n.Eng)) {
			return "", refuse("not_found", fmt.Sprintf("no notification %d of yours", id))
		}
	}
	if err := d.MarkReadIDs(u.Username, list); err != nil {
		return "", err
	}
	return okMsg(fmt.Sprintf("marked %d read", len(list)))
}

func fixChecks(s *Server, ctx context.Context, u config.User, a args) (string, error) {
	ref, err := s.ref(a)
	if err != nil {
		return "", err
	}
	if err := s.Store.StartFix(ref.EngID, ref.Dir, u); err != nil {
		return "", err
	}
	return okMsg("fix started; read get_check_results")
}

// allowedActions are the actions of the finding's status as u could take
// them over MCP now, with the reason transition would give, checked in its
// order: the token, then no database (a clone), the archive, the role,
// status and content gate, and for submit,
// approve, sign off and complete the store's own blocks with the fast rules
// (script and AI rules run at the transition itself). The actions are those
// of the data folder's workflow (AllowedActions reads it from the config).
// A sign-off, an approval and a completion need base.
func (s *Server) allowedActions(ctx context.Context, u config.User, ref store.FindingRef) []workflow.Allowed {
	out := workflow.AllowedActions(u, ref.F.Meta, s.conf())
	tk, hasTok := tokenFrom(ctx)
	// the transition tool as the gate sees it (its own entry would make an
	// initialization cycle: read_finding is in the same table)
	transition := tool{name: "transition", action: "status"}
	for i := range out {
		al := &out[i]
		act := workflow.Action(al.Action)
		if store.SignsOff(act) {
			al.Needs = "base" // transition refuses it without (none of them takes a reason)
		}
		why := ""
		switch need := actionOf(transition, args{"action": al.Action}); {
		case hasTok && !tk.Allows(need):
			why = "this token may not " + actionLabel[need] // the gate's, before the tool runs
		case s.Store.DB() == nil:
			why = store.ErrNoDB.Error()
		case s.Store.Archived(ref.EngID):
			why = store.ErrArchived.Error()
		case al.Enabled:
			var err error
			if why, err = s.Store.BlockingNow(ref.EngID, ref.Dir, act, u); err != nil {
				// the transition would fail the same way, and say the same
				if codeOf(err) == "server_error" {
					s.log().Error("mcp: a finding's allowed action is not worked out", "req", logs.ReqID(ctx), "tool", "read_finding", "user", u.Username,
						"action", al.Action, "eng", ref.EngID, "finding", store.LogID(ref.Dir), "err", err)
				}
				why = wording(err)
			}
		}
		if why != "" {
			al.Enabled, al.Reason = false, why
		}
	}
	return out
}
