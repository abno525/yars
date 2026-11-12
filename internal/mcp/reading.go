package mcp

import (
	"context"
	"path"
	"slices"
	"time"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/history"
	"yars/internal/store"
	"yars/internal/workflow"
)

// The reading tools of MCP v2 (M32 task 5): who the caller is, the
// structure, the team, a finding's chat, history and attachments, a
// template; and the actions read_finding offers.

var readingTools = []tool{
	{name: "whoami", desc: "Who you are here: username, role, whether you are an admin, and (over HTTP) your token's actions and engagements (an empty engagement list: every engagement of the account).",
		run: whoami},
	{name: "get_config", desc: "The team's structure: the sections and details rows of a finding, the severities, the CVSS version and standard values (a different value needs a written reason), the statuses and the transition actions.",
		run: getConfig},
	{name: "list_team", serverOnly: true, desc: "The engagement's team: each member's username and role.",
		required: []param{pEng}, optional: []param{pLimit, pCursor},
		run: listTeam},
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
	out := struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Admin    bool   `json:"admin"`
		Token    *token `json:"token,omitempty"`
	}{u.Username, u.Role, u.IsAdmin, nil}
	if tk, ok := tokenFrom(ctx); ok {
		out.Token = &token{append([]string{}, tk.Scopes...), append([]string{}, tk.Engagements...)}
	}
	return ok(out)
}

func getConfig(s *Server, ctx context.Context, u config.User, a args) (string, error) {
	c := s.conf()
	actions := []string{}
	for _, act := range workflow.Actions {
		actions = append(actions, string(act))
	}
	actions = append(actions, "revert") // the step back, by status
	return ok(struct {
		Sections    []string          `json:"sections"`
		DetailsRows []string          `json:"details_rows"`
		Severities  []string          `json:"severities"`
		CVSSVersion string            `json:"cvss_version"`
		Standard    map[string]string `json:"cvss_standard"`
		Statuses    []string          `json:"statuses"`
		Actions     []string          `json:"actions"`
	}{c.Sections, c.DetailsRows, c.Severities, c.CVSS.Version, c.CVSS.Standard, workflow.AllStatuses, actions})
}

func listTeam(s *Server, ctx context.Context, u config.User, a args) (string, error) {
	if err := a.need("engagement"); err != nil {
		return "", err
	}
	members, err := s.Store.Members(a.str("engagement"))
	if err != nil {
		return "", err
	}
	roles := map[string]string{}
	if s.Users != nil {
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

// stamp is a time as the answers give it (RFC 3339, UTC).
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func readChat(s *Server, ctx context.Context, u config.User, a args) (string, error) {
	ref, err := s.ref(a)
	if err != nil {
		return "", err
	}
	msgs, err := s.Store.Chat(ref.EngID, ref.Dir)
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
	vs, err := history.Versions(repo, path.Join("findings", ref.Dir, "finding.md"))
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
	for i, v := range vs {
		changed := []string{"created"}
		if i+1 < len(vs) {
			if changed = history.Parts(vs[i+1].Raw, v.Raw); len(changed) == 0 {
				changed = []string{v.Subject}
			}
		}
		who, ai := history.Who(v.Author)
		out = append(out, version{v.Hash, who, ai, stamp(v.Time), v.Subject, changed})
	}
	return listPage(a, out)
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
		Name      string `json:"name"`
		Size      int64  `json:"size"`
		Type      string `json:"type"` // image | file
		Modified  string `json:"modified"`
		InHistory bool   `json:"earlier_version_in_history"`
	}
	out := []att{}
	for _, x := range as {
		kind := "file"
		if x.Image {
			kind = "image"
		}
		out = append(out, att{x.Name, x.Size, kind, stamp(x.ModTime), x.HasOriginal})
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

// allowedActions are the actions of the finding's status as u could take
// them over MCP now, with the reason transition would give, checked in its
// order: marking reported is a director's here, then no database (a
// clone), the archive, the role, status and content gate, and for submit,
// approve and sign off the store's own blocks with the fast rules (script
// and AI rules run at the transition itself).
func (s *Server) allowedActions(u config.User, ref store.FindingRef) []workflow.Allowed {
	out := workflow.AllowedActions(u, ref.F.Meta, s.conf())
	for i := range out {
		al := &out[i]
		act := workflow.Action(al.Action)
		why := ""
		switch {
		case act == workflow.Report && !workflow.AtLeast(u, "director"):
			why = "only a director can mark reported"
		case s.Store.DB() == nil:
			why = store.ErrNoDB.Error()
		case s.Store.Archived(ref.EngID):
			why = store.ErrArchived.Error()
		case al.Enabled:
			why, _ = s.Store.BlockingNow(ref.EngID, ref.Dir, act, u)
		}
		if why != "" {
			al.Enabled, al.Reason = false, why
		}
	}
	return out
}
