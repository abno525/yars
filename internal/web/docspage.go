package web

import (
	"html/template"
	"net/http"
	"slices"
	"strings"

	"yars/docs"
	"yars/internal/db"
	"yars/internal/mcp"
	"yars/internal/webhook"
)

// docsTabs are the developer pages, in the rail's order.
var docsTabs = []struct{ Key, Label string }{
	{"mcp", "MCP"}, {"rules", "Script rules"}, {"exporters", "Script exporters"},
	{"git", "Git"}, {"config", "Config"}, {"webhooks", "Webhooks"},
}

// docsView is a developer docs page: generated panels (from the code) and
// the page's Markdown from docs/<page>.md.
type docsView struct {
	Page  string
	Title string
	Tabs  []adminTab
	HTML  template.HTML
	// MCP
	MCPURL, Protocol, OlderProtocols string
	Tools                            []mcp.ToolDoc
	Actions                          []actionTools
	Tokens                           int
	User                             string
	// Git
	MainURL, EngURL string
	EngOpts         []option
	// Webhooks
	Events []string
}

// actionTools is a token action and the tools it opens.
type actionTools struct {
	Action, Label string
	Tools         []string
}

func (s *Server) routesDocs(mux *http.ServeMux) {
	mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs/mcp", http.StatusSeeOther)
	})
	// the single scripts page became two tabs; old links land on the first
	mux.HandleFunc("GET /docs/scripts", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs/rules", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /docs/{page}", s.docsPage)
}

// actionTag is the tag class of a token action.
func actionTag(a string) string {
	switch a {
	case "create", "edit", "reviewers":
		return "act-edit"
	case "status":
		return "act-status"
	case "comment":
		return "act-chat"
	case "checks":
		return "act-checks"
	case "export":
		return "act-export"
	}
	return "act-read"
}

// actionName is the tag text of a token action.
func actionName(a string) string {
	switch actionTag(a) {
	case "act-edit":
		return "Edit"
	case "act-status":
		return "Status"
	case "act-chat":
		return "Chat"
	case "act-checks":
		return "Checks"
	case "act-export":
		return "Export"
	}
	return "Read"
}

// dropSection removes a "## name" section from Markdown (the MCP page
// shows the generated tool table instead of the file's).
func dropSection(md, name string) string {
	i := strings.Index(md, "\n## "+name+"\n")
	if i < 0 {
		return md
	}
	rest := md[i+1:]
	if j := strings.Index(rest[3:], "\n## "); j >= 0 {
		return md[:i+1] + rest[3+j+1:]
	}
	return md[:i+1]
}

// dropTitle removes the "# title" line (the page has its own heading).
func dropTitle(md string) string {
	if strings.HasPrefix(md, "# ") {
		if i := strings.Index(md, "\n"); i >= 0 {
			return md[i+1:]
		}
	}
	return md
}

func (s *Server) docsPage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("page")
	i := slices.IndexFunc(docsTabs, func(t struct{ Key, Label string }) bool { return t.Key == name })
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	src, err := docs.Page(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Nav = "settings" // Developers opens from the user name, so the user name is lit
	v := &p.Docs
	v.Page, v.Title, v.User = name, docsTabs[i].Label, p.User.Username
	for _, t := range docsTabs {
		v.Tabs = append(v.Tabs, adminTab{Label: t.Label, URL: "/docs/" + t.Key, On: t.Key == name})
	}
	base := s.conf().BaseURL
	if base == "" {
		base = gitBase(r)
	}
	switch name {
	case "mcp":
		src = dropSection(src, "Tools")
		v.MCPURL = base + "/mcp"
		pv := mcp.ProtocolVersions()
		v.Protocol, v.OlderProtocols = pv[0], strings.Join(pv[1:], " · ")
		v.Tools = mcp.Catalog()
		byAction := map[string][]string{}
		for _, t := range v.Tools {
			byAction[t.Action] = append(byAction[t.Action], t.Name)
			if t.Also != "" { // a tool that needs a second action too (fix_checks: edit)
				byAction[t.Also] = append(byAction[t.Also], t.Name)
			}
		}
		byAction["reviewers"] = append(byAction["reviewers"], "set_field reviewers")
		byAction["export"] = append(byAction["export"], "transition report")
		for _, a := range append([]string{db.ScopeRead}, db.TokenActions...) {
			label := tokenActionLabels[a]
			if a == "read" {
				label = "Read findings and chat"
			}
			v.Actions = append(v.Actions, actionTools{Action: a, Label: label, Tools: byAction[a]})
		}
		if s.Tokens != nil {
			for _, t := range s.Tokens.ListFor(p.User.Username) {
				if t.Kind == db.TokenMCP {
					v.Tokens++
				}
			}
		}
	case "git":
		if p.engsErr != nil { // the clone list needs the engagements
			s.fail(w, p.engsErr)
			return
		}
		who := strings.Replace(base, "://", "://"+p.User.Username+"@", 1)
		v.MainURL = who + "/git/yars"
		v.EngURL = who + "/git/e/"
		for _, e := range p.Engagements {
			v.EngOpts = append(v.EngOpts, option{Value: e.ID, Label: e.Name, On: e.ID == p.Eng.ID})
		}
	case "webhooks":
		v.Events = webhook.Events
	}
	v.HTML = s.renderMD(dropTitle(src))
	s.render(w, "docs.html", p)
}
