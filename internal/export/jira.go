package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"

	"github.com/abno525/yars/internal/cvss"
	"github.com/abno525/yars/internal/finding"
)

func validJira(j *JiraConf) error {
	switch {
	case j == nil || j.BaseURL == "" || j.Project == "" || j.UserEnv == "" || j.TokenEnv == "":
		return errors.New("jira exporter needs jira: base_url, project, user_env and token_env")
	case !strings.HasPrefix(j.UserEnv, "JIRA_") || !strings.HasPrefix(j.TokenEnv, "JIRA_"):
		return errors.New("jira user_env/token_env must start with JIRA_ (other server secrets are off limits)")
	}
	for sev, p := range j.Priorities {
		if strings.ContainsFunc(sev+p, unicode.IsControl) || len(p) > 100 {
			return fmt.Errorf("jira priorities: the name for %q must be one line of at most 100 characters", sev)
		}
	}
	j.IssueType = issueType(j.IssueType)
	return nil
}

// issueType is a Jira destination's issue type: Bug when none is written.
func issueType(t string) string {
	if t == "" {
		return "Bug"
	}
	return t
}

// priorities maps severities to Jira's default priority names.
var priorities = map[string]string{"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}

// priority is the Jira priority a finding of that severity is sent with
// ("" = none).
func (j *JiraConf) priority(sev string) string {
	if p, ok := j.Priorities[sev]; ok {
		return p
	}
	return priorities[sev]
}

// jira sends one issue per finding and returns their addresses. A finding's
// issue is updated when it is known (Known) or found by its label;
// otherwise a new one is made with that label. A failure stops the run;
// issues sent before it are returned with the error.
func (r *Runner) jira(ctx context.Context, e Exporter, in Input) (Result, error) {
	j := e.Jira
	if err := validJira(j); err != nil {
		return Result{}, err
	}
	if err := httpsOnly(j.BaseURL, "jira"); err != nil {
		return Result{}, err
	}
	user, token, err := r.login(in, "jira", j.UserEnv, j.TokenEnv)
	if err != nil {
		return Result{}, err
	}
	base := strings.TrimRight(j.BaseURL, "/")
	res := Result{Pushed: true}
	for _, f := range in.ordered() {
		call := func(method, url string, body []byte) ([]byte, error) {
			return r.call(ctx, "jira "+f.Meta.ID, user, token, method, url, body)
		}
		label := jiraLabel(in.Engagement.ID, f.Meta.ID)
		fields := map[string]any{
			"summary":     f.Meta.ID + " " + f.Meta.Title,
			"description": jiraText(f, in),
		}
		if p := j.priority(cvss.Derive(f.Meta.CVSS, f.Meta.Severity)); p != "" {
			fields["priority"] = map[string]string{"name": p}
		}
		update, _ := json.Marshal(map[string]any{"fields": fields})
		// put updates an issue; false when it is gone
		put := func(key string) (bool, error) {
			_, err := call("PUT", base+"/rest/api/2/issue/"+url.PathEscape(key), update)
			if notFound(err) {
				return false, nil
			}
			return err == nil, err
		}
		key, action := "", ""
		if k := in.Known[f.Meta.ID]; k.ID != "" {
			ok, err := put(k.ID)
			if err != nil {
				return res, err
			}
			if ok {
				key, action = k.ID, "updated"
			}
		}
		if key == "" { // search by the label set at creation
			q := url.Values{"jql": {`project = "` + jqlQuote(j.Project) + `" AND labels = "` + label + `"`}, "fields": {"key"}, "maxResults": {"1"}}
			data, err := call("GET", base+"/rest/api/2/search?"+q.Encode(), nil)
			if err != nil {
				return res, err
			}
			var found struct{ Issues []struct{ Key string } }
			json.Unmarshal(data, &found)
			if len(found.Issues) > 0 && found.Issues[0].Key != "" {
				ok, err := put(found.Issues[0].Key)
				if err != nil {
					return res, err
				}
				if ok {
					key, action = found.Issues[0].Key, "updated"
				}
			}
		}
		if key == "" {
			fields["project"] = map[string]string{"key": j.Project}
			fields["issuetype"] = map[string]string{"name": j.IssueType}
			fields["labels"] = []string{label}
			body, _ := json.Marshal(map[string]any{"fields": fields})
			data, err := call("POST", base+"/rest/api/2/issue", body)
			if err != nil {
				return res, err
			}
			var out struct{ Key string }
			json.Unmarshal(data, &out)
			if out.Key == "" {
				return res, fmt.Errorf("jira %s: no issue key in the answer", f.Meta.ID)
			}
			key, action = out.Key, "created"
		}
		it := Item{ID: f.Meta.ID, URL: base + "/browse/" + key, Remote: Remote{ID: key}, Action: action}
		res.Items = append(res.Items, it)
		if res.URL == "" {
			res.URL = it.URL
		}
	}
	return res, nil
}

var labelUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// jiraLabel marks the issue of one finding of one engagement (Jira labels
// take no spaces).
func jiraLabel(eng, id string) string {
	return labelUnsafe.ReplaceAllString("yars-"+eng+"-"+id, "-")
}

func jqlQuote(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

// jiraText is a finding in Jira's wiki markup: the summary table, the
// CVSS explanations and every section. Every value and name is escaped as
// the sections' text is (jiraEsc): it is the team's text, sent with the
// author's or the server's key.
func jiraText(f *finding.Finding, in Input) string {
	var b strings.Builder
	cell := func(s string) string {
		s = strings.ReplaceAll(jiraEsc(strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")), "|", "\\|")
		if s == "" {
			return " " // "||" would start a header cell
		}
		return s
	}
	for _, r := range summary(f, in.Cfg) {
		fmt.Fprintf(&b, "||%s|%s|\n", cell(r.Label), cell(r.Value))
	}
	if rs := reasons(f, in.Cfg); len(rs) > 0 {
		b.WriteString("\nh2. CVSS explanation\n\n||Metric||Value||Explanation||\n")
		for _, r := range rs {
			fmt.Fprintf(&b, "|%s|%s|%s|\n", cell(r[0]), cell(r[1]), cell(r[2]))
		}
	}
	for _, s := range sectionsOf(f, in) {
		body := strings.Trim(s.Body, "\n")
		if strings.TrimSpace(body) == "" {
			continue
		}
		fmt.Fprintf(&b, "\nh2. %s\n\n%s\n", jiraEsc(s.Name), mdToJira(body))
	}
	return b.String()
}

var (
	mdHeading = regexp.MustCompile(`^(#{1,6})\s+(.*)$`)
	mdBullet  = regexp.MustCompile(`^(\s*)[-*+]\s+(.*)$`)
	mdNumber  = regexp.MustCompile(`^(\s*)\d+[.)]\s+(.*)$`)
	mdImage   = regexp.MustCompile(`!\[([^\]]*)\]\([^)]*\)`)
	mdLink    = regexp.MustCompile(`\[([^\]]+)\]\(([^)\s]+)\)`)
	mdBold    = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	mdCode    = regexp.MustCompile("`([^`]+)`")
)

// zwsp is a zero-width space: it parts two characters Jira would read
// together, and shows as nothing.
const zwsp = string(rune(0x200b))

// jiraBraces escapes the braces of text: Jira reads {name} as a macro
// ({color}, {panel}, {html} where the instance allows it). A backslash that
// stands before a brace is parted from the escape, or the two backslashes
// would read as a line break and leave the brace as it was.
var jiraBraces = strings.NewReplacer(`\{`, `\`+zwsp+`\{`, `\}`, `\`+zwsp+`\}`, "{", `\{`, "}", `\}`)

// jiraEsc is s with no brace Jira reads as a macro's.
func jiraEsc(s string) string { return jiraBraces.Replace(s) }

// jiraInline is one line (or table cell) of Markdown text in Jira's markup:
// braces escaped first, also inside inline code, then links, bold and
// inline code. Images are not uploaded; their text stays.
func jiraInline(s string) string {
	s = jiraEsc(s)
	s = mdImage.ReplaceAllString(s, "[image: $1]")
	s = mdLink.ReplaceAllString(s, "[$1|$2]")
	s = mdBold.ReplaceAllString(s, "*$1*")
	return mdCode.ReplaceAllString(s, "{{$1}}")
}

// jiraLangs maps the first word after a code fence to the language Jira's
// {code} macro knows it as. A word that is not here names no language: Jira
// shows an error for one it does not know, and the word is the writer's.
var jiraLangs = map[string]string{
	"java": "java", "javascript": "javascript", "js": "javascript", "json": "json", "xml": "xml", "html": "html",
	"sql": "sql", "python": "python", "py": "python", "bash": "bash", "sh": "bash", "shell": "bash",
	"go": "go", "golang": "go", "c": "c", "c++": "c++", "cpp": "c++", "c#": "c#", "cs": "c#", "csharp": "c#",
	"css": "css", "php": "php", "ruby": "ruby", "rb": "ruby", "perl": "perl", "pl": "perl", "yaml": "yaml", "yml": "yaml",
}

var noformatToken = regexp.MustCompile(`(?i)\{(noformat)`)

// jiraBlock is a fenced code block in Jira's markup. Nothing is escaped
// inside {code}, and a line {code} there would end the block and leave the
// rest as live markup: such a block is written as {noformat}, and when it
// holds that word too, its {noformat is parted by a zero-width space.
func jiraBlock(info string, body []string) []string {
	open, end := "{code}", "{code}"
	if w := strings.Fields(strings.ToLower(info)); len(w) > 0 && jiraLangs[w[0]] != "" {
		open = "{code:" + jiraLangs[w[0]] + "}"
	}
	if text := strings.ToLower(strings.Join(body, "\n")); strings.Contains(text, "{code") {
		open, end = "{noformat}", "{noformat}"
		if strings.Contains(text, "{noformat") {
			body = slices.Clone(body)
			for i, l := range body {
				body[i] = noformatToken.ReplaceAllString(l, "{"+zwsp+"$1")
			}
		}
	}
	return append(append([]string{open}, body...), end)
}

// fence reads a line that opens or closes a fenced code block: its
// character, how many of them, and what follows them.
func fence(line string) (c byte, n int, info string, ok bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "```") && !strings.HasPrefix(t, "~~~") {
		return 0, 0, "", false
	}
	c = t[0]
	for n < len(t) && t[n] == c {
		n++
	}
	return c, n, strings.TrimSpace(t[n:]), true
}

// jiraTableMD reads tables as the pages' renderer does (GFM tables).
var jiraTableMD = goldmark.New(goldmark.WithExtensions(extension.Table))

// jiraTable is a Markdown table in Jira's markup: its rows, and where the
// table's last line ends in the source.
type jiraTable struct {
	rows []string
	end  int
}

// jiraTables finds the tables of md as the renderer reads them (none in a
// code block), by the offset of the line each starts on. The line of dashes
// under the header is no row.
func jiraTables(md string) map[int]jiraTable {
	if !strings.Contains(md, "|") {
		return nil
	}
	src := []byte(md)
	lineEnd := func(at int) int {
		if i := bytes.IndexByte(src[min(at, len(src)):], '\n'); i >= 0 {
			return at + i
		}
		return len(src)
	}
	out := map[int]jiraTable{}
	ast.Walk(jiraTableMD.Parser().Parse(text.NewReader(src)), func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering || n.Kind() != east.KindTable {
			return ast.WalkContinue, nil
		}
		tb, start := jiraTable{}, -1
		for row := n.FirstChild(); row != nil; row = row.NextSibling() {
			sep, at := "|", -1
			if row.Kind() == east.KindTableHeader {
				sep = "||"
			}
			line := sep
			for c := row.FirstChild(); c != nil; c = c.NextSibling() {
				cell := " " // an empty cell: "||" would start a header cell
				if c.Lines().Len() > 0 {
					seg := c.Lines().At(0)
					if at < 0 {
						at = seg.Start
					}
					if s := strings.TrimSpace(string(seg.Value(src))); s != "" {
						cell = jiraInline(s)
					}
				}
				line += cell + sep
			}
			if at < 0 {
				return ast.WalkSkipChildren, nil // a row without a place: the table stays as written
			}
			if start < 0 {
				start = bytes.LastIndexByte(src[:at], '\n') + 1
				tb.end = lineEnd(lineEnd(start) + 1) // the line of dashes
			}
			tb.end = max(tb.end, lineEnd(at))
			tb.rows = append(tb.rows, line)
		}
		if start >= 0 {
			out[start] = tb
		}
		return ast.WalkSkipChildren, nil
	})
	return out
}

// mdToJira turns finding Markdown into Jira wiki markup, plain enough:
// code blocks, tables, headings, lists, links, bold and inline code. What
// the finding says is text there, never markup of Jira's own: braces are
// escaped outside code blocks, and a code block cannot end itself
// (jiraBlock).
func mdToJira(md string) string {
	var out, block []string
	tables := jiraTables(md)
	var open byte // the fence character of the code block the line is in, or 0
	openLen, info, off, skip := 0, "", 0, 0
	for _, line := range strings.Split(md, "\n") {
		at := off
		off += len(line) + 1
		if c, n, rest, ok := fence(line); ok && open == 0 {
			open, openLen, info, block = c, n, rest, nil
			continue
		} else if ok && c == open && n >= openLen && rest == "" {
			out = append(out, jiraBlock(info, block)...)
			open = 0
			continue
		}
		if open != 0 {
			block = append(block, line)
			continue
		}
		if at < skip {
			continue // a line of a table already written
		}
		if tb, ok := tables[at]; ok {
			out = append(out, tb.rows...)
			skip = tb.end
			continue
		}
		prefix := ""
		switch {
		case mdHeading.MatchString(line):
			m := mdHeading.FindStringSubmatch(line)
			prefix, line = fmt.Sprintf("h%d. ", max(len(m[1]), 3)), m[2] // below the section's h2
		case mdBullet.MatchString(line):
			m := mdBullet.FindStringSubmatch(line)
			prefix, line = strings.Repeat("*", len(m[1])/2+1)+" ", m[2]
		case mdNumber.MatchString(line):
			m := mdNumber.FindStringSubmatch(line)
			prefix, line = strings.Repeat("#", len(m[1])/2+1)+" ", m[2]
		}
		out = append(out, prefix+jiraInline(line))
	}
	if open != 0 {
		out = append(out, jiraBlock(info, block)...)
	}
	return strings.Join(out, "\n")
}
