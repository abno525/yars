package export

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"yars/internal/cvss"
	"yars/internal/finding"
)

func validJira(j *JiraConf) error {
	switch {
	case j == nil || j.BaseURL == "" || j.Project == "" || j.UserEnv == "" || j.TokenEnv == "":
		return errors.New("jira exporter needs jira: base_url, project, user_env and token_env")
	case !strings.HasPrefix(j.UserEnv, "JIRA_") || !strings.HasPrefix(j.TokenEnv, "JIRA_"):
		return errors.New("jira user_env/token_env must start with JIRA_ (other server secrets are off limits)")
	}
	if j.IssueType == "" {
		j.IssueType = "Bug"
	}
	return nil
}

// priorities maps severities to Jira's default priority names.
var priorities = map[string]string{"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}

// jira creates one issue per finding (POST /rest/api/2/issue) and returns
// their addresses. A failure stops the run; issues made before it are
// returned with the error.
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
		fields := map[string]any{
			"project":     map[string]string{"key": j.Project},
			"summary":     f.Meta.ID + " " + f.Meta.Title,
			"description": jiraText(f, in),
			"issuetype":   map[string]string{"name": j.IssueType},
		}
		if p := priorities[cvss.Derive(f.Meta.CVSS, f.Meta.Severity)]; p != "" {
			fields["priority"] = map[string]string{"name": p}
		}
		body, _ := json.Marshal(map[string]any{"fields": fields})
		data, err := r.call(ctx, "jira "+f.Meta.ID, user, token, "POST", base+"/rest/api/2/issue", body)
		if err != nil {
			return res, err
		}
		var out struct{ Key string }
		json.Unmarshal(data, &out)
		if out.Key == "" {
			return res, fmt.Errorf("jira %s: no issue key in the answer", f.Meta.ID)
		}
		it := Item{ID: f.Meta.ID, URL: base + "/browse/" + out.Key}
		res.Items = append(res.Items, it)
		if res.URL == "" {
			res.URL = it.URL
		}
	}
	return res, nil
}

// jiraText is a finding in Jira's wiki markup: the summary table, the
// CVSS explanations and every section.
func jiraText(f *finding.Finding, in Input) string {
	var b strings.Builder
	cell := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(s), "\n", " "), "|", "\\|")
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
	for _, s := range f.Sections {
		body := strings.Trim(s.Body, "\n")
		if strings.TrimSpace(body) == "" {
			continue
		}
		fmt.Fprintf(&b, "\nh2. %s\n\n%s\n", s.Name, mdToJira(body))
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

// mdToJira turns finding Markdown into Jira wiki markup, plain enough:
// code blocks, headings, lists, links, bold and inline code. Images are not
// uploaded; their text stays.
func mdToJira(md string) string {
	var out []string
	inCode := false
	for _, line := range strings.Split(md, "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			if inCode {
				out = append(out, "{code}")
			} else if lang := strings.Trim(t, "`~ "); lang != "" {
				out = append(out, "{code:"+lang+"}")
			} else {
				out = append(out, "{code}")
			}
			inCode = !inCode
			continue
		}
		if inCode {
			out = append(out, line)
			continue
		}
		switch {
		case mdHeading.MatchString(line):
			m := mdHeading.FindStringSubmatch(line)
			line = fmt.Sprintf("h%d. %s", len(m[1]), m[2])
		case mdBullet.MatchString(line):
			m := mdBullet.FindStringSubmatch(line)
			line = strings.Repeat("*", len(m[1])/2+1) + " " + m[2]
		case mdNumber.MatchString(line):
			m := mdNumber.FindStringSubmatch(line)
			line = strings.Repeat("#", len(m[1])/2+1) + " " + m[2]
		}
		line = mdImage.ReplaceAllString(line, "[image: $1]")
		line = mdLink.ReplaceAllString(line, "[$1|$2]")
		line = mdBold.ReplaceAllString(line, "*$1*")
		line = mdCode.ReplaceAllString(line, "{{$1}}")
		out = append(out, line)
	}
	if inCode {
		out = append(out, "{code}")
	}
	return strings.Join(out, "\n")
}
