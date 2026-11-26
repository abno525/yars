package export

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

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
	if j.IssueType == "" {
		j.IssueType = "Bug"
	}
	return nil
}

// priorities maps severities to Jira's default priority names.
var priorities = map[string]string{"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}

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
		if p := priorities[cvss.Derive(f.Meta.CVSS, f.Meta.Severity)]; p != "" {
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
			line = fmt.Sprintf("h%d. %s", max(len(m[1]), 3), m[2]) // below the section's h2
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
