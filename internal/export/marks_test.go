package export

import "testing"

// Q7: a destination that makes a file does not mark findings reported
// unless its file says so; one that publishes to a service does unless its
// file says not to. A written mark_reported wins for every type.
func TestMarksDefaultFollowsTheType(t *testing.T) {
	const (
		pandoc   = "type: pandoc\nformat: docx\n"
		script   = "type: script\nscript: s.sh\nextension: txt\n"
		conf     = "type: confluence\n"
		confREST = "type: confluence\nconfluence:\n  base_url: https://c.example.com/wiki\n  space: SEC\n  user_env: CONFLUENCE_USER\n  token_env: CONFLUENCE_TOKEN\n"
		jira     = "type: jira\njira:\n  base_url: https://j.example.com\n  project: SEC\n  user_env: JIRA_USER\n  token_env: JIRA_TOKEN\n"
	)
	for name, c := range map[string]struct {
		yaml string
		want bool
	}{
		"pandoc":                   {pandoc, false},
		"script":                   {script, false},
		"confluence file":          {conf, false},
		"confluence push":          {confREST, true},
		"jira":                     {jira, true},
		"pandoc, true":             {pandoc + "mark_reported: true\n", true},
		"script, true":             {script + "mark_reported: true\n", true},
		"confluence file, true":    {conf + "mark_reported: true\n", true},
		"pandoc, false":            {pandoc + "mark_reported: false\n", false},
		"confluence push, false":   {confREST + "mark_reported: false\n", false},
		"jira, false":              {jira + "mark_reported: false\n", false},
		"jira, true":               {jira + "mark_reported: true\n", true},
		"confluence block, no url": {conf + "confluence:\n  space: SEC\n", false},
	} {
		e, err := Parse("d.yaml", []byte(c.yaml))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if e.Marks() != c.want {
			t.Errorf("%s: Marks() = %v, want %v", name, e.Marks(), c.want)
		}
	}
}
