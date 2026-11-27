package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
)

// shownAndMore splits what a rule reported into its rows and the row that
// counts the ones not shown (nil when there is none); two such rows fail.
func shownAndMore(t *testing.T, vs []Violation) (rows []Violation, more *Violation) {
	t.Helper()
	for i, v := range vs {
		if _, ok := More(v); !ok {
			rows = append(rows, v)
			continue
		}
		if more != nil {
			t.Fatalf("two rows count the rest: %+v", vs)
		}
		if i != len(vs)-1 {
			t.Fatalf("the row that counts the rest is not last: %+v", vs)
		}
		more = &vs[i]
	}
	return rows, more
}

// A pattern rule that finds more than MaxPerRule places says how many it
// does not show, in one last row, counted over every part of the finding.
func TestPatternRuleCountsTheRest(t *testing.T) {
	const rule = "- id: any\n  level: warning\n  target: sections\n  regex_forbid: 'x\\d*'\n"
	// words is x0 x1 … : n matches, each with its own quote
	words := func(n int) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, "x%d ", i)
		}
		return b.String()
	}
	d := doc()
	for _, c := range []struct {
		name     string
		sections []Section
		rows     int
		more     int
		message  string
	}{
		{"25 in one section", []Section{{"Description", words(25)}}, 20, 5, "and 5 more"},
		{"15 and 15 in two sections", []Section{{"Description", words(15)}, {"Impact", words(15)}}, 20, 10, "and 10 more"},
		{"exactly 20", []Section{{"Description", words(20)}}, 20, 0, ""},
		{"past the count's limit", []Section{{"Description", words(1500)}}, 20, MaxCounted + 1, "and more than 1000 more"},
		// one wording in one place is one row of the checks table, however
		// often it is there
		{"the same word 500 times", []Section{{"Description", strings.Repeat("x ", 500)}}, 20, 0, ""},
		{"22 words, then one of them again", []Section{{"Description", words(22) + "x21 x20 "}}, 20, 2, "and 2 more"},
	} {
		d.Sections = c.sections
		rows, more := shownAndMore(t, run(t, rule, d))
		if len(rows) != c.rows {
			t.Errorf("%s: %d rows", c.name, len(rows))
		}
		if c.more == 0 {
			if more != nil {
				t.Errorf("%s: an extra row %+v", c.name, *more)
			}
			continue
		}
		if more == nil {
			t.Errorf("%s: no row counts the rest", c.name)
			continue
		}
		if n, _ := More(*more); n != c.more || more.Message != c.message || more.Rule != "any" || more.Level != "warning" || more.Quote != "" {
			t.Errorf("%s: %+v", c.name, *more)
		}
	}
	// the count is part of the row's place: a dismissal of "and 5 more" is
	// not one of "and 6 more"
	d.Sections = []Section{{"Description", words(25)}}
	_, five := shownAndMore(t, run(t, rule, d))
	d.Sections = []Section{{"Description", words(26)}}
	_, six := shownAndMore(t, run(t, rule, d))
	if five == nil || six == nil || five.Target == six.Target {
		t.Fatalf("places %+v %+v", five, six)
	}
}

// A built-in check is cut the same way.
func TestBuiltinCheckCountsTheRest(t *testing.T) {
	d := doc()
	d.Details = map[string]string{}
	var b strings.Builder
	b.WriteString("| Field | Value |\n|---|---|\n")
	for i := range 23 {
		fmt.Fprintf(&b, "| P%d | `v%d` |\n", i, i)
	}
	d.Sections = []Section{{"Description", b.String()}}
	rows, more := shownAndMore(t, run(t, "- id: tc\n  check: table-cells-no-backticks\n", d))
	if len(rows) != MaxPerRule || more == nil || more.Message != "and 3 more" || more.Level != "error" {
		t.Fatalf("%d rows, more %+v", len(rows), more)
	}
}

// A script that prints more than MaxPerRule results: the rest is counted,
// also when the result comes back from the store.
func TestScriptRuleCountsTheRest(t *testing.T) {
	dir := t.TempDir()
	var res []map[string]string
	for i := range 25 {
		res = append(res, map[string]string{"message": "bad", "quote": fmt.Sprint("q", i), "target": "title"})
	}
	// a script cannot write the counting row itself
	res = append(res, map[string]string{"message": "and 900 more", "target": "more:900"})
	out, _ := json.Marshal(res)
	runs := counting(t, dir, "c.sh", string(out))
	store := newMemResults()
	s := &Set{Rules: []Rule{{ID: "s", Level: "warning", Script: "c.sh"}}}
	for i := range 2 {
		r := NewRunner(dir, config.AIConfig{})
		r.Results = store
		rows, more := shownAndMore(t, s.Run(context.Background(), doc(), config.Default(), All, r))
		if len(rows) != MaxPerRule || more == nil || more.Message != "and 6 more" || more.Level != "warning" {
			t.Fatalf("run %d: %d rows, more %+v", i, len(rows), more)
		}
	}
	if runs() != 1 {
		t.Fatalf("runs %d", runs())
	}
}

// An AI rule runs once per part: the rest is the sum over the parts, also
// from the store.
func TestAIRuleCountsTheRest(t *testing.T) {
	type hit struct {
		Quote   string `json:"quote"`
		Message string `json:"message"`
	}
	f := &fakeAI{body: func(map[string]any) string {
		var hits []hit
		for i := range 25 {
			hits = append(hits, hit{fmt.Sprint("q", i), "vague"})
		}
		content, _ := json.Marshal(map[string]any{"violations": hits})
		reply, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": string(content)}}}})
		return string(reply)
	}}
	srv := f.server(t)
	store := newMemResults()
	d := doc()
	d.Sections = []Section{{"Description", "one"}, {"Impact", "two"}}
	s := &Set{Rules: []Rule{{ID: "acr", Level: "warning", AI: "x", Target: "sections"}}}
	for i := range 2 {
		r := aiRunner(t, "openai", srv.URL)
		r.Results = store
		rows, more := shownAndMore(t, s.Run(context.Background(), d, config.Default(), All, r))
		// 25 of each part: 20 shown, 5 and 25 not
		if len(rows) != MaxPerRule || more == nil || more.Message != "and 30 more" {
			t.Fatalf("run %d: %d rows, more %+v", i, len(rows), more)
		}
	}
	if f.hits.Load() != 2 {
		t.Fatalf("calls %d", f.hits.Load())
	}
}
