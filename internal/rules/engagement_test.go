package rules

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
)

// aiHit is a provider that finds the word "injection" in every text.
func aiHit(t *testing.T) *fakeAI {
	t.Helper()
	return &fakeAI{body: func(map[string]any) string {
		content, _ := json.Marshal(map[string]any{"violations": []map[string]string{{"quote": "injection", "message": "vague"}}})
		reply, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": string(content)}}}})
		return string(reply)
	}}
}

// An engagement that takes no AI gets no AI rule: the provider is not
// called, a reply kept from before the switch is not read, the rule is not
// one of the run's rules (no step, no notice) and the other rules run. A
// finding whose engagement is not known gets none either. The same finding
// in an engagement that takes AI is asked.
func TestNoAIRuleWhereAIIsOff(t *testing.T) {
	f := aiHit(t)
	r := aiRunner(t, "openai", f.server(t).URL)
	set := &Set{Rules: []Rule{
		{ID: "ai", Level: "warning", AI: "Be plain.", Target: "title"},
		{ID: "re", Level: "warning", RegexForbid: "SQL", Target: "title"},
	}}
	if err := set.Rules[1].prepare(); err != nil {
		t.Fatal(err)
	}
	fd := &finding.Finding{Meta: finding.Meta{ID: "F-001", Title: "SQL injection", Engagement: "acme"}}
	on := DocOf(fd)
	if vs := set.Run(context.Background(), on, config.Default(), All, r); len(vs) != 2 || f.hits.Load() != 1 {
		t.Fatalf("AI on: %+v, %d calls", vs, f.hits.Load())
	}
	fd.Meta.NoAI = true
	off := DocOf(fd)
	var steps []string
	vs := set.RunWith(context.Background(), off, config.Default(), All, r, Hooks{Start: func(r Rule) { steps = append(steps, r.ID) }})
	if len(vs) != 1 || vs[0].Rule != "re" {
		t.Fatalf("AI off: %+v", vs)
	}
	if f.hits.Load() != 1 {
		t.Fatalf("AI off: the provider was called (%d calls)", f.hits.Load())
	}
	if strings.Join(steps, ",") != "re" {
		t.Fatalf("AI off: steps %v", steps)
	}
	if got := set.RunsFor(off, All, r); len(got) != 1 || got[0].ID != "re" {
		t.Fatalf("AI off: the run's rules %+v", got)
	}
	// no engagement named: no AI either
	fd.Meta.Engagement, fd.Meta.NoAI = "", false
	if vs := set.Run(context.Background(), DocOf(fd), config.Default(), All, r); len(vs) != 1 || f.hits.Load() != 1 {
		t.Fatalf("no engagement: %+v, %d calls", vs, f.hits.Load())
	}
	if AIOff(fd) != AIOffWords {
		t.Fatalf("no engagement: %q", AIOff(fd))
	}
	// the same text in another engagement is asked (other text: not kept)
	other := &finding.Finding{Meta: finding.Meta{ID: "F-001", Title: "An injection of SQL", Engagement: "beta"}}
	if vs := set.Run(context.Background(), DocOf(other), config.Default(), All, r); len(vs) != 2 || f.hits.Load() != 2 {
		t.Fatalf("another engagement: %+v, %d calls", vs, f.hits.Load())
	}
	// the switch is not in what a script reads; the engagement is
	b, _ := json.Marshal(off)
	if s := string(b); !strings.Contains(s, `"engagement":"acme"`) || strings.Contains(strings.ToLower(s), "noai") {
		t.Fatalf("the Doc's JSON: %s", s)
	}
}

// The engine's steps of a check are the finding's own rules, and its bench
// run of an AI rule answers with words where the engagement takes no AI.
func TestEngineLeavesAIOutWhereItIsOff(t *testing.T) {
	f := aiHit(t)
	dir := writeRules(t, map[string]string{"r.yaml": "- id: ai\n  level: warning\n  target: title\n  ai: Be plain.\n- id: re\n  level: warning\n  target: title\n  regex_forbid: 'SQL'\n"})
	e := NewEngine(dir, config.Default())
	e.Runner = aiRunner(t, "openai", f.server(t).URL)
	fd := &finding.Finding{Meta: finding.Meta{ID: "F-001", Title: "SQL injection", Engagement: "acme", NoAI: true}}
	if got := e.CheckRulesFor(fd); len(got) != 1 || got[0].ID != "re" {
		t.Fatalf("steps where AI is off: %+v", got)
	}
	if vs := e.CheckWith(context.Background(), fd, Hooks{}); len(vs) != 1 || vs[0].Rule != "re" {
		t.Fatalf("check where AI is off: %+v", vs)
	}
	if vs := e.Lint(context.Background(), fd, All); len(vs) != 1 || vs[0].Rule != "re" {
		t.Fatalf("lint where AI is off: %+v", vs)
	}
	ai, _ := e.Rule("ai")
	vs := e.RunRule(context.Background(), ai, DocOf(fd))
	if len(vs) != 1 || vs[0].Target != "ai" || vs[0].Message != "AI is off for this engagement" {
		t.Fatalf("bench where AI is off: %+v", vs)
	}
	if f.hits.Load() != 0 {
		t.Fatalf("the provider was called %d times", f.hits.Load())
	}
	fd.Meta.NoAI = false
	if got := e.CheckRulesFor(fd); len(got) != 2 {
		t.Fatalf("steps where AI is on: %+v", got)
	}
	if vs := e.RunRule(context.Background(), ai, DocOf(fd)); len(vs) != 1 || vs[0].Target != "title" || f.hits.Load() != 1 {
		t.Fatalf("bench where AI is on: %+v, %d calls", vs, f.hits.Load())
	}
}

// A rule with engagements runs in those engagements only, is a step only
// there, and keeps the key through the editor's write and a pack.
func TestRuleLimitedToEngagements(t *testing.T) {
	const src = "- id: acme-only\n  target: title\n  regex_forbid: 'SQL'\n  engagements: [acme, acme-retest]\n- id: all\n  target: title\n  regex_forbid: 'injection'\n"
	s := Load(writeRules(t, map[string]string{"r.yaml": src}))
	if len(s.Problems) != 0 || len(s.Rules) != 2 {
		t.Fatalf("rules %+v, problems %+v", s.Rules, s.Problems)
	}
	ids := func(vs []Violation) string {
		var out []string
		for _, v := range vs {
			out = append(out, v.Rule)
		}
		return strings.Join(out, ",")
	}
	for eng, want := range map[string]string{"acme": "acme-only,all", "acme-retest": "acme-only,all", "beta": "all", "": "all"} {
		d := doc()
		d.Engagement = eng
		if got := ids(s.Run(context.Background(), d, config.Default(), Fast, nil)); got != want {
			t.Errorf("engagement %q: ran %q, want %q", eng, got, want)
		}
		if got := s.RunsFor(d, Fast, nil); len(got) != strings.Count(want, ",")+1 {
			t.Errorf("engagement %q: the run's rules %+v", eng, got)
		}
		if got := ids(s.RunSection(d, config.Default(), "Description", "SQL")); got != "" {
			t.Errorf("engagement %q: a title rule in a section: %q", eng, got)
		}
	}
	// the bench runs it on any finding, as it runs a rule that is off
	d := doc()
	d.Engagement = "beta"
	e := &Engine{Dir: s.Dir}
	if vs := e.RunRule(context.Background(), s.Rules[0], d); len(vs) != 1 {
		t.Fatalf("bench in another engagement: %+v", vs)
	}
	// a save, a toggle and an export write the key back
	b, err := SetRule([]byte(src), "acme-only", &s.Rules[0])
	if err != nil || !strings.Contains(string(b), "engagements: [acme, acme-retest]") {
		t.Fatalf("after a save:\n%s\n%v", b, err)
	}
	pack, err := Pack(s.Rules)
	if err != nil || strings.Count(string(pack), "engagements:") != 1 {
		t.Fatalf("pack:\n%s\n%v", pack, err)
	}
	back, err := ParsePack(pack)
	if err != nil || len(back[0].Engagements) != 2 || len(back[1].Engagements) != 0 {
		t.Fatalf("pack read back: %+v %v", back, err)
	}
	// a name that can be no engagement's does not load
	_, problems := Parse("r.yaml", []byte("- id: x\n  regex_forbid: 'a'\n  engagements: ['../acme']\n"))
	if len(problems) != 1 || !strings.Contains(problems[0].Message, "is not an engagement ID") {
		t.Fatalf("a bad engagement: %+v", problems)
	}
	// the key is not in a kept script result's key when it is not written
	plain, _ := json.Marshal(Rule{ID: "x", Script: "s.sh"})
	if strings.Contains(string(plain), "Engagements") {
		t.Fatalf("an unlimited rule's JSON: %s", plain)
	}
}
