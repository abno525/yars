// Package rules loads user-written style rules from .yars/rules/*.yaml and
// checks findings against them. Fast kinds (regex, built-in checks) are pure
// and cheap; slow kinds (scripts, AI) go through a SlowRunner.
package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"yars/internal/config"
	"yars/internal/finding"
)

// MaxPerRule caps violations reported by one rule on one finding.
const MaxPerRule = 20

const maxQuote = 80

// maxMessage caps a violation's message (a script's or a model's can be any
// length).
const maxMessage = 300

type Rule struct {
	ID              string `yaml:"id"`
	Level           string `yaml:"level"`
	Message         string `yaml:"message"`
	Target          string `yaml:"target"`
	RegexForbid     string `yaml:"regex_forbid"`
	RegexRequire    string `yaml:"regex_require"`
	Check           string `yaml:"check"`
	Script          string `yaml:"script"`
	AI              string `yaml:"ai"`
	RequireNonempty bool   `yaml:"require_nonempty"`
	Enabled         *bool  `yaml:"enabled"`
	File            string `yaml:"-"`
	re              *regexp.Regexp
}

type Violation struct {
	Rule    string `json:"rule"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Target  string `json:"target"`
	Quote   string `json:"quote,omitempty"`
	// Fail is set when the rule itself could not run (a script that
	// crashed, timed out or printed something that is not JSON): the reason,
	// "invalid output" for unparseable output.
	Fail string `json:"-"`
}

// InvalidOutput is the Fail reason of a script whose output is not JSON.
const InvalidOutput = "invalid output"

type Section struct {
	Name string `json:"name"`
	Body string `json:"body"`
}

// Doc is the JSON view of a finding given to rules, scripts and the AI.
type Doc struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Status      string            `json:"status"`
	Severity    string            `json:"severity"`
	CVSS        string            `json:"cvss"`
	CVSSReasons map[string]string `json:"cvss_reasons"`
	Details     map[string]string `json:"details"`
	Sections    []Section         `json:"sections"`
	Author      string            `json:"author"`
	Reviewers   []string          `json:"reviewers"`
	// RetestResult is fixed, partially_fixed, not_fixed or "" (not a retest
	// or not retested yet).
	RetestResult string `json:"retest_result"`
	// Attachments are the files of attachments/ the sections refer to, in
	// order of first use.
	Attachments []string `json:"attachments"`
}

// attachmentUse finds references to the finding's own attachments.
var attachmentUse = regexp.MustCompile(`attachments/([A-Za-z0-9][A-Za-z0-9._-]*)`)

func DocOf(f *finding.Finding) Doc {
	m := f.Meta
	d := Doc{ID: m.ID, Title: m.Title, Status: m.Status, Severity: m.Severity, CVSS: m.CVSS,
		CVSSReasons: m.CVSSReasons, Details: m.Details, Author: m.Author, Reviewers: m.Reviewers, Attachments: []string{}}
	if m.Retest != nil {
		d.RetestResult = m.Retest.Result
	}
	seen := map[string]bool{}
	for _, s := range f.Sections {
		d.Sections = append(d.Sections, Section{Name: s.Name, Body: strings.Trim(s.Body, "\n")})
		for _, sub := range attachmentUse.FindAllStringSubmatch(s.Body, -1) {
			if name := strings.TrimRight(sub[1], "."); !seen[name] {
				seen[name] = true
				d.Attachments = append(d.Attachments, name)
			}
		}
	}
	if d.CVSSReasons == nil {
		d.CVSSReasons = map[string]string{}
	}
	if d.Details == nil {
		d.Details = map[string]string{}
	}
	return d
}

type Kind int

const (
	Fast Kind = 1
	Slow Kind = 2
	All       = Fast | Slow
)

// SlowRunner evaluates script and AI rules.
type SlowRunner interface {
	Script(ctx context.Context, r Rule, d Doc) []Violation
	AI(ctx context.Context, r Rule, target, text string) []Violation
}

// Set is a loaded rule directory. Problems are load errors reported as
// error-level violations so a broken rule can't be silently ignored.
type Set struct {
	Dir      string
	Rules    []Rule
	Problems []Violation
}

var checks = map[string]bool{"table-cells-no-backticks": true, "cvss-explained": true, "not-empty": true}

// Load reads every *.yaml/*.yml file in dir. It never fails.
func Load(dir string) *Set {
	s := &Set{Dir: dir}
	names, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	more, _ := filepath.Glob(filepath.Join(dir, "*.yml"))
	names = append(names, more...)
	sort.Strings(names)
	seen := map[string]bool{}
	for _, path := range names {
		file := filepath.Base(path)
		b, err := os.ReadFile(path)
		if err != nil {
			s.Problems = append(s.Problems, fileProblem(file, "rules/"+file, err.Error()))
			continue
		}
		s.add(file, b, seen)
	}
	return s
}

// LoadFiles reads the rule files of a rules folder given by name and
// content (a git tree, say) as Load reads the folder; files other than
// *.yaml and *.yml are skipped.
func LoadFiles(dir string, files map[string][]byte) *Set {
	s := &Set{Dir: dir}
	var names []string
	for n := range files {
		if strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	seen := map[string]bool{}
	for _, n := range names {
		s.add(n, files[n], seen)
	}
	return s
}

// NewProblems lists the load problems of after that before did not have
// (by message): what a change of the rule files broke. Admin › Rules and
// a git push refuse a change that has any.
func NewProblems(before, after *Set) []Violation {
	had := map[string]bool{}
	for _, p := range before.Problems {
		had[p.Message] = true
	}
	var out []Violation
	for _, p := range after.Problems {
		if !had[p.Message] {
			out = append(out, p)
		}
	}
	return out
}

// Parse reads one rule file's content as Load would, without the
// directory: its rules and its problems.
func Parse(file string, b []byte) ([]Rule, []Violation) {
	s := &Set{}
	s.add(file, b, map[string]bool{})
	return s.Rules, s.Problems
}

func fileProblem(file, rule, msg string) Violation {
	return Violation{Rule: rule, Level: "error", Target: "rules", Message: "rule invalid (" + file + "): " + msg}
}

// add loads the rules of one file; seen holds the ids loaded so far.
func (s *Set) add(file string, b []byte, seen map[string]bool) {
	problem := func(rule, msg string) { s.Problems = append(s.Problems, fileProblem(file, rule, msg)) }
	var rs []Rule
	var raw []map[string]any
	if err := yaml.Unmarshal(b, &rs); err != nil {
		problem("rules/"+file, err.Error())
		return
	}
	yaml.Unmarshal(b, &raw)
	for i, r := range rs {
		r.File = file
		// a typo like "levle:" must not be silently ignored
		if i < len(raw) {
			if bad := unknownKeys(raw[i]); len(bad) > 0 {
				problem(r.ID, fmt.Sprintf("%s: unknown field(s) %s", r.ID, strings.Join(bad, ", ")))
				continue
			}
		}
		if err := r.prepare(); err != nil {
			problem(r.ID, err.Error())
			continue
		}
		if seen[r.ID] {
			problem(r.ID, "duplicate rule id "+r.ID)
			continue
		}
		seen[r.ID] = true
		s.Rules = append(s.Rules, r)
	}
}

var ruleKeys = map[string]bool{"id": true, "level": true, "message": true, "target": true, "regex_forbid": true,
	"regex_require": true, "check": true, "script": true, "ai": true, "require_nonempty": true, "enabled": true}

func unknownKeys(m map[string]any) []string {
	var bad []string
	for k := range m {
		if !ruleKeys[k] {
			bad = append(bad, k)
		}
	}
	sort.Strings(bad)
	return bad
}

func (r *Rule) prepare() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("rule without id")
	}
	if r.Level == "" {
		r.Level = "error"
	}
	if r.Level != "error" && r.Level != "warning" {
		return fmt.Errorf("%s: level %q must be error or warning", r.ID, r.Level)
	}
	kinds := 0
	for _, k := range []string{r.RegexForbid, r.RegexRequire, r.Check, r.Script, r.AI} {
		if k != "" {
			kinds++
		}
	}
	if kinds != 1 {
		return fmt.Errorf("%s: needs exactly one of regex_forbid, regex_require, check, script, ai", r.ID)
	}
	if r.Check != "" && !checks[r.Check] {
		return fmt.Errorf("%s: unknown check %q", r.ID, r.Check)
	}
	if p := r.RegexForbid + r.RegexRequire; p != "" {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("%s: %v", r.ID, err)
		}
		r.re = re
	}
	if r.Target == "" && r.Script == "" {
		r.Target = "text"
	}
	switch t := r.Target; {
	case t == "", t == "title", t == "sections", t == "details", t == "text":
	case strings.HasPrefix(t, "section:") && len(t) > len("section:"):
	case strings.HasPrefix(t, "details:") && len(t) > len("details:"):
	default:
		return fmt.Errorf("%s: unknown target %q (use title, text, sections, details, section:<Name> or details:<Row>)", r.ID, t)
	}
	return nil
}

func (r Rule) message() string {
	if r.Message != "" {
		return r.Message
	}
	return r.ID
}

type part struct {
	Target, Text string
	Kind         string // title | section | details
}

// parts resolves a target to the texts it covers, in document order.
func parts(d Doc, target string) []part {
	var out []part
	addSections := func(only string) {
		for _, s := range d.Sections {
			if only == "" || s.Name == only {
				out = append(out, part{"section:" + s.Name, s.Body, "section"})
			}
		}
	}
	addDetails := func(only string) {
		keys := make([]string, 0, len(d.Details))
		for k := range d.Details {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if only == "" || k == only {
				out = append(out, part{"details:" + k, d.Details[k], "details"})
			}
		}
	}
	switch {
	case target == "title":
		out = append(out, part{"title", d.Title, "title"})
	case target == "sections":
		addSections("")
	case target == "details":
		addDetails("")
	case strings.HasPrefix(target, "section:"):
		name := strings.TrimPrefix(target, "section:")
		addSections(name)
		if len(out) == 0 {
			out = append(out, part{target, "", "section"})
		}
	case strings.HasPrefix(target, "details:"):
		name := strings.TrimPrefix(target, "details:")
		addDetails(name)
		if len(out) == 0 {
			out = append(out, part{target, "", "details"})
		}
	default: // text
		out = append(out, part{"title", d.Title, "title"})
		addSections("")
		addDetails("")
	}
	return out
}

func quote(s string) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxQuote {
		return string([]rune(s)[:maxQuote]) + "…"
	}
	return s
}

func (r Rule) v(target, msg, q string) Violation {
	if utf8.RuneCountInString(msg) > maxMessage {
		msg = string([]rune(msg)[:maxMessage]) + "…"
	}
	return Violation{Rule: r.ID, Level: r.Level, Message: msg, Target: target, Quote: quote(q)}
}

// Run evaluates the set on d. slow may be nil (script/AI rules skipped).
func (s *Set) Run(ctx context.Context, d Doc, cfg config.Config, kinds Kind, slow SlowRunner) []Violation {
	return s.RunProgress(ctx, d, cfg, kinds, slow, nil)
}

// counts reports whether rule r runs for kinds (with slow rules only when
// a runner is given).
func (r Rule) counts(kinds Kind, slow SlowRunner) bool {
	if r.Enabled != nil && !*r.Enabled {
		return false
	}
	if r.re != nil || r.Check != "" {
		return kinds&Fast != 0
	}
	return kinds&Slow != 0 && slow != nil
}

// RunProgress is Run that tells progress (may be nil) how many of the rules
// that run are done: once before the first and after each one.
func (s *Set) RunProgress(ctx context.Context, d Doc, cfg config.Config, kinds Kind, slow SlowRunner, progress func(done, total int)) []Violation {
	return s.RunWith(ctx, d, cfg, kinds, slow, Hooks{Progress: progress})
}

// Hooks follow a run rule by rule. Every field may be nil or empty.
type Hooks struct {
	// Only runs this rule alone (no load problems are reported then).
	Only string
	// Progress tells how many rules are done: once before the first and
	// after each one.
	Progress func(done, total int)
	// Start is called before a rule runs, Done after it with what it found.
	Start func(r Rule)
	Done  func(r Rule, vs []Violation)
}

// Runs returns the rules a run of kinds runs, in order.
func (s *Set) Runs(kinds Kind, slow SlowRunner) []Rule {
	var out []Rule
	for _, r := range s.Rules {
		if r.counts(kinds, slow) {
			out = append(out, r)
		}
	}
	return out
}

// RunWith evaluates the set on d, telling h about each rule.
func (s *Set) RunWith(ctx context.Context, d Doc, cfg config.Config, kinds Kind, slow SlowRunner, h Hooks) []Violation {
	var out []Violation
	if h.Only == "" {
		out = append(out, s.Problems...)
	}
	seen := map[Violation]bool{}
	run := s.Runs(kinds, slow)
	if h.Only != "" {
		run = slices.DeleteFunc(run, func(r Rule) bool { return r.ID != h.Only })
	}
	total, done := len(run), 0
	progress := h.Progress
	if progress != nil {
		progress(0, total)
	}
	for _, r := range run {
		if h.Start != nil {
			h.Start(r)
		}
		start := len(out)
		var vs []Violation
		switch {
		case r.re != nil || r.Check != "":
			if kinds&Fast != 0 {
				vs = r.fast(d, cfg)
			}
		case r.Script != "":
			if kinds&Slow != 0 && slow != nil {
				vs = slow.Script(ctx, r, d)
			}
		case r.AI != "":
			if kinds&Slow != 0 && slow != nil {
			parts:
				for _, p := range parts(d, r.Target) {
					if strings.TrimSpace(p.Text) == "" {
						continue
					}
					got := slow.AI(ctx, r, p.Target, p.Text)
					vs = append(vs, got...)
					// provider down or not configured: don't repeat for every part
					for _, v := range got {
						if v.Target == "ai" {
							break parts
						}
					}
				}
			}
		}
		if len(vs) > MaxPerRule {
			vs = vs[:MaxPerRule]
		}
		for _, v := range vs {
			// AI rules run once per target part; collapse repeated notices
			// (e.g. "no AI provider configured") but keep regex repeats.
			if r.AI != "" {
				if seen[v] {
					continue
				}
				seen[v] = true
			}
			out = append(out, v)
		}
		if h.Done != nil {
			h.Done(r, out[start:])
		}
		if done++; progress != nil {
			progress(done, total)
		}
	}
	return out
}

func (r Rule) fast(d Doc, cfg config.Config) []Violation {
	var vs []Violation
	switch {
	case r.RegexForbid != "":
		for _, p := range parts(d, r.Target) {
			for _, m := range r.re.FindAllString(p.Text, MaxPerRule) {
				vs = append(vs, r.v(p.Target, r.message(), m))
			}
		}
	case r.RegexRequire != "":
		for _, p := range parts(d, r.Target) {
			if strings.TrimSpace(p.Text) == "" && !r.RequireNonempty {
				continue
			}
			if !r.re.MatchString(p.Text) {
				vs = append(vs, r.v(p.Target, r.message(), ""))
			}
		}
	default:
		vs = r.builtin(d, cfg)
	}
	return vs
}

// RunSection evaluates fast rules on a section body being edited and returns
// only the violations for that section (live editor hints).
func (s *Set) RunSection(d Doc, cfg config.Config, section, body string) []Violation {
	// the body as it is saved and as DocOf gives it to the panel's checks
	body = strings.Trim(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	d.Sections = append([]Section(nil), d.Sections...)
	found := false
	for i := range d.Sections {
		if d.Sections[i].Name == section {
			d.Sections[i].Body, found = body, true
		}
	}
	if !found {
		d.Sections = append(d.Sections, Section{Name: section, Body: body})
	}
	var out []Violation
	for _, v := range s.Run(context.Background(), d, cfg, Fast, nil) {
		if v.Target == "section:"+section {
			out = append(out, v)
		}
	}
	return out
}

// Errors returns the messages of error-level violations.
func Errors(vs []Violation) []string {
	var out []string
	for _, v := range vs {
		if v.Level == "error" {
			out = append(out, v.Message)
		}
	}
	return out
}
