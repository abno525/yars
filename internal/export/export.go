// Package export turns an engagement's findings into client deliverables
// through pluggable exporters configured in .yars/exporters/*.yaml: pandoc
// (docx, pdf, html, odt, …), Confluence (HTML download or REST push) and
// scripts.
package export

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"yars/internal/config"
	"yars/internal/cvss"
	"yars/internal/finding"
	"yars/internal/store"
	"yars/internal/workflow"
)

type ConfluenceConf struct {
	BaseURL  string `yaml:"base_url,omitempty"`
	Space    string `yaml:"space,omitempty"`
	ParentID string `yaml:"parent_id,omitempty"`
	UserEnv  string `yaml:"user_env,omitempty"`
	TokenEnv string `yaml:"token_env,omitempty"`
}

// JiraConf is a Jira project that gets one issue per finding.
type JiraConf struct {
	BaseURL   string `yaml:"base_url,omitempty"`
	Project   string `yaml:"project,omitempty"`
	IssueType string `yaml:"issue_type,omitempty"`
	UserEnv   string `yaml:"user_env,omitempty"`
	TokenEnv  string `yaml:"token_env,omitempty"`
}

type Exporter struct {
	ID           string          `yaml:"-"`
	Name         string          `yaml:"name"`
	Type         string          `yaml:"type"`
	Format       string          `yaml:"format,omitempty"`
	Template     string          `yaml:"template,omitempty"`
	Args         []string        `yaml:"args,omitempty"`
	Script       string          `yaml:"script,omitempty"`
	Extension    string          `yaml:"extension,omitempty"`
	Statuses     []string        `yaml:"statuses,omitempty"`
	MarkReported *bool           `yaml:"mark_reported,omitempty"`
	Confluence   *ConfluenceConf `yaml:"confluence,omitempty"`
	Jira         *JiraConf       `yaml:"jira,omitempty"`
}

// Marks reports whether a successful export should mark findings reported.
func (e Exporter) Marks() bool { return e.MarkReported == nil || *e.MarkReported }

// Service reports a destination that publishes to an outside service
// (Confluence REST, Jira) with a key, instead of producing a file.
func (e Exporter) Service() bool {
	return e.Type == "jira" || (e.Type == "confluence" && e.Confluence != nil && e.Confluence.BaseURL != "")
}

// ServiceName is the outside service a destination publishes to
// ("confluence", "jira"; "" for files): the name of personal keys.
func (e Exporter) ServiceName() string {
	if !e.Service() {
		return ""
	}
	return e.Type
}

// TokenEnv is the server's environment variable with the service key.
func (e Exporter) TokenEnv() string {
	switch {
	case e.Type == "jira" && e.Jira != nil:
		return e.Jira.TokenEnv
	case e.Confluence != nil:
		return e.Confluence.TokenEnv
	}
	return ""
}

// Host is the service's host name ("" for files).
func (e Exporter) Host() string {
	base := ""
	switch {
	case e.Type == "jira" && e.Jira != nil:
		base = e.Jira.BaseURL
	case e.Confluence != nil:
		base = e.Confluence.BaseURL
	}
	if u, err := url.Parse(base); err == nil {
		return u.Host
	}
	return ""
}

// Load reads every exporter in dir; invalid files are returned as errors.
func Load(dir string) ([]Exporter, []error) {
	names, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	sort.Strings(names)
	var out []Exporter
	var errs []error
	for _, p := range names {
		file := filepath.Base(p)
		b, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", file, err))
			continue
		}
		var e Exporter
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&e); err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", file, err))
			continue
		}
		e.ID = strings.TrimSuffix(file, ".yaml")
		if e.Name == "" {
			e.Name = e.ID
		}
		// withdrawn findings are never exported
		e.Statuses = slices.DeleteFunc(e.Statuses, func(s string) bool { return !workflow.Active(s) })
		if len(e.Statuses) == 0 {
			e.Statuses = []string{"complete"}
		}
		switch {
		case e.Type == "pandoc" && !safeWord.MatchString(e.Format):
			err = errors.New("pandoc exporter needs a format like docx, pdf or html")
		case e.Type == "script" && (e.Script == "" || !safeWord.MatchString(e.Extension)):
			err = errors.New("script exporter needs script and a plain extension (letters/digits)")
		case e.Type == "jira":
			err = validJira(e.Jira)
		case e.Type != "pandoc" && e.Type != "script" && e.Type != "confluence":
			err = fmt.Errorf("unknown type %q (pandoc, confluence, jira or script)", e.Type)
		default:
			err = validateArgs(e.Args)
		}
		if err == nil && e.Confluence != nil && e.Confluence.BaseURL != "" {
			c := e.Confluence
			switch {
			case c.Space == "" || c.UserEnv == "" || c.TokenEnv == "":
				err = errors.New("confluence push needs space, user_env and token_env")
			case !strings.HasPrefix(c.UserEnv, "CONFLUENCE_") || !strings.HasPrefix(c.TokenEnv, "CONFLUENCE_"):
				err = errors.New("confluence user_env/token_env must start with CONFLUENCE_ (other server secrets are off limits)")
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", file, err))
			continue
		}
		out = append(out, e)
	}
	return out, errs
}

var safeWord = regexp.MustCompile(`^[a-z0-9_]+$`)

// pandoc args are limited to presentation options: nothing that reads or
// writes files, runs filters or changes the output path.
var plainArgs = map[string]bool{"--toc": true, "--table-of-contents": true, "--number-sections": true, "-N": true,
	"--no-highlight": true, "--section-divs": true, "--standalone": true}
var valueArgs = []string{"--toc-depth=", "--shift-heading-level-by=", "--highlight-style=", "--pdf-engine=", "--variable=",
	"--metadata=", "--columns=", "--dpi=", "--wrap=", "--top-level-division=", "--number-offset="}

func validateArgs(args []string) error {
	for _, a := range args {
		if plainArgs[a] {
			continue
		}
		ok := false
		for _, p := range valueArgs {
			if v, found := strings.CutPrefix(a, p); found {
				pathy := p == "--highlight-style=" || p == "--pdf-engine="
				ok = !(pathy && strings.ContainsAny(v, `/\`))
			}
		}
		if !ok {
			return fmt.Errorf("pandoc argument %q is not allowed (presentation options only, e.g. --toc, --toc-depth=2, --number-sections, --variable=k:v)", a)
		}
	}
	return nil
}

type Input struct {
	Engagement store.Engagement
	Findings   []*finding.Finding
	Cfg        config.Config
	// Attachment reads "attachments/<file>" of a finding (nil: images are
	// dropped). Only these files are ever embedded into a report.
	Attachment func(f *finding.Finding, rel string) ([]byte, bool)
	// Creds is the sender's own key for a service destination; nil uses the
	// server's key from the environment.
	Creds *Creds
	// Known is the page or issue each finding (by ID) became at this
	// destination before; it is updated instead of making another.
	Known map[string]Remote
	// imageSrc, when set, replaces inlining: it stores an attachment and
	// returns the src to use (the HTML ZIP).
	imageSrc func(f *finding.Finding, rel, ct string, data []byte) string
	// strictImages keeps only pictures that decode (PNG, JPEG, GIF): a PDF
	// fails on a broken one.
	strictImages bool
}

// Creds is a login for an outside service.
type Creds struct{ User, Token string }

// ordered returns findings by severity (config order), then ID.
// Ordered is the findings in report order (the preview's contents).
func (in Input) Ordered() []*finding.Finding { return in.ordered() }

func (in Input) ordered() []*finding.Finding {
	fs := slices.Clone(in.Findings)
	rank := func(f *finding.Finding) int {
		s := cvss.Derive(f.Meta.CVSS, f.Meta.Severity)
		if i := slices.Index(in.Cfg.Severities, s); i >= 0 {
			return i
		}
		return len(in.Cfg.Severities)
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if ri, rj := rank(fs[i]), rank(fs[j]); ri != rj {
			return ri < rj
		}
		return fs[i].Meta.ID < fs[j].Meta.ID
	})
	return fs
}

func (in Input) subtitle() string {
	e := in.Engagement
	parts := []string{}
	if e.Client != "" {
		parts = append(parts, e.Client)
	}
	if e.Start != "" || e.End != "" {
		parts = append(parts, strings.Trim(e.Start+" – "+e.End, " –"))
	}
	return strings.Join(parts, " · ")
}

// row is one line of a finding's summary table.
type row struct{ Label, Value string }

// summary is the table shown under each finding heading.
func summary(f *finding.Finding, cfg config.Config) []row {
	m := f.Meta
	rows := []row{{"Severity", cvss.Derive(m.CVSS, m.Severity)}}
	if v, err := cvss.Parse(m.CVSS); err == nil {
		sc, _ := cvss.Score(v)
		rows = append(rows, row{"CVSS", cvss.FormatScore(sc) + " (" + v.String() + ")"})
	}
	if m.Retest != nil {
		res := workflow.RetestLabel(m.Retest.Result)
		if res == "" {
			res = "not retested"
		}
		rows = append(rows, row{"Retest result", res})
	}
	for _, name := range cfg.DetailsRows {
		if v := strings.TrimSpace(m.Details[name]); v != "" {
			rows = append(rows, row{name, v})
		}
	}
	return rows
}

// reasons lists non-standard CVSS metrics with their explanations.
func reasons(f *finding.Finding, cfg config.Config) [][3]string {
	v, err := cvss.Parse(f.Meta.CVSS)
	if err != nil {
		return nil
	}
	var out [][3]string
	for _, mt := range cvss.Metrics {
		if cfg.NonStandard(mt.Key, v[mt.Key]) {
			out = append(out, [3]string{mt.Name, cvss.ValueName(mt.Key, v[mt.Key]), f.Meta.CVSSReasons[mt.Key]})
		}
	}
	return out
}

type Result struct {
	Filename, ContentType string
	Data                  []byte
	Pushed                bool   // published remotely (Confluence, Jira) instead of a file
	URL                   string // a push: the (first) page or issue
	Items                 []Item // a push: what each finding became
}

// Item is one finding's page or issue. Action is "created" or "updated".
type Item struct {
	ID, URL string
	Remote  Remote
	Action  string
}

// Remote is a page or issue at a service: the Jira issue key or the
// Confluence page id with its version.
type Remote struct {
	ID      string
	Version int
}

// Target is where a service destination publishes: its address and
// project or space ("" for files). A remembered page or issue only counts
// for the same target.
func (e Exporter) Target() string {
	switch {
	case e.Type == "jira" && e.Jira != nil:
		return strings.TrimRight(e.Jira.BaseURL, "/") + " " + e.Jira.Project
	case e.Service():
		return strings.TrimRight(e.Confluence.BaseURL, "/") + " " + e.Confluence.Space
	}
	return ""
}

// Runner executes exporters. Dir is .yars/exporters.
type Runner struct {
	Dir        string
	PandocPath string
	HTTP       httpDoer
	Getenv     func(string) string
	Timeout    time.Duration
	// PDFTimeout limits one PDF (default 60 s); at most pdfWorkers render
	// at once, the others wait.
	PDFTimeout time.Duration

	pdfOnce  sync.Once
	pdfSlots chan struct{}
}

const pdfWorkers = 2

// Run executes exporter e on the input.
func (r *Runner) Run(ctx context.Context, e Exporter, in Input) (Result, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch e.Type {
	case "pandoc":
		return r.pandoc(ctx, e, in)
	case "confluence":
		return r.confluence(ctx, e, in)
	case "script":
		return r.script(ctx, e, in)
	case "jira":
		return r.jira(ctx, e, in)
	}
	return Result{}, fmt.Errorf("unknown exporter type %q", e.Type)
}

// safePath resolves rel inside the exporters dir (symlinks included).
func (r *Runner) safePath(rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", errors.New(rel + " is outside the exporters directory")
	}
	dir, err := filepath.EvalSymlinks(r.Dir)
	if err != nil {
		return "", err
	}
	p, err := filepath.EvalSymlinks(filepath.Join(dir, rel))
	if err != nil {
		if rr, rerr := filepath.Rel(dir, filepath.Join(dir, rel)); rerr != nil || strings.HasPrefix(rr, "..") {
			return "", errors.New(rel + " is outside the exporters directory")
		}
		return "", err
	}
	if rr, err := filepath.Rel(dir, p); err != nil || rr == ".." || strings.HasPrefix(rr, ".."+string(filepath.Separator)) {
		return "", errors.New(rel + " is outside the exporters directory")
	}
	return p, nil
}

// capWriter keeps at most max bytes (no ReadFrom, so io.Copy honours it).
type capWriter struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.max {
		w.over = true
		return 0, errors.New("output too large")
	}
	return w.buf.Write(p)
}

const maxOutput = 100 << 20

func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		s = "…" + s[len(s)-400:]
	}
	return s
}
