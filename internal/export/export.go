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

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/cvss"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
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

// KeyName names the personal keys a destination may send with: the
// service and its host ("jira@firm.atlassian.net"; "" for files). A key is
// only ever sent to the host it was stored for.
func (e Exporter) KeyName() string {
	if !e.Service() || e.Host() == "" {
		return ""
	}
	return e.ServiceName() + "@" + strings.ToLower(e.Host())
}

// Endpoint is where a service destination sends keys and which server
// keys it reads ("" for files).
func (e Exporter) Endpoint() string {
	if !e.Service() {
		return ""
	}
	base, user := "", ""
	switch {
	case e.Type == "jira" && e.Jira != nil:
		base, user = e.Jira.BaseURL, e.Jira.UserEnv
	case e.Confluence != nil:
		base, user = e.Confluence.BaseURL, e.Confluence.UserEnv
	}
	return e.Type + " " + strings.TrimRight(strings.TrimSpace(base), "/") + " " + user + " " + e.TokenEnv()
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
		e, err := Parse(file, b)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", file, err))
			continue
		}
		out = append(out, e)
	}
	return out, errs
}

// IDRe is the form of an exporter's id (its file name without .yaml).
var IDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)

// Parse reads one exporter file (<id>.yaml) as Load does, with the same
// checks; a git push of an exporter is held to them too.
func Parse(file string, b []byte) (Exporter, error) {
	var e Exporter
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&e); err != nil {
		return e, err
	}
	e.ID = strings.TrimSuffix(file, ".yaml")
	if e.Name == "" {
		e.Name = e.ID
	}
	// only finished findings leave YARS (R10): never drafts, findings in
	// review or withdrawn ones
	e.Statuses = slices.DeleteFunc(e.Statuses, func(s string) bool { return s != "complete" && s != "reported" })
	if len(e.Statuses) == 0 {
		e.Statuses = []string{"complete"}
	}
	var err error
	switch {
	case e.Type == "pandoc" && !pandocFormat.MatchString(e.Format):
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
	return e, err
}

// AdminOnly is the refusal of a save NeedsAdmin keeps to admins (the export
// setup and a push say the same).
const AdminOnly = "address, space, parent page, project, issue type, key variables, script, template and pandoc --variable: admin only"

// adminPart is everything of a destination that is an admin's to set ("" for
// one that has nothing of it):
//   - a service's address and key variables (it gets the server's and the
//     authors' keys) and where it publishes there: the project and issue
//     type, or the space and parent page. Another project or space of the
//     same server may be one outsiders read.
//   - a script destination's script: it runs on the server as the service
//     account.
//   - a pandoc destination's template: a file of the server that pandoc (for
//     a PDF, LaTeX) reads; and its --variable arguments: their values reach
//     that template, the built-in PDF theme too, as they are, so LaTeX in
//     one reads a file of the server into the report as a template would.
func (e Exporter) adminPart() string {
	const sep = "\x00"
	switch {
	case e.Type == "script":
		return "script" + sep + e.Script
	case e.Type == "jira" && e.Jira != nil:
		// as it is read: a file that names no issue type means Bug
		return e.Endpoint() + sep + e.Target() + sep + issueType(e.Jira.IssueType)
	case e.Service():
		return e.Endpoint() + sep + e.Target() + sep + e.Confluence.ParentID
	case e.Type == "pandoc":
		vars := e.rawArgs()
		if e.Template == "" && len(vars) == 0 {
			return ""
		}
		return "template" + sep + e.Template + sep + strings.Join(vars, sep)
	}
	return ""
}

// rawArgs are the pandoc arguments whose value goes into the template as it
// is, in their order: --variable (pandoc escapes a --metadata value for the
// output format, a variable's not, and a variable wins over the metadata of
// the same name).
func (e Exporter) rawArgs() []string {
	var out []string
	for _, a := range e.Args {
		if strings.HasPrefix(a, "--variable=") {
			out = append(out, a)
		}
	}
	return out
}

// NeedsAdmin reports whether saving ex over prev (nil: a new exporter)
// takes an admin: ex has a part that is an admin's to set (adminPart) and
// prev did not have that same part. Name, statuses, mark_reported, a pandoc
// format and its other arguments, a script's extension, and taking such a
// part away are a director's.
func NeedsAdmin(prev *Exporter, ex Exporter) bool {
	part := ex.adminPart()
	return part != "" && (prev == nil || prev.adminPart() != part)
}

var safeWord = regexp.MustCompile(`^[a-z0-9_]+$`)

// pandocFormat is a pandoc format with its extensions turned on or off
// (docx+styles, markdown-smart+pipe_tables).
var pandocFormat = regexp.MustCompile(`^[a-z0-9_]+([+-][a-z0-9_]+)*$`)

// baseFormat is a pandoc format without its extensions.
func baseFormat(f string) string {
	if i := strings.IndexAny(f, "+-"); i >= 0 {
		return f[:i]
	}
	return f
}

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
	// Report is the engagement's report-level sections (Report tab), in
	// config order.
	Report []ReportText
	// Preview is the report as the web shows it: its label/value tables get
	// a Field | Value header row like every web table (the PDF, Word and
	// Confluence documents keep the report design, without one).
	Preview bool
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
	// attach, when set, replaces inlining: it keeps an attachment for the
	// page and returns its file name there (the Confluence push).
	attach func(f *finding.Finding, rel, ct string, data []byte) string
	// strictImages keeps only pictures that decode (PNG, JPEG, GIF): a PDF
	// fails on a broken one.
	strictImages bool
}

// ReportText is one report-level section: its name and Markdown body.
type ReportText struct {
	Name string `json:"name"`
	Body string `json:"body"`
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
	runOnce  sync.Once
	runSlots chan struct{}
}

// Slot waits for one of the export workers (at most exportWorkers exports
// run at once); release gives it back. Run takes one itself; a caller that
// builds a file without Run (the ZIPs) takes one with Slot.
func (r *Runner) Slot(ctx context.Context) (release func(), err error) {
	q := r.runQueue()
	select {
	case q <- struct{}{}:
		return func() { <-q }, nil
	case <-ctx.Done():
		return nil, notStarted(ctx, "export")
	}
}

// runQueue holds one token per export running.
func (r *Runner) runQueue() chan struct{} {
	r.runOnce.Do(func() { r.runSlots = make(chan struct{}, exportWorkers) })
	return r.runSlots
}

// notStarted is the error of a run whose wait for a worker ended: its
// request went away or its time ran out, in the words a finished run uses.
func notStarted(ctx context.Context, what string) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.New(what + " not started: timed out")
	}
	return errors.New(what + " not started: cancelled")
}

const pdfWorkers = 2

// exportWorkers is how many exports run at once: each may hold up to
// maxOutput in memory.
const exportWorkers = 4

// Run executes exporter e on the input.
func (r *Runner) Run(ctx context.Context, e Exporter, in Input) (Result, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if e.Type == "pandoc" && baseFormat(e.Format) == "pdf" {
		// first a PDF worker: a PDF in the queue holds no export worker
		release, err := r.pdfSlot(ctx)
		if err != nil {
			return Result{}, err
		}
		defer release()
	}
	release, err := r.Slot(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()
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
		if rr, rerr := filepath.Rel(dir, filepath.Join(dir, rel)); rerr != nil || rr == ".." || strings.HasPrefix(rr, ".."+string(filepath.Separator)) {
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
