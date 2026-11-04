# M8 Exporters Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Export an engagement's findings into client deliverables through pluggable exporters — pandoc (docx/pdf/html/odt… with user templates), Confluence HTML (download for pasting, optional push via the Confluence REST API) and script exporters — and mark exported findings as reported.

**Architecture:** A new `internal/export` package loads exporter configs from `.yars/exporters/*.yaml`, builds one report document from the selected findings (Markdown for pandoc, XHTML for Confluence, JSON for scripts) and runs the exporter. `web` adds an Export page per engagement (pick exporter + findings → download or push result); successful exports by a director/admin mark the findings reported through `store.Transition(Report)`. `cmd/yars` gets `yars export` and `init` ships two default exporters.

**Tech Stack:** Go 1.27, os/exec (pandoc), goldmark (XHTML), net/http client (Confluence), yaml.v3.

**Spec:** `docs/superpowers/specs/2026-11-03-yars-design.md` (section "Exporters"); user: "currently it's html into confluence. I want it to have pluggable exporters too, I like pandoc for file generation in many formats."

## Global Constraints
- Exporter file `.yars/exporters/<id>.yaml` (id = file name without extension):
  ```yaml
  name: Client report (DOCX)
  type: pandoc               # pandoc | confluence | script
  format: docx               # pandoc: output format (docx, pdf, html, odt, md, …)
  template: report.docx      # optional, relative to .yars/exporters; docx/odt/pptx → --reference-doc, others → --template
  args: [--toc]              # optional extra pandoc args
  script: export.sh          # script type: executable in .yars/exporters, finding JSON on stdin, file on stdout
  extension: txt             # script type: output file extension
  statuses: [complete]       # which findings are pre-selected (default [complete])
  mark_reported: true        # default true; only takes effect for director/admin exports
  confluence:                # confluence type, optional push (without it: HTML download)
      base_url: https://acme.atlassian.net/wiki
      space: SEC
      parent_id: "12345"
      user_env: CONFLUENCE_USER
      token_env: CONFLUENCE_TOKEN
  ```
- Report content per finding (all exporters): heading `<ID> <title>`; severity (+ CVSS score/vector when valid); details table (configured rows, plain text); CVSS explanation table (non-standard metrics with reasons) when present; retest result line for retest findings; then every section in file order with its Markdown body (section headings one level below the finding heading). Findings ordered by severity (config order) then ID. Report title = engagement name, subtitle client + dates.
- Pandoc: `pandoc -f gfm -t <format> -o <tmp>/report.<ext> [--reference-doc|--template <abs>] [args…] --metadata title=<name>` with the Markdown on stdin; 120 s timeout; output size cap 100 MB; pandoc path from `exec.LookPath("pandoc")` (overridable for tests). `pdf` uses pandoc's default engine (user's environment).
- Confluence HTML: XHTML (goldmark `html.WithXHTML()`), tables with `<table><tbody>`, code blocks as Confluence code macros only in push mode (`ac:structured-macro name="code"`); download mode is plain XHTML wrapped in a minimal HTML document.
- Confluence push: `POST {base_url}/rest/api/content` with `{"type":"page","title":"<engagement name> — findings","space":{"key":space},"ancestors":[{"id":parent_id}],"body":{"storage":{"value":<xhtml>,"representation":"storage"}}}`, Basic auth from the env vars; https only (http only for localhost); on success the page URL (`_links.base + _links.webui`) is shown.
- Script exporter: env PATH/HOME only, cwd `.yars/exporters`, 120 s timeout, stdout cap 100 MB, stdin = JSON `{"engagement":{…},"findings":[Doc…]}` (Doc = rules.Doc plus `"html_sections"`).
- Marking reported: only findings in status `complete`, only when the exporter has `mark_reported` and the user is director/admin; one `Transition(Report)` per finding after the export succeeded; failures are listed, never fatal for the download.
- Anyone logged in may export (preview); nobody but director/admin changes statuses.
- Shell usage: Write/Edit for files; single plain commands.

## Review Focus
1. A finding body with raw HTML, `<script>`, or Confluence macro XML: escaped/omitted in Confluence output (no macro injection into the client's wiki) (Task 1 `TestConfluenceEscapes`).
2. Pandoc missing, failing, or hanging: clear error, no partial download, nothing marked reported (Task 1 `TestPandocFailure`, Task 2 `TestExportFailureMarksNothing`).
3. Template/script paths escaping `.yars/exporters` (`../`, absolute, symlink): rejected (Task 1 `TestExporterPathEscape`).
4. Exporting draft/verification findings when explicitly selected: allowed as preview, but they're never marked reported (Task 2 `TestExportMarksOnlyComplete`).
5. Confluence credentials/token never appear in errors shown to users or in logs (Task 1 `TestConfluencePushErrors`).

---

### Task 1: `internal/export`

**Files:** Create `internal/export/export.go` (config, load, document), `internal/export/pandoc.go`, `internal/export/confluence.go`, `internal/export/script.go`, `internal/export/export_test.go`.

**Interfaces — Produces:**
- `type Exporter struct{ ID, Name, Type, Format, Template, Script, Extension string; Args, Statuses []string; MarkReported *bool; Confluence *ConfluenceConf }` with `func (e Exporter) Marks() bool`.
- `func Load(dir string) ([]Exporter, []error)` — sorted by ID; invalid files reported.
- `type Input struct{ Engagement store.Engagement; Findings []*finding.Finding; Cfg config.Config }`.
- `func Markdown(in Input) string`, `func XHTML(in Input, confluenceMacros bool) string`.
- `type Result struct{ Filename, ContentType string; Data []byte; URL string }` (URL set for Confluence push).
- `type Runner struct{ Dir, PandocPath string; HTTP *http.Client; Getenv func(string) string; Timeout time.Duration }` and `func (r *Runner) Run(ctx context.Context, e Exporter, in Input) (Result, error)`.

- [ ] **Step 1: Failing tests** — `TestLoad` (two exporters, one invalid type → error listed), `TestMarkdownLayout` (finding order by severity; details table; CVSS explanation table; retest line; section headings shifted to `##`), `TestPandocRun` (fake pandoc script records args/stdin and writes the output file → Result has bytes, filename `<eng>.docx`, args include `--reference-doc <abs>`), `TestPandocReal` (skipped when pandoc missing: docx output starts with `PK`), `TestPandocFailure` (fake exits 1 with stderr → error contains stderr tail; hanging fake with short timeout → timeout error), `TestConfluenceEscapes`, `TestConfluencePush` (httptest: path, Basic auth, body storage value contains finding title; Result.URL), `TestConfluencePushErrors` (401 → error without token text), `TestExporterPathEscape`, `TestScriptExporter`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `feat(export): pandoc, Confluence and script exporters`.

---

### Task 2: Export page, mark reported, CLI, defaults, manual check

**Files:** Create `internal/web/export.go`, `internal/web/templates/export.html`; Modify `server.go` (route, `Server.Export *export.Runner`), `engagement.html` (Export button), `cmd/yars/main.go` (`export` subcommand, init writes `.yars/exporters/docx.yaml` and `confluence.yaml`, serve wires the runner); Tests `internal/web/export_test.go`, `cmd/yars/main_test.go`.

**Interfaces:**
- `GET /e/{eng}/export` — exporters as radio cards, findings checklist (pre-checked by the chosen exporter's statuses; default complete), note "Findings will be marked reported" when it applies.
- `POST /e/{eng}/export` (fields `exporter`, `finding`…) — runs; download (`Content-Disposition: attachment; filename=…`) or, for Confluence push, a result page with the link; then marks complete findings reported (director/admin + mark_reported). Errors re-render the page with a banner (400/500), nothing marked.
- `yars export --data <dir> --exporter <id> [--out <file>] [--mark --as <user>] <eng> [<finding-dir>…]`.

- [ ] **Step 1: Failing tests** — `TestExportDownload` (fake pandoc; dora exports → 200 attachment; F-001 complete → reported; commit by dora), `TestExportMarksOnlyComplete` (draft selected → in report, still draft), `TestExportFailureMarksNothing`, `TestExportPentesterNoMark` (alice exports → download, nothing reported), `TestExportCLI`.
- [ ] **Step 2–4:** FAIL → implement → `go test ./...`, `gofmt -l .` PASS.
- [ ] **Step 5: Commit** `feat: export page, mark reported, yars export, default exporters`.
- [ ] **Step 6: Manual check** — on the demo with real pandoc: export the ACME engagement to DOCX (open the file's text via `pandoc -t plain` to verify content), download Confluence HTML, confirm the complete finding became reported and the inbox/table update.
