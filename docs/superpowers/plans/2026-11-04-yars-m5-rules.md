# M5 Rule engine (static checkers) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** End users write style rules as YAML files (regex, built-in checks, scripts, AI prompts), each with its own level (error blocks, warning informs); rules run live in the editor, on the finding page, at submit/approve, and from `yars lint`.

**Architecture:** A new `internal/rules` package loads `.yars/rules/*.yaml`, builds a JSON view of a finding, and evaluates four rule kinds. Fast kinds (regex, built-in) run on every render and keystroke preview; slow kinds (script, AI) run on demand, at submit/approve and in the CLI, with results cached by content hash. The store gets a `Linter` hook that `Transition` uses so error-level violations block submit/approve; `web` shows a Checks panel and live editor hints; `cmd/yars` gets `lint` and ships example rules on `init`.

**Tech Stack:** Go 1.27, regexp (RE2), os/exec, net/http client, yaml.v3, encoding/json.

**Spec:** `docs/superpowers/specs/2026-11-03-yars-design.md` (section "Rule engine"); user requirements: rules are written by end users; YAML + regex + scripts + AI; per-rule block/warn; aim for "more or less bulletproof" findings.

## Global Constraints
- Rule files: every `*.yaml` in `.yars/rules/`, each a YAML list of rules. Fields: `id` (required, unique), `level` (`error`|`warning`, default `error`), `message`, `target`, and exactly one of `regex_forbid`, `regex_require`, `check`, `script`, `ai`. Optional `enabled: false`.
- Targets: `title`, `section:<Name>`, `sections` (each section separately), `details:<Row>`, `details` (each row separately), `text` (title + every section + every details row, each separately). Default target `text`. Script and AI rules may omit target (script gets the whole finding).
- `regex_forbid`: violation per match (quote = matched text, max 80 chars). `regex_require`: violation when the target has no match. Patterns use Go RE2 syntax; `(?m)` etc. allowed. Empty targets are skipped for `regex_require` unless `require_nonempty: true`.
- Built-in `check` values: `table-cells-no-backticks` (backticks inside GFM table cells of sections, and anywhere in details values), `cvss-explained` (non-standard CVSS metric without explanation), `not-empty` (target must be non-blank).
- Script rules: path relative to `.yars/rules/`, must stay inside it; run directly (must be executable) with the finding JSON on stdin, cwd = `.yars/rules/`, 10 s timeout, env limited to `PATH` and `HOME`; stdout = JSON array of `{"message","quote"?,"target"?}`; non-zero exit or bad JSON = one violation "rule failed: …" at the rule's level.
- AI rules: `ai` = plain-English rule; sent with the target text to the configured provider; response must be JSON `{"violations":[{"quote","message"}]}`. Config in `.yars/config.yaml`:
  ```yaml
  ai:
      provider: openai        # openai (also LiteLLM / any OpenAI-compatible) | anthropic
      base_url: https://api.openai.com/v1
      model: gpt-4o-mini
      api_key_env: YARS_AI_KEY   # key read from this env var, never stored in git
  ```
  No `ai` config or no key → AI rules are skipped with one warning "AI rules skipped: no AI provider configured". 60 s timeout. Results cached in memory by sha256(provider, model, rule text, target text).
- Finding JSON (scripts, AI context): `{"id","title","status","severity","cvss","cvss_reasons":{},"details":{},"sections":[{"name","body"}],"author","reviewers":[]}`.
- Violation: `{rule, level, message, target, quote}`; `message` defaults to the rule id when the rule has none.
- Gate: `submit` and `approve` run all kinds; any `error` violation denies with the messages listed. Warnings never block.
- Shell usage: Write/Edit for files; single plain commands; tests that need an executable script write it with `os.WriteFile(..., 0o755)` inside `t.TempDir()`.

## Review Focus
1. A user regex that doesn't compile, or a rule file with bad YAML: the server still starts; the broken rule is reported as an error-level "rule invalid" violation on every finding (so it can't be silently ignored) (Task 1 `TestLoadReportsBadRules`).
2. A script that hangs, prints garbage, or tries `../` paths: timeout/violation, never a hang or escape (Task 2 `TestScriptTimeoutAndEscape`).
3. The AI provider down or returning non-JSON: one "AI check failed" warning, never a block or a 500 (Task 2 `TestAIErrorIsWarning`).
4. A huge or catastrophic-looking regex input: RE2 is linear, but cap quotes and violations per rule (max 20) so a page can't explode (Task 1 `TestViolationCap`).
5. Backticks inside fenced code blocks must not trigger `table-cells-no-backticks`; a `|` inside inline code must not break cell parsing (Task 1 `TestTableCellsCheck`).

---

### Task 1: `internal/rules` — load, finding JSON, regex and built-in checks

**Files:** Create `internal/rules/rules.go`, `internal/rules/builtin.go`, `internal/rules/rules_test.go`.

**Interfaces — Produces:**
- `type Rule struct{ ID, Level, Message, Target, RegexForbid, RegexRequire, Check, Script, AI string; RequireNonempty bool; Enabled *bool; File string }` (yaml tags as above; `File` set by loader).
- `type Violation struct{ Rule, Level, Message, Target, Quote string }` (json tags lower-case).
- `type Set struct{ Rules []Rule; Dir string; Problems []Violation }` — `Problems` holds load errors as error-level violations with rule id `rules/<file>`.
- `func Load(dir string) *Set` — never fails; missing dir = empty set.
- `type Doc struct` = the finding JSON (fields above) and `func DocOf(f *finding.Finding) Doc`.
- `type Kind int`; `const Fast Kind = 1; Slow Kind = 2; All = Fast | Slow`.
- `func (s *Set) Run(ctx context.Context, d Doc, cfg config.Config, kinds Kind, slow SlowRunner) []Violation` — `slow` may be nil (slow rules skipped). Order: problems, then rules in file/rule order.
- `type SlowRunner interface{ Script(ctx, r Rule, d Doc) []Violation; AI(ctx, r Rule, target, text string) []Violation }`.
- `func Errors(vs []Violation) []string` — messages of error-level violations.
- `func (s *Set) ForTarget(target string) []Rule`... not needed; editor uses `RunText(section string, body string)`: `func (s *Set) RunSection(d Doc, cfg config.Config, section, body string) []Violation` — fast rules whose target applies to that section, evaluated on `body` (for live preview).

- [ ] **Step 1: Failing tests** — `TestLoadReportsBadRules` (bad YAML file, bad regex, duplicate id, two kinds in one rule, unknown check → Problems with file names; good rules still loaded); `TestRegexForbid` (title "SQL injection." with `\.$` → 1 violation quote "."); `TestRegexRequire`; `TestTargets` (section:Location, sections, details:Location, text); `TestTableCellsCheck` (table with `` `x` `` in a cell → violation; backticks in a paragraph or fenced block → none; `` `a|b` `` in a cell doesn't split oddly; details value with backtick → violation); `TestCVSSExplainedCheck`; `TestViolationCap` (regex_forbid `.` on 10 000 chars → 20 violations); `TestDisabledRule`; `TestRunSection`.
- [ ] **Step 2: Run** `go test ./internal/rules/` — FAIL.
- [ ] **Step 3: Implement.** Table cell parsing: walk section lines outside fences (reuse a fence tracker equivalent to `finding`'s — export `finding.FenceTracker` or copy the 15 lines); a table row is a line starting with optional spaces then `|`, or a line containing `|` directly below/above a delimiter row `|---|`; check backticks on those rows.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat(rules): rule files, regex and built-in checks`.

---

### Task 2: Script and AI runners

**Files:** Create `internal/rules/slow.go`, `internal/rules/ai.go`, `internal/rules/slow_test.go`; Modify `internal/config/config.go` (`AI AIConfig` with `Provider, BaseURL, Model, APIKeyEnv`), `config_test.go`.

**Interfaces — Produces:**
- `type Runner struct{ Dir string; AI AIConfig; HTTP *http.Client; cache sync.Map }` implementing `SlowRunner`; `func NewRunner(dir string, ai config.AIConfig) *Runner`.
- OpenAI-compatible: `POST {base_url}/chat/completions` with `{"model","messages":[system,user],"response_format":{"type":"json_object"},"temperature":0}`, header `Authorization: Bearer <key>`. Anthropic: `POST {base_url or https://api.anthropic.com}/v1/messages` with `{"model","max_tokens":1024,"system","messages":[user]}`, headers `x-api-key`, `anthropic-version: 2023-06-01`; take the first text block and extract the JSON object from it.
- System prompt (exact): "You check penetration-test findings against one style rule. Reply with JSON only: {\"violations\":[{\"quote\":\"exact text from the input\",\"message\":\"what is wrong and how to fix it\"}]}. Return an empty list when the text follows the rule." User message: "Rule: <rule>\n\nText (<target>):\n<text>".

- [ ] **Step 1: Failing tests** — `TestScriptViolations` (script prints `[{"message":"m","quote":"q"}]` → 1 violation; reads stdin JSON id), `TestScriptTimeoutAndEscape` (sleep 30 with 1 s test timeout override → "rule failed"; `script: ../x` → "rule failed: script outside rules dir"; non-executable → failed), `TestAIOpenAI` and `TestAIAnthropic` (httptest servers assert path, headers, model; return violations), `TestAICache` (second identical call doesn't hit server), `TestAIErrorIsWarning` (500 and non-JSON → one warning-level "AI check failed"), `TestAINotConfigured` (→ one warning, rules skipped).
- [ ] **Step 2–4:** FAIL → implement → `go test ./...` PASS.
- [ ] **Step 5: Commit** `feat(rules): script and AI rule runners`.

---

### Task 3: Gate, Checks panel, live editor hints

**Files:** Modify `internal/store/store.go` (`Linter` hook), `internal/web/server.go`, `edit.go` (preview), `partials.html` (editor shows hints), `workflow.go`; Create `internal/web/checks.go`, `templates/checks.html`; Modify `cmd/yars/main.go` (wire rules); Tests `internal/store/rules_test.go`, `internal/web/checks_test.go`.

**Interfaces:**
- `type Linter interface{ Lint(ctx context.Context, f *finding.Finding, kinds rules.Kind) []rules.Violation }` in store; `Store.Linter` field (nil = no rules). `Transition` for submit/approve: error violations (kinds All) → `*workflow.Denied{"cannot submit: <rule message>; …"}`.
- `rules.Engine{Set *Set; Runner SlowRunner; Cfg config.Config}` implements `Lint`; the set is reloaded when `.yars/rules` changes (mtime check per call is enough).
- Web: Checks panel at the top of the finding's main column listing fast violations (errors red, warnings amber, with quote and target) and a "Run all checks" button (htmx POST `/e/{eng}/f/{fid}/checks` → full run, renders `checks_panel`). Workflow bar: when fast checks have errors, the submit button is disabled and the errors listed like gate problems.
- Live: the section editor's preview request carries `section`; the preview response appends fast violations for that section under the preview.

- [ ] **Step 1: Failing tests** — `TestSubmitBlockedByRule` (rule title-no-dot error; title "X." → submit Denied mentioning the rule message; warning-only rule doesn't block); `TestChecksPanel` (page lists violation; POST /checks runs a script rule); `TestPreviewShowsHints` (preview with section=Location and a backtick body → hint listed).
- [ ] **Step 2–4:** FAIL → implement → `go test ./...` PASS.
- [ ] **Step 5: Commit** `feat: rules gate submit/approve; checks panel; live editor hints`.

---

### Task 4: `yars lint`, example rules, manual check

**Files:** Modify `cmd/yars/main.go`; Create `cmd/yars/rules_example.yaml` (embedded) and `cmd/yars/main_test.go`.

**Interfaces:**
- `yars lint --data <dir> [--all] [<eng>[/<finding-dir>]]` — default fast+slow (`--fast` for fast only); prints `F-001 error title-no-dot: Title must not end with a dot ("SQL injection.")`, exit 1 when any error, 0 otherwise.
- `yars init` writes `.yars/rules/style.yaml` with the user's examples: title-no-trailing-dot (regex_forbid `\.\s*$` on title), no-backticks-in-tables (check table-cells-no-backticks), no-backticks-in-location (regex_forbid backtick on details:Location and section:Location), cvss-explained (check), acronyms-expanded (ai, warning, target sections; skipped until AI configured).

- [ ] **Step 1: Failing test** — `TestLintCommand` (run `run([]string{"lint", ...})` against a temp repo with a bad title → exit code 1 and output line).
- [ ] **Step 2–4:** FAIL → implement → PASS; `gofmt -l .` clean.
- [ ] **Step 5: Commit** `feat(cli): yars lint and example style rules`.
- [ ] **Step 6: Manual check** — copy the example rules into the demo data repo, restart, see violations on F-001 in the Checks panel, type a backtick into Location and see the live hint, try to submit a finding with a trailing dot (blocked), run `yars lint --data <demo>`.
