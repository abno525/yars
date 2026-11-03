# CVSS calculator + details table Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a CVSS 3.1 calculator with a CVSS reasoning table and a configurable 5-row details table to YARS findings.

**Architecture:** A dependency-free `internal/cvss` package scores and parses vectors. `finding` gains YAML-node patching so front-matter edits keep comments/order. `store` gets one generic mutate helper plus `UpdateCVSS`, `UpdateSeverity`, `UpdateDetails`. `web` adds two htmx panels (Details, CVSS) above the prose sections; the index derives severity from the vector on read.

**Tech Stack:** Go 1.27, net/http, html/template, htmx 2.0.4, gopkg.in/yaml.v3.

**Spec:** `docs/superpowers/specs/2026-11-03-yars-cvss-details-design.md` (parent: `docs/superpowers/specs/2026-11-03-yars-design.md`)

## Global Constraints
- Branch: continue on `feat/core` (milestones 1–2 not merged yet).
- CVSS 3.1 base metrics only: AV, AC, PR, UI, S, C, I, A. Vector stored as `CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_` (canonical order). `CVSS:3.0/` input accepted, stored as 3.1.
- Ratings: 0.0 → `info`, 0.1–3.9 `low`, 4.0–6.9 `medium`, 7.0–8.9 `high`, 9.0–10.0 `critical`.
- Default `details_rows`: `[Location, Business impact, Row 3, Row 4, Row 5]`.
- Default `cvss.standard`: `AV: N, AC: L, PR: N, UI: N, S: U`; config merges over it; `"-"` removes a default.
- Default sections become: Description, Impact, Steps to Reproduce, Remediation, References.
- Front-matter keys: `cvss`, `cvss_reasons` (map metric→text), `details` (map row→text), `severity`.
- Details values are plain text (never rendered as Markdown); multi-line values are written as YAML literal block scalars.
- Commit messages: `F-001: set CVSS 8.1`, `F-001: clear CVSS`, `F-001: set severity high`, `F-001: edit details`.
- Shell usage (user requirement, no permission prompts): write files only with Write/Edit; single plain commands, e.g. `go test ./internal/cvss/`, `git -C /home/plato/Documents/CLAUDE/yars ...`; no heredocs, `sed -i`, `cd`, pipes, chains or variables in redirects. Subagent prompts must repeat this.

## Review Focus
1. A finding whose front matter has comments, custom keys and non-default order: a CVSS/details save must leave every untouched line byte-identical (Task 3 test `TestSetMetaKeepsComments`).
2. A foreign `cvss` value (`8.1`, a `CVSS:4.0/...` vector, a 3.1 vector with `E:P`): the finding page renders with a read-only note and no 500; table severity = stored severity (Task 6 test `TestFindingForeignCVSS`).
3. Two people editing CVSS or details at once: second save gets 409 with their input kept (Tasks 4, 6, 7 tests).
4. Details text containing `<script>`, `: `, a leading `- `, `#` or newlines: round-trips through YAML unchanged and is HTML-escaped on the page (Task 4 `TestUpdateDetailsRoundTrip`, Task 7 `TestDetailsEscaped`).
5. Pasted vectors with lowercase, surrounding spaces, shuffled order, a missing metric, a duplicate metric, or an invalid value: parsed or a clear error, never a panic (Task 1 `TestParse` table).

---

### Task 1: `internal/cvss` package

**Files:**
- Create: `internal/cvss/cvss.go`
- Test: `internal/cvss/cvss_test.go`

**Interfaces:**
- Produces:
  - `type Vector map[string]string` (metric key → value code, e.g. `"AV":"N"`)
  - `type Value struct{ Code, Name string }`; `type Metric struct{ Key, Name string; Values []Value }`
  - `var Metrics []Metric` — in canonical order AV, AC, PR, UI, S, C, I, A with names: Attack Vector (N Network, A Adjacent, L Local, P Physical), Attack Complexity (L Low, H High), Privileges Required (N None, L Low, H High), User Interaction (N None, R Required), Scope (U Unchanged, C Changed), Confidentiality / Integrity / Availability (H High, L Low, N None)
  - `func Parse(s string) (Vector, error)` — trims space, case-insensitive prefix `CVSS:3.0/` or `CVSS:3.1/` required, uppercases keys/values, any order; errors: missing prefix, unknown metric, duplicate metric, invalid value, missing metric (message names the metric, e.g. `missing metric AC`)
  - `func ParsePartial(s string) (Vector, error)` — same, but missing metrics allowed (used by the calculator form)
  - `func (v Vector) Complete() bool`
  - `func (v Vector) String() string` — canonical `CVSS:3.1/...`; only metrics present
  - `func Score(v Vector) (float64, error)` — error if not complete
  - `func Rating(score float64) string`
  - `func FormatScore(f float64) string` — `"%.1f"`
  - `func Derive(vector, stored string) string` — returns `Rating(Score(Parse(vector)))` when vector parses complete, else `stored`
  - `func MetricName(key string) string`, `func ValueName(key, code string) string`

- [ ] **Step 1: Write failing tests**

```go
func TestScore(t *testing.T) {
	cases := map[string]string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": "9.8",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": "6.1",
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": "7.8",
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N": "7.4",
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": "9.9",
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": "1.6",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": "0.0",
		"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N": "5.5", // PR:H with scope changed uses 0.50
	}
	// for each: Parse ok, Score ok, FormatScore(score) == want
}
func TestRating(t *testing.T) // 0→info, 0.1→low, 3.9→low, 4.0→medium, 6.9→medium, 7.0→high, 8.9→high, 9.0→critical, 10→critical
func TestParse(t *testing.T) {
	// ok: "  cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h ", shuffled order "CVSS:3.1/C:H/AV:N/...",
	//     "CVSS:3.0/..." → String() starts with "CVSS:3.1/" and is canonical order
	// errors (no panic): "8.1", "CVSS:4.0/AV:N/...", "AV:N/AC:L/...", missing AC (error contains "AC"),
	//     duplicate "AV:N/AV:L", "AV:X", "E:P" extra metric, "" (empty)
}
func TestParsePartial(t *testing.T) // "CVSS:3.1/AV:N/AC:L" ok, Complete()==false, Score errors
func TestDerive(t *testing.T) // valid vector → rating; "8.1" → stored; "" → stored
```

- [ ] **Step 2: Run** `go test ./internal/cvss/` — Expected: FAIL (package/functions undefined).

- [ ] **Step 3: Implement `internal/cvss/cvss.go`.** Weights and formula from the FIRST CVSS v3.1 spec §7: AV N .85 A .62 L .55 P .2; AC L .77 H .44; PR N .85, L .62 (.68 if S:C), H .27 (.5 if S:C); UI N .85 R .62; C/I/A H .56 L .22 N 0. ISS = 1−(1−C)(1−I)(1−A); Impact = 6.42·ISS (S:U) or 7.52·(ISS−0.029) − 3.25·(ISS−0.02)^15 (S:C); Exploitability = 8.22·AV·AC·PR·UI; Impact ≤ 0 → 0; else S:U Roundup(min(Impact+Expl, 10)), S:C Roundup(min(1.08·(Impact+Expl), 10)). Roundup per spec Appendix A: `i := int(math.Round(x*100000)); if i%10000 == 0 { return float64(i)/100000 }; return (math.Floor(float64(i)/10000)+1)/10`.

- [ ] **Step 4: Run** `go test ./internal/cvss/` — Expected: PASS.

- [ ] **Step 5: Commit** `git -C /home/plato/Documents/CLAUDE/yars add internal/cvss` then `git -C /home/plato/Documents/CLAUDE/yars commit -m "feat(cvss): CVSS 3.1 parser and calculator"`.

---

### Task 2: Config — details rows, CVSS standards, severity check

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: `cvss.Metrics`, `cvss.ValueName`.
- Produces:
  - `Config.DetailsRows []string` (`yaml:"details_rows"`)
  - `Config.CVSS CVSSConfig` (`yaml:"cvss"`); `type CVSSConfig struct{ Version string; Standard map[string]string }` (`yaml:"version"`, `yaml:"standard"`)
  - After `Load`/`Default`: `DetailsRows` defaulted, `CVSS.Version` = `"3.1"`, `CVSS.Standard` = defaults merged with file values, `"-"` entries deleted.
  - `func (c Config) NonStandard(key, value string) bool` — true when a standard exists for key and value != standard.

- [ ] **Step 1: Write failing tests**

```go
func TestDefaultDetailsAndSections(t *testing.T) // DetailsRows == [Location, Business impact, Row 3, Row 4, Row 5]; Sections has no "Location"
func TestCVSSStandardMerge(t *testing.T) // file `cvss: {standard: {AC: H, UI: "-", C: N}}` → Standard == {AV:N, AC:H, PR:N, S:U, C:N}
func TestNonStandard(t *testing.T) // default cfg: ("AC","H") true, ("AC","L") false, ("C","H") false
func TestLoadRejectsBadStandard(t *testing.T) // `standard: {AV: Z}` → error mentioning "AV"
func TestLoadRequiresRatingSeverities(t *testing.T) // `severities: [high, medium, low]` → error mentioning "critical" and "info"
```

- [ ] **Step 2: Run** `go test ./internal/config/` — Expected: FAIL.
- [ ] **Step 3: Implement** in `config.go` (validation in a `validate(c *Config) error` called by `Load`; required severities = the five rating names).
- [ ] **Step 4: Run** `go test ./internal/config/` — Expected: PASS. Then `go test ./...` — fix any test that relied on `Location` being a default section by giving it an explicit config.
- [ ] **Step 5: Commit** `feat(config): details rows and CVSS standards`.

---

### Task 3: Front-matter node patching in `finding`

**Files:**
- Modify: `internal/finding/finding.go`
- Test: `internal/finding/finding_test.go`

**Interfaces:**
- Produces:
  - `Meta.CVSSReasons map[string]string` (`yaml:"cvss_reasons,omitempty"`), `Meta.Details map[string]string` (`yaml:"details,omitempty"`)
  - `func (f *Finding) SetMeta(key string, value any) error` — parses current front matter (rawMeta, or `encodeMeta` when empty) into a `yaml.Node`, replaces the value node of `key` in place (keeping the key's head comment and position), appends the key at the end if absent, deletes the key when `value == nil`; re-encodes the document with indent 4, sets `rawMeta`, re-decodes `Meta`, resets `metaSnap`. `value` may be a `*yaml.Node` (used as-is) or any Go value (encoded via `Node.Encode`).
  - `func OrderedMap(keys []string, m map[string]string) *yaml.Node` — mapping node in `keys` order (keys missing from `m` skipped), then any remaining keys of `m` sorted; values containing `\n` use `yaml.LiteralStyle`.

Note: re-encoding a node tree keeps comments and key order but may normalise indentation/quoting of the whole block; the test pins what must survive.

- [ ] **Step 1: Write failing tests**

```go
func TestSetMetaKeepsComments(t *testing.T) {
	// input front matter:
	// id: F-001
	// # owner note
	// title: SQLi
	// custom_key: keep me   # trailing comment
	// severity: high
	// SetMeta("severity", "critical"); SetMeta("cvss", "CVSS:3.1/...")
	// out := string(f.Bytes()): contains "# owner note", "custom_key: keep me", "# trailing comment",
	// "severity: critical"; index("title") < index("custom_key") < index("severity") < index("cvss");
	// re-Parse(out).Meta.Severity == "critical"; body sections unchanged
}
func TestSetMetaDelete(t *testing.T)       // SetMeta("cvss", nil) removes the line; other keys intact
func TestSetMetaCRLF(t *testing.T)         // CRLF input stays CRLF after SetMeta
func TestSetMetaOnNew(t *testing.T)        // New(...) then SetMeta("details", OrderedMap(...)) → Parse round-trip has Details
func TestOrderedMapMultiline(t *testing.T) // value "a\nb" → re-parsed equals "a\nb"; keys appear in given order then extras sorted
```

- [ ] **Step 2: Run** `go test ./internal/finding/` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./internal/finding/` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(finding): patch front matter via YAML nodes`.

---

### Task 4: Store — CVSS, severity, details updates

**Files:**
- Modify: `internal/store/store.go`
- Test: `internal/store/store_test.go`

**Interfaces:**
- Consumes: Task 1 `cvss.Parse`, `Score`, `Rating`, `FormatScore`, `Derive`; Task 2 `Config.DetailsRows`, `Config.Severities`; Task 3 `SetMeta`, `OrderedMap`.
- Produces:
  - `var ErrInvalidValue = errors.New("invalid value")`
  - `func CVSSHash(m finding.Meta) string` — `BodyHash` of `m.CVSS` + "\x00" + reasons in sorted key order
  - `func DetailsHash(m finding.Meta) string` — `BodyHash` of details in sorted key order
  - `func (s *Store) UpdateCVSS(engID, dir, vector string, reasons map[string]string, base string, a gitrepo.Author) error` — `vector == ""` clears: sets `severity` to `cvss.Derive(old cvss, old severity)`, deletes `cvss`, msg `clear CVSS`. Otherwise `Parse` (error → `ErrInvalidValue` wrapped), store canonical `String()`, set `severity` to rating; merge reasons: non-empty value sets key, empty value deletes key, keys not in `reasons` untouched; msg `set CVSS 8.1`. Empty base skips the conflict check; mismatch → `ErrConflict`. No-op change → no commit.
  - `func (s *Store) UpdateSeverity(engID, dir, sev string, a gitrepo.Author) error` — sev must be in `Config.Severities` else `ErrInvalidValue`; refused with `ErrInvalidValue` when the finding has a vector that parses; msg `set severity high`.
  - `func (s *Store) UpdateDetails(engID, dir string, values map[string]string, base string, a gitrepo.Author) error` — values normalised (CRLF→LF, trailing whitespace trimmed per value); keys in `values` replace, other existing keys kept; written with `OrderedMap(cfg.DetailsRows, merged)`; msg `edit details`; same base/no-op rules.
  - Internal refactor: `func (s *Store) mutate(engID, dir string, a gitrepo.Author, fn func(f *finding.Finding) (msg string, err error)) error` used by `UpdateSection` and the three new methods (lock, load, fn, no-op check, write, commit with rollback).

- [ ] **Step 1: Write failing tests**

```go
func TestUpdateCVSS(t *testing.T) // vector shuffled lowercase → file has canonical cvss, severity high, reasons{AC:"race"}; git log subject "F-001: set CVSS 7.4"; author correct
func TestUpdateCVSSInvalid(t *testing.T) // "8.1" → errors.Is(err, ErrInvalidValue); no new commit
func TestUpdateCVSSConflict(t *testing.T) // base = CVSSHash before; another UpdateCVSS lands; old base → ErrConflict
func TestUpdateCVSSReasonsKept(t *testing.T) // reasons{AC:"x"} then save with reasons{} for a vector where AC is standard → AC reason still in file
func TestUpdateCVSSClear(t *testing.T) // after set (high), clear → no cvss key, severity high, msg "F-001: clear CVSS"
func TestUpdateSeverity(t *testing.T) // no vector: "medium" ok; "urgent" → ErrInvalidValue; with vector → ErrInvalidValue
func TestUpdateDetailsRoundTrip(t *testing.T) // values {"Location":"<script>x</script>\n- a: b\n# c", "Business impact":"x"} → reload equal; keys order in file follows DetailsRows; pre-existing key "Old row" kept
func TestUpdateDetailsConflict(t *testing.T) // stale base → ErrConflict
func TestUpdateDetailsNoop(t *testing.T) // same values twice → one commit
```

- [ ] **Step 2: Run** `go test ./internal/store/` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./internal/store/` then `go test ./...` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(store): CVSS, severity and details updates`.

---

### Task 5: Index — derived severity and score column

**Files:**
- Modify: `internal/index/index.go`, `internal/web/server.go` (columns), `internal/web/templates/partials.html` (findings table)
- Test: `internal/index/index_test.go`

**Interfaces:**
- Consumes: `cvss.Derive`, `cvss.Parse`, `cvss.Score`, `cvss.FormatScore`.
- Produces: `Row.Score string` (`"8.1"` or `""`), `Row.Severity` = `cvss.Derive(m.CVSS, m.Severity)`; sort key `"cvss"` sorts by numeric score (empty below 0.0); web column `{"cvss","CVSS"}` placed after Severity; filter by severity uses derived value.

- [ ] **Step 1: Write failing tests**

```go
func TestRowsDeriveSeverity(t *testing.T) // file severity: low, cvss 9.8 vector → Row.Severity "critical", Row.Score "9.8"; severity filter "critical" returns it
func TestRowsForeignCVSS(t *testing.T)    // cvss "8.1", severity medium → Severity "medium", Score ""
func TestSortByCVSS(t *testing.T)         // scores 9.8, "", 4.8 → asc order "", 4.8, 9.8; desc reversed
```

- [ ] **Step 2: Run** `go test ./internal/index/` — Expected: FAIL.
- [ ] **Step 3: Implement; add the CVSS `<td>` (class `fid`) to the findings partial and bump the empty-row colspan to 7; update the mobile CSS hide rules to columns 6 and 7.**
- [ ] **Step 4: Run** `go test ./...` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(index): derive severity from CVSS, add score column`.

---

### Task 6: Web — CVSS panel and calculator

**Files:**
- Create: `internal/web/cvss.go`, `internal/web/templates/cvss.html` (defines templates `cvss_panel` and `cvss_editor`; parsed for every page like partials — add it to the shared list in `Server.init`)
- Modify: `internal/web/server.go` (route registration, `page.CVSS`), `internal/web/templates/finding.html`, `internal/web/static/style.css`
- Test: `internal/web/cvss_test.go`

**Interfaces:**
- Consumes: Tasks 1, 2, 4.
- Produces routes (all under `/e/{eng}/f/{fid}`):
  - `GET /cvss` → `cvss_panel`; `GET /cvss/edit` → `cvss_editor` initialised from the stored vector (or team standards + empty C/I/A when none/foreign)
  - `POST /cvss/calc` → `cvss_editor` recomputed from form (radio values `AV`…`A`, `reason_<KEY>` fields, optional `paste` field: when non-empty it is `ParsePartial`-ed and overrides the radios; parse error shown in the editor)
  - `POST /cvss` → save (`vector` built from radios, reasons from `reason_<KEY>` for non-standard metrics only, hidden `base` = `CVSSHash`); `action=clear` clears. 409/400 re-render editor keeping input (same pattern as `sectionSave`).
  - `POST /severity` → `UpdateSeverity`, returns `cvss_panel`.
- View model `type cvssView struct` with: `Metrics []cvssMetric{Key, Name, Values []cvss.Value, Selected, Standard string, NonStandard bool, Reason string}`, `Vector, Score, Rating, Foreign, Error, Base string`, `Complete bool`, `Missing []string` (names of non-standard metrics without reason), `Reasons []cvssReason{Metric, Value, Reason string}` (only non-standard metrics, for the read table), `Severity string`, `Severities []string`, URLs.
- Read panel shows: score + rating pill + vector; the reasoning table ("Metric | Value | Reason") only when there are non-standard metrics; missing reason cell shows `reason missing` with class `error`; a warning line when `Missing` non-empty; for a foreign value: the raw text and the note `Not a CVSS 3.1 base vector — using the calculator will replace it.`; when no vector: a severity `<select>` posting to `/severity`.
- Editor: per metric a segmented button group (radio inputs inside labels, `title` = full value name, `hx-post` `/cvss/calc` on `change`, `hx-target` the editor section, `hx-swap="outerHTML"`); a reason `<input>` (full width) right under each non-standard metric; live score/rating/vector line; paste box with an "Apply" button; Save (disabled unless `Complete`), Clear, Cancel.
- Finding page header severity pill uses `cvss.Derive`; the old `<code class="cvss">` in the header is removed (the panel shows it). CVSS panel is rendered after the Details panel slot and before prose sections.

- [ ] **Step 1: Write failing tests** (use the existing web test helpers in `server_test.go`/`edit_test.go`)

```go
func TestCVSSCalcLive(t *testing.T)      // POST /cvss/calc with all 8 radios (AC=H) → 200, body contains "7.4", "high", "reason_AC" input
func TestCVSSSave(t *testing.T)          // POST /cvss with radios + reason_AC=race + base → 200 cvss_panel contains "7.4" and "race"; file has cvss + cvss_reasons.AC; git subject "F-001: set CVSS 7.4"
func TestCVSSSaveIncomplete(t *testing.T) // missing A → 400, editor re-rendered, no commit
func TestCVSSConflict(t *testing.T)      // stale base → 409, body contains user's reason text
func TestCVSSMissingReasonWarns(t *testing.T) // save AC=H without reason → 200; panel contains "reason missing"
func TestCVSSPaste(t *testing.T)         // calc with paste="cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h" → "9.8" and radios checked; paste="junk" → error text, 200
func TestFindingForeignCVSS(t *testing.T) // file cvss "8.1", severity medium → GET finding 200, contains "Not a CVSS 3.1 base vector" and pill "medium"
func TestSeverityManual(t *testing.T)    // no vector, POST /severity sev=low → file severity low; with vector → 400
```

- [ ] **Step 2: Run** `go test ./internal/web/` — Expected: FAIL.
- [ ] **Step 3: Implement** handlers in `cvss.go`, templates, CSS: `.seg` segmented group (inline-flex, buttons ≥ 36px tall, checked = accent background), `.metric` row grid (`12em 1fr`), reasoning table uses `.md table` look, `.score` large number.
- [ ] **Step 4: Run** `go test ./...` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(web): CVSS calculator panel and reasoning table`.

---

### Task 7: Web — Details panel, final page order, manual check

**Files:**
- Create: `internal/web/details.go`, `internal/web/templates/details.html` (templates `details_panel`, `details_editor`; added to the shared list in `Server.init`)
- Modify: `internal/web/server.go`, `internal/web/templates/finding.html`, `internal/web/static/style.css`
- Test: `internal/web/details_test.go`

**Interfaces:**
- Consumes: Task 2 `DetailsRows`, Task 4 `UpdateDetails`, `DetailsHash`.
- Produces routes under `/e/{eng}/f/{fid}`: `GET /details`, `GET /details/edit`, `POST /details` (fields `row_0`…`row_4` mapped to `DetailsRows` by index, hidden `base`). Errors: 409 keeps input, same pattern as sections.
- View: a two-column table (row name | value) for every configured row (empty value → muted "—"), then any extra keys under an "Other" subheading (read-only in the editor too). Values rendered as escaped text with `white-space: pre-wrap` (no Markdown). Editor: one labelled `<textarea rows="3">` per row, full width.
- Final page order: header → Details panel → CVSS panel → prose section panels.

- [ ] **Step 1: Write failing tests**

```go
func TestDetailsView(t *testing.T)    // finding page contains "Location", "Business impact", "Row 3" in that order, before "Description"; Details before CVSS
func TestDetailsSave(t *testing.T)    // POST row_0="https://x/login", row_1="Account takeover" → panel shows both; file details.Location set; subject "F-001: edit details"
func TestDetailsEscaped(t *testing.T) // row_0="<script>alert(1)</script>" → response contains "&lt;script&gt;" and not "<script>alert"
func TestDetailsConflict(t *testing.T) // stale base → 409, body contains the typed text
func TestDetailsOtherKeys(t *testing.T) // file has details "Old row: x" → page shows "Other" and "Old row"; save keeps it
```

- [ ] **Step 2: Run** `go test ./internal/web/` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./...` and `gofmt -l /home/plato/Documents/CLAUDE/yars` — Expected: PASS, no files listed.
- [ ] **Step 5: Commit** `feat(web): details table panel`.
- [ ] **Step 6: Manual check.** Rebuild the scratchpad binary (`go build -o <scratchpad>/yars ./cmd/yars`), restart the demo server (TaskStop the old one, start again in background), and in the browser: open a finding, fill Location and Business impact, set a vector by clicking (AC=High) with a reason, paste a vector, clear it and set severity manually. Expected: table, reasoning table and header pill update; `git -C <scratchpad>/data log --oneline -5` shows the four commits.
