# M7 Retests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A director starts a retest from a finished engagement: a new engagement (`type: retest`, `source: <eng>`) with copies of the selected findings, each restarting at draft with a retest result to fill in (fixed / not fixed / partially fixed) and a link to the original. The original engagement is never modified; new findings can be added to the retest normally.

**Architecture:** `store.CreateRetest` writes the new engagement and all copied findings in one commit. The copies carry `retest: {source: <eng>/<dir>, result: ""}`. `workflow.Gate` requires a result for retest findings. `store.SetRetestResult` is a content edit (same lock/clearance rules as other edits). `web` adds a "New retest" form on the engagement page, a Retest panel on retest findings, a Result column in retest tables and a "Retest of …" banner.

**Tech Stack:** Go 1.27, html/template, htmx.

**Spec:** `docs/superpowers/specs/2026-11-03-yars-design.md` (section "Retests"); user: "New engagement with fixed, not fixed, partially fixed. It shouldn't update previous findings. It should allow for creation of new findings, use just old pentest as a starting point."

## Global Constraints
- Result values: `fixed`, `not_fixed`, `partially_fixed`; labels "Fixed", "Not fixed", "Partially fixed". Empty = not yet retested.
- Copy rules: same finding ID and directory name as the original (traceability); `status: draft`; `author` = the user creating the retest; `reviewers`, `cleared_by`, `returned` cleared; title, severity, cvss, cvss_reasons, details, all sections copied verbatim; `retest: {source: "<srcEng>/<dir>", result: ""}`; chat and attachments are not copied (ruling: the retest starts a new discussion; evidence of the original stays linked).
- Only director/admin create retests (same as engagements). Source must exist; at least one finding selected; new engagement ID must be new and valid.
- New findings created in a retest engagement get the next free number (normal `CreateFinding`) and no `retest` field.
- Commit: `engagement <new>: retest of <src> (N findings)` — one commit for everything.
- Gate addition: a finding with a `retest` field needs a valid result before submit/approve ("set the retest result").
- `SetRetestResult` commit: `F-001: retest result fixed`; refuses invalid values (ErrInvalidValue) and findings without a `retest` field.
- Original engagement files byte-identical after a retest is created (test asserts).
- Shell usage: Write/Edit for files; single plain commands.

## Review Focus
1. Creating a retest must not touch a single byte of the source engagement (Task 1 `TestRetestLeavesSourceUntouched`).
2. Retest of a retest: source is itself a retest — copies must point at the immediate source and drop the old result (Task 1 `TestRetestOfRetest`).
3. Duplicate/invalid new engagement ID, empty selection, or a selected dir that doesn't exist in the source: error, nothing written (Task 1 `TestCreateRetestValidation`).
4. Pushing a retest via git (M6 policy): a new finding with status draft and a `retest` field is accepted; result changes are ordinary edits (Task 1 `TestRetestPolicyCompatible`).
5. Submitting a retest finding without a result is blocked with a clear message (Task 1 `TestGateNeedsRetestResult`).

---

### Task 1: Store + workflow

**Files:** Modify `internal/store/store.go`, `internal/workflow/workflow.go`; Tests `internal/store/retest_test.go`, `internal/workflow/workflow_test.go`, `internal/policy/policy_test.go`.

**Interfaces — Produces:**
- `var RetestResults = []string{"fixed", "not_fixed", "partially_fixed"}` and `func RetestLabel(string) string` in workflow.
- `func (s *Store) CreateRetest(e Engagement, source string, dirs []string, u config.User) error` — e.Type forced to `retest`, e.Source = source.
- `func (s *Store) SetRetestResult(engID, dir, result string, a Actor) error`.
- Gate: `retest` present and result not in RetestResults → "set the retest result (fixed, not fixed or partially fixed)".

- [ ] **Step 1: Failing tests** — `TestCreateRetest` (2 of 3 findings copied; meta as in constraints; engagement.yaml type retest/source; one commit with subject), `TestRetestLeavesSourceUntouched` (hash of every source file before/after), `TestRetestOfRetest`, `TestCreateRetestValidation`, `TestSetRetestResult` (valid → commit subject; "maybe" → ErrInvalidValue; non-retest finding → ErrInvalidValue), `TestGateNeedsRetestResult`, `TestRetestPolicyCompatible` (policy: push of a retest finding's result change by its author is accepted).
- [ ] **Step 2–4:** FAIL → implement → `go test ./...` PASS.
- [ ] **Step 5: Commit** `feat(store): retests from finished engagements`.

---

### Task 2: Web — new retest form, retest panel, result column, banner; manual check

**Files:** Create `internal/web/retest.go`, `internal/web/templates/new_retest.html`, `internal/web/templates/retest.html` (template `retest_panel`, shared); Modify `server.go`, `engagement.html`, `finding.html`, `partials.html`, `index/index.go` (`Row.RetestResult`), `style.css`; Test `internal/web/retest_test.go`.

**Interfaces:**
- Routes: `GET /e/{eng}/retest/new` (director/admin; form: new ID prefilled `<eng>-retest`, name prefilled "<name> — retest", start/end, checkbox per source finding with ID/title/status/severity, checked by default for complete/reported findings), `POST /e/{eng}/retest/new` → 303 to the new engagement; `POST /e/{eng}/f/{fid}/retest` (field `result`) → renders `retest_panel` (403 when locked, 400 invalid).
- Engagement page: "New retest" button (director/admin); for retest engagements a banner "Retest of <source name>" linking to the source.
- Findings table: in retest engagements an extra "Result" column (pill: green fixed, red not fixed, amber partially fixed, muted "—" when empty; empty for new findings without `retest`).
- Retest panel (top of main column, retest findings only): segmented buttons Fixed / Not fixed / Partially fixed (htmx post on click), link "Original: <src>/<ID>" to the source finding with its final status and severity.

- [ ] **Step 1: Failing tests** — `TestNewRetestFlow` (dora GETs form: lists findings, complete ones checked; POSTs with two dirs → 303, new engagement page shows banner and both findings; alice gets 403 on the form), `TestRetestPanel` (alice sets result "partially_fixed" → panel shows it selected; table shows the pill), `TestRetestPanelLocked` (complete retest finding → 403 for pentester).
- [ ] **Step 2–4:** FAIL → implement → `go test ./...`, `gofmt -l .` PASS.
- [ ] **Step 5: Commit** `feat(web): retests — form, panel, result column`.
- [ ] **Step 6: Manual check** — on the demo: dir1 creates a retest of the ACME engagement with F-001/F-003; pen1 sets results, adds a new finding, submits one; the original engagement's git history shows no new commits touching its files.
