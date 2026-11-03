# M3 Workflow, reviewers, inbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Findings move draft → verification → complete → reported under role rules, with reviewer assignment, recorded reviewer "clear", a return-to-draft reason, locked editing after approval, and an inbox.

**Architecture:** A pure `internal/workflow` package holds every rule (who may do which transition, the submit gate, who may edit/assign, inbox classification) so web, pre-receive (M6) and MCP (M9) share it. `store` gains `Transition` and `SetReviewers` (one commit each) and resets clearances when content changes during verification. `web` adds a workflow bar on the finding page, reviewer checkboxes, an `/inbox` page and a topbar badge, and enforces edit permissions server-side.

**Tech Stack:** Go 1.27, net/http, html/template, htmx 2.0.4, yaml.v3.

**Spec:** `docs/superpowers/specs/2026-11-03-yars-design.md` (section "Workflow & roles"), plus `docs/superpowers/specs/2026-11-03-yars-cvss-details-design.md` (missing CVSS explanations block at the verification gate).

## Global Constraints
- Statuses: `draft`, `verification`, `complete`, `reported`. Roles: `pentester`, `reviewer`, `director`, `admin` (admin may do everything).
- Transitions (action → from → to, who):
  - `submit`: draft → verification; the finding's author, director, admin. Gate must pass.
  - `return`: verification → draft; an assigned reviewer, director, admin; non-empty reason required.
  - `clear`: stays verification; an assigned reviewer who is not the author and has not cleared yet (director/admin may also clear).
  - `approve`: verification → complete; director, admin; ≥1 entry in `cleared_by`.
  - `reopen`: complete → verification; director, admin; empties `cleared_by`.
  - `report`: complete → reported; director, admin (used by exporters in M8; no UI button in M3).
- Submit gate (all must hold): ≥1 reviewer; title non-empty; a valid CVSS vector or a severity; no non-standard CVSS metric without an explanation.
- Front matter: `cleared_by: [names]`, `returned: {by: name, reason: text}` (set on return, removed on submit). `submit` also empties `cleared_by`.
- Editing content (sections, details, CVSS, severity): anyone in draft/verification; only director/admin in complete/reported. Any content edit during verification empties `cleared_by`.
- Assigning reviewers: author, director, admin; in draft or verification; candidates = users with role reviewer or director; the author can't be a reviewer. Removing a reviewer removes their clearance.
- Commit messages: `F-001: submit for verification`, `F-001: return to draft` (reason in body), `F-001: cleared by bob`, `F-001: approve`, `F-001: reopen`, `F-001: mark reported`, `F-001: set reviewers bob, carol`.
- Permission checks live in `workflow`; `store.Transition` enforces them; web handlers enforce edit/assign permissions before calling the store (403).
- Shell usage: Write/Edit for files; single plain commands (`go test ./...`, `git -C /home/plato/Documents/CLAUDE/yars ...`), no pipes, heredocs, `cd`, chains.

## Review Focus
1. The author clearing their own finding, or an unassigned reviewer clearing: refused (Task 1 `TestCheckMatrix`).
2. Content edited after a clearance during verification: clearances reset, so the director can't approve text nobody reviewed (Task 2 `TestEditResetsClearances`).
3. A complete finding edited by a direct POST (no button): 403, no commit (Task 4 `TestLockedEditForbidden`).
4. A reviewer removed after clearing: their clearance disappears (Task 2 `TestSetReviewersDropsClearance`).
5. Return with an empty/whitespace reason: refused, no commit (Task 2 `TestTransitionReturnNeedsReason`).

---

### Task 1: `internal/workflow` rules

**Files:** Create `internal/workflow/workflow.go`, `internal/workflow/workflow_test.go`.

**Interfaces:**
- Consumes: `config.User`, `config.Config`, `finding.Meta` (adds fields in Task 2 — define them in Task 1 already: `ClearedBy []string yaml:"cleared_by,omitempty"`, `Returned *Returned yaml:"returned,omitempty"`, `type Returned struct{ By, Reason string }` with yaml tags `by`, `reason`, in `internal/finding/finding.go`), `cvss.Parse`.
- Produces:
  - `type Action string`; consts `Submit, Return, Clear, Approve, Reopen, Report`
  - `var Actions = []Action{Submit, Return, Clear, Approve, Reopen, Report}`
  - `func Target(a Action) (from, to string)` (Clear: verification → verification)
  - `func Check(u config.User, m finding.Meta, a Action) error` — status + role rules; errors are `*Denied{Reason string}` (implements error)
  - `func Gate(m finding.Meta, cfg config.Config) []string` — human-readable blocking problems for submit (empty = OK)
  - `func CanEdit(u config.User, m finding.Meta) bool`
  - `func CanAssign(u config.User, m finding.Meta) bool`
  - `func ReviewerCandidate(u config.User, m finding.Meta) bool` — role reviewer|director and not the author
  - `type Inbox string`; consts `InboxNone=""`, `InboxReview="review"`, `InboxApprove="approve"`, `InboxReturned="returned"`
  - `func Pending(u config.User, m finding.Meta) Inbox` — review: verification, u in reviewers, not in cleared_by; approve: u director/admin, verification, cleared_by non-empty; returned: draft, u is author, Returned != nil.
  - `func Label(a Action) string` — button text: "Submit for verification", "Return to draft", "Clear", "Approve", "Reopen", "Mark reported"

- [ ] **Step 1: Failing tests** — `TestCheckMatrix` (table: user role/name × status × action → allowed?; covers every row in Global Constraints incl. author can't clear own finding, unassigned reviewer can't clear, approve without clearances denied, admin allowed everywhere the status matches, wrong-status always denied); `TestGate` (no reviewers → mentions "reviewer"; empty title; no vector and no severity; CVSS `AC:H` without `cvss_reasons.AC` → mentions "Attack Complexity"; complete valid meta → empty); `TestCanEdit` (draft/verification anyone; complete pentester false, director true); `TestCanAssign`; `TestPending` (one case per inbox kind + none).
- [ ] **Step 2: Run** `go test ./internal/workflow/` — Expected: FAIL (undefined).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./internal/workflow/ ./internal/finding/` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(workflow): status transition rules, gate, permissions`.

---

### Task 2: Store transitions, reviewers, clearance reset

**Files:** Modify `internal/store/store.go`; Test `internal/store/workflow_test.go`.

**Interfaces:**
- Consumes: Task 1.
- Produces:
  - `type Denied` errors from workflow pass through (`errors.As(err, &*workflow.Denied)`); gate failures return `*workflow.Denied` with the problems joined by "; ".
  - `func (s *Store) Transition(engID, dir string, act workflow.Action, reason string, u config.User) error` — Check, (Submit: Gate), (Return: reason trimmed non-empty else Denied), then field updates: status; Submit → delete `cleared_by`, delete `returned`; Return → `returned: {by, reason}`, delete `cleared_by`; Clear → append u to `cleared_by`; Approve → status only; Reopen → delete `cleared_by`; Report → status. Commit message per Global Constraints; for Return the reason goes in the commit body (`msg + "\n\n" + reason`).
  - `func (s *Store) SetReviewers(engID, dir string, names []string, u config.User) error` — `workflow.CanAssign` else Denied; dedupe, sort, drop author; set `reviewers`; filter `cleared_by` to remaining names; msg `set reviewers a, b` (or `set reviewers (none)`). Name validity against the user list is the caller's job.
  - Content edits (`UpdateSection`, `UpdateCVSS`, `UpdateSeverity`, `UpdateDetails`): when the finding is in `verification` and the edit changes the file, delete `cleared_by` in the same commit.
  - `author(u config.User) gitrepo.Author` helper moved/duplicated into store as `AuthorOf(u config.User) gitrepo.Author` (web uses it too).

- [ ] **Step 1: Failing tests** — `TestTransitionSubmitGate` (no reviewers → Denied mentioning reviewer, no commit; with reviewers + severity → status verification, subject `F-001: submit for verification`); `TestTransitionFlow` (submit → clear by bob → approve by dora → status complete; `cleared_by: [bob]`; subjects); `TestTransitionReturnNeedsReason` ("  " → Denied, no commit; "fix steps" → status draft, `returned.reason`, commit body contains reason); `TestEditResetsClearances`; `TestSetReviewersDropsClearance`; `TestSetReviewersDropsAuthor`.
- [ ] **Step 2: Run** `go test ./internal/store/` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./...` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(store): workflow transitions and reviewer assignment`.

---

### Task 3: Finding page workflow bar, reviewers, locked editing

**Files:** Create `internal/web/workflow.go`, `internal/web/templates/workflow.html` (templates `workflow_bar`; shared list); Modify `server.go`, `edit.go`, `cvss.go`, `details.go`, `finding.html`, `partials.html`, `cvss.html`, `details.html`, `style.css`, `internal/auth/auth.go` (`func (a *Auth) Users() []config.User`, sorted by username); Test `internal/web/workflow_test.go`.

**Interfaces:**
- Routes: `POST /e/{eng}/f/{fid}/action/{act}` (form `reason`), `POST /e/{eng}/f/{fid}/reviewers` (repeated `reviewer` fields). Both are plain form posts answered with 303 to the finding page; a `*workflow.Denied` re-renders the finding page with status 400 and the message in a `.error` banner (`page.Error`).
- `type wfView struct{ Status string; Steps []string; Actions []wfAction{Act, Label string; Needs Reason bool}; Gate []string; Reviewers []wfReviewer{Name string; Cleared bool}; Candidates []wfCandidate{Name string; Checked bool}; CanAssign bool; Returned *finding.Returned }` in `page.WF`.
- Workflow bar (under the title): step chips draft → verification → complete → reported with the current one highlighted; one button per allowed action (`workflow.Check` nil); `return` shows a reason textarea in its form; when `submit` is allowed by role but the gate fails, the button is disabled and the gate problems are listed; reviewers listed with ✓ for cleared; when `CanAssign`, a "Reviewers" details/summary with checkboxes of candidates; a banner with `returned.by` and reason when present.
- Locked editing: `!workflow.CanEdit` → section panels, details and CVSS panels render without Edit buttons (`panel.EditURL == ""`, `Locked` flag on cvss/details views, severity select hidden) and every content POST/GET-edit route answers 403.
- Reviewer names posted are validated against `Auth.Users()` candidates (unknown → 400).

- [ ] **Step 1: Failing tests** — `TestWorkflowButtonsByRole` (draft finding by alice: alice sees "Submit for verification" disabled with "reviewer" problem; bob sees no submit); `TestSubmitAndClearFlow` (alice assigns bob via POST reviewers; sets severity; submits → 303, status verification; bob page shows "Clear" and "Return to draft"; bob clears → ✓; dora approves → complete); `TestReturnRequiresReason` (empty → 400 page with error; with reason → draft + banner on page); `TestLockedEditForbidden` (complete finding: pentester GET section edit → 403, POST section/cvss/details/severity → 403, page has no Edit buttons; director can edit); `TestReviewersRejectUnknown` (POST reviewer=mallory → 400).
- [ ] **Step 2: Run** `go test ./internal/web/` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./...` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(web): workflow bar, reviewer assignment, locked editing`.

---

### Task 4: Inbox page and badge, manual check

**Files:** Modify `internal/index/index.go` (`Row.Meta finding.Meta`), `server.go` (route `GET /inbox`, `page.InboxCount`, `page.Inbox map`), Create `internal/web/templates/inbox.html`, Modify `layout.html`, `style.css`; Test `internal/web/inbox_test.go`.

**Interfaces:**
- `Row.Meta` carries the parsed meta so `workflow.Pending` can classify rows.
- `/inbox`: three lists across all engagements — "Awaiting my review", "Ready to approve", "Returned to me" — each row: engagement name, ID, title, severity pill, link. Empty state per list.
- Topbar: "Inbox" link with a count badge (sum of the three lists) for every page that has a user (`base()` computes it).

- [ ] **Step 1: Failing tests** — `TestInboxLists` (finding in verification with bob as reviewer: bob's inbox lists it under "Awaiting my review", badge "1"; after bob clears: bob's list empty, dora's "Ready to approve" lists it; after dora returns with reason: alice's "Returned to me" lists it).
- [ ] **Step 2: Run** `go test ./internal/web/` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./...` and `gofmt -l .` — Expected: PASS, nothing listed.
- [ ] **Step 5: Commit** `feat(web): inbox and badge`.
- [ ] **Step 6: Manual check** — add demo users `pen1` (pentester) and `rev1` (reviewer) with password `pw` via `yars useradd`, restart the demo server, and walk one finding draft → verification → cleared → complete with three logins; return once with a reason; confirm inbox badges and that the complete finding has no Edit buttons. `git log` of the data repo shows each step authored by the acting user.
