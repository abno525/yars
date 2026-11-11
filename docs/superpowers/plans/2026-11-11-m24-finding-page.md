# M24 — finding page: Checks strip, one error count, side column, status in chat

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Read `2026-11-11-yars-roadmap-to-v1.md` first. Steps use checkbox (`- [ ]`) syntax.

**Goal:** the finding's text comes first on its page. Checks become a closed strip at the bottom, problems are counted once, and status changes are read in the chat.

**Architecture:** template and view-model changes in `internal/web` only; the store is not touched. The Checks panel becomes a `<details>` element whose open state the server decides and the browser remembers per finding. The workflow gate's own problems ("assign at least one reviewer") become rows of the Checks table, so there is one list and one count. The separate Status panel goes; its events are drawn in the chat timeline, which already carries them.

**Spec:** `docs/open-decisions-2026-11-07.md` D2, D3, D4 (items 1, 3, 4, 5), D21, D22 (answer: keep two rows). Roadmap question 3: check threads are kept.

**Branch:** `pr/18-finding-page` from `pr/17-catch-up`.

**Gate:** the canvas boards of row 3 (Finding) are redrawn to this plan and signed off: 3.1 finding page with the strip closed, 3.2 strip open with results, 3.3 strip while a check runs, 3.4 side column with Possible duplicates and the chat with status events, 3.5 workflow bar (two rows, no error list), 3.6 retest with Original collapsed, 3.7 Attachments panel. Pixel values in the code come from those boards.

## Review focus

1. A live refresh must not close a strip the user opened, nor open one the user closed, except while a check runs (task 1).
2. The count in the workflow bar and the rows of the strip must always be the same number (task 2 `TestOneErrorCount`).
3. A viewer who cannot submit must not see "errors to fix" (existing rule; task 2 keeps it).
4. A long chat with many status events must still load the newest 50 messages first (task 4).
5. A dismiss reason form open in the strip must survive a live refresh (existing guard in `app.js:253`; task 1 keeps the `#checks` id).

## File structure

| File | Change |
|---|---|
| `internal/web/checks.go` | `checksView.Open`, `Running` attribute, gate rows |
| `internal/web/templates/checks.html` | the panel becomes a `<details>` strip |
| `internal/web/templates/finding.html` | order of the page; More menu; duplicates to the side; Attachments panel; no `activity` |
| `internal/web/workflow.go`, `templates/workflow.html` | no gate list; the state text is a button; one count |
| `internal/web/chat.go`, `templates/chat.html` | events inline; `activity` removed |
| `internal/web/templates/retest.html` | Original collapsed |
| `internal/web/static/app.js`, `style.css` | strip memory; open-checks button |

---

### Task 1: the Checks strip (D2)

**Files:** modify `internal/web/checks.go` (`checksView`, `checksFor`), `internal/web/templates/checks.html:3-76`, `internal/web/templates/finding.html:31-38`, `internal/web/static/app.js`, `internal/web/static/style.css`, `internal/web/checks_test.go`

**Interfaces produced:**

```go
// checksView gains:
	Open bool // the strip starts open: a check is running, or the author's draft has errors
```

Rules:
1. `Open = v.Running || (m.Status == "draft" && u.Username == m.Author && v.Errors > 0)`.
2. `finding.html`: remove `{{template "checks_panel" .Checks}}` from the top of `.finding-main` and put `{{if not $wd}}{{template "checks_panel" .Checks}}{{end}}` after `{{range .Panels}}…{{end}}` (and after the Attachments panel of task 5). The template still renders nothing when `.Enabled` is false (no rules).
3. `checks.html`: `<section class="panel checks…" id="checks" …>` becomes `<details class="panel checks strip{{if .Empty}} empty{{end}}" id="checks"{{if .Open}} open{{end}}{{if .Running}} data-running{{end}} …>` with the same `hx-*` and `data-sse` attributes; `<div class="panelhead">` becomes `<summary class="panelhead">`. The strip's closed height is 48 px.
4. `app.js`: remember the user's choice per finding and re-apply it after every swap of `#checks`:

```js
// Checks strip: the server opens it while a check runs or the author's
// draft has errors; a click on its head is the user's choice, kept for this
// finding in this tab and re-applied after live refreshes (never against a
// running check, which stays open).
function yarsChecksKey() { return 'yars-checks:' + location.pathname; }
function yarsChecksApply() {
  var d = document.getElementById('checks');
  if (!d || d.tagName !== 'DETAILS' || d.hasAttribute('data-running')) return;
  var want = null;
  try { want = sessionStorage.getItem(yarsChecksKey()); } catch (e) { return; }
  if (want === 'open') d.open = true;
  if (want === 'closed') d.open = false;
}
document.addEventListener('click', function (evt) {
  var s = evt.target.closest && evt.target.closest('#checks > summary');
  if (!s) return;
  // the click toggles after this handler: the state it leads to
  try { sessionStorage.setItem(yarsChecksKey(), s.parentNode.open ? 'closed' : 'open'); } catch (e) { /* not kept */ }
});
document.addEventListener('DOMContentLoaded', yarsChecksApply);
document.addEventListener('htmx:afterSwap', function (evt) {
  if (evt.detail.target && evt.detail.target.id === 'checks') yarsChecksApply();
});
```

- [x] **Step 1: write the failing tests** (`checks_test.go`; add a rule file as the existing checks tests do).
  - `TestChecksStripClosedByDefault`: as `bob` on a draft with one rule error, `id="checks"` is a `<details` without ` open`.
  - `TestChecksStripOpenForAuthorWithErrors`: as `alice` (author) the same page has `<details … open`.
  - `TestChecksStripOpenWhileRunning`: with a run in progress (a linter that blocks on a channel, as `checks_test.go` already does) the strip has `open` and `data-running` for every viewer.
  - `TestChecksStripAfterSections`: in the page, the index of `id="checks"` is after the index of the last `<section class="panel" id="s-`.
  - `TestChecksStripHiddenWhenWithdrawnOrNoRules`: no `id="checks"` on a withdrawn finding; none without rules.
  - `TestAppJSRemembersChecksStrip`: `app.js` contains `yars-checks:` and `data-running`.
- [x] **Step 2:** run `go test ./internal/web -run ChecksStrip`. Expected: FAIL. **Step 3:** implement. **Step 4:** run `go test ./internal/web`. Fix tests that look for `<section class="panel checks`.
- [x] **Step 5: browser check:** close the strip, change the finding in a second session: it stays closed; press Check: it opens and, when the run ends without errors, returns to closed; open a Dismiss reason form and trigger a refresh: the form stays.
- [x] **Step 6:** commit: `feat(finding): Checks is a closed strip under the text (D2)`.

### Task 2: one list of problems, one count (D3)

**Files:** modify `internal/web/checks.go` (`checksFor`), `internal/web/workflow.go:147-221,277-325`, `internal/web/templates/workflow.html:36,69`, `internal/web/static/app.js`, `internal/web/workflow_test.go`, `internal/web/checks_test.go`

Rules:
1. `checksFor` adds one row per item of `workflow.Gate(ref.F.Meta, s.conf())` for a finding in `draft` or `verification`: `checkRow{Level: "error", Rule: "workflow", Message: <item>, Where: "Workflow", CanDismiss: false}`, placed before the rule rows and counted in `Errors`. An item that starts with `explain the non-standard CVSS value for ` is skipped when an enabled rule has `Check == "cvss-explained"` (that rule reports the same thing).
2. `workflow.html`: delete line 69 (`{{if .Gate}}<ul class="gate">…{{end}}`).
3. `wfView` gains `Problems int`. `wfGated` sets it to `checks.Errors` when `wf.HasGated`. In `arrange`, the first case of the state switch becomes `case v.Problems > 0 && v.HasGated: v.State, v.StateError = plural(v.Problems, "error")+" to fix", true`.
4. `workflow.html:36`: when `.StateError` or `.OpenWarnings`, the state is a button: `<button type="button" class="wfstate{{if .StateError}} error{{end}}" id="wf-state" data-open-checks title="{{.State}}">{{.State}}</button>`; otherwise the existing `<span>`. Same box, same place.
5. `app.js`: a click on `[data-open-checks]` sets `#checks` open, stores `open` under `yarsChecksKey()` and calls `scrollIntoView({block: 'nearest'})`.
6. Check results keep opening one chat thread per new violation (`store.finishCheck` is not changed).

- [x] **Step 1: write the failing tests.**
  - `TestGateProblemsAreCheckRows`: a draft without reviewers: the strip has a row with `Workflow` and `assign at least one reviewer`, with no Dismiss button.
  - `TestNoGateListUnderBar`: the finding page has no `class="gate"`.
  - `TestOneErrorCount`: a draft without reviewers and with one rule error: the bar says `2 errors to fix` and the strip's Errors badge says `2`.
  - `TestCVSSProblemListedOnce`: with the example rule `check: cvss-explained` enabled and a non-standard CVSS value without a reason, the strip has exactly one row about it.
  - `TestStateIsButtonOnlyWithProblems`: `data-open-checks` is present with errors, absent on a clean draft.
- [x] **Step 2–4:** fail, implement, pass (`go test ./internal/web`; update tests that assert the gate list).
- [x] **Step 5:** commit: `feat(finding): problems are listed once, in Checks (D3)`.

### Task 3: title row and side column (D4 items 1 and 3)

**Files:** modify `internal/web/templates/finding.html:18-24,31-42`, `internal/web/static/style.css`, `internal/web/finding_ui_test.go`

Rules:
1. The title-row buttons become three fixed slots: **More** (w136), **History** (w136), **Export** (w136). More is `<details class="pop more"><summary class="btn secondary w136">More</summary><div class="poplist">…</div></details>` holding the links "Merge into" and "Save as template", each only when the viewer may use it (`.CanMerge`, `.Tpl.CanEdit`). With neither, an empty `<span class="slot w136"></span>`. The old w152 slot goes.
2. `{{if .Dups.Rows}}{{template "dups_panel" .Dups}}{{end}}` moves from `.finding-main` to the top of `.side`, above the chat. The panel gets the class `compact`; its columns are those of board 3.4.

- [x] **Step 1: write the failing tests.** `TestMoreMenuHoldsMergeAndTemplate` (as `dora`: both links are inside `class="pop more"`; no `w152` in the title row); `TestMoreSlotEmptyWithoutRights` (a viewer with neither right gets the empty slot); `TestDuplicatesInSideColumn` (the index of the duplicates panel is after the index of `class="side"`).
- [x] **Step 2–4:** fail, implement, pass. **Step 5:** commit: `feat(finding): More menu; Possible duplicates in the side column (D4)`.

### Task 4: status changes in the chat (D21)

**Files:** modify `internal/web/chat.go` (`chatView`, the function that builds it), `internal/web/templates/chat.html:25-36,42-43,92`, `internal/web/templates/finding.html:40`, `internal/web/chat_test.go`, `internal/web/static/style.css`

Rules:
1. `chatView.Items` holds the timeline in order with both kinds: an item has `Event` or `Thread` (the type `chatItem` already has both fields). The fields `Events` and `OOB` are removed, and so are the `activity` template, its include in `finding.html` and the out-of-band line `{{if .OOB}}{{template "activity" .}}{{end}}`.
2. `chat_list` draws an event as: `<div class="chatev ev-{{.Kind}}"><span class="what"><strong>{{.User}}</strong> {{.What}}{{if .Text}}: <span class="text">{{.Text}}</span>{{end}}</span><span class="time">{{.Time}}</span></div>`.
3. The tail rule stays "the newest 50 messages, whole threads": events do not count towards the 50; an event is shown when it is newer than the oldest shown thread, and older events are behind "Show older (N)", where N still counts messages.

- [x] **Step 1: write the failing tests.**
  - `TestStatusEventsInChat`: after Submit, the chat list has `class="chatev ev-submit"` with `submitted it for verification`; the page has no `id="activity"`.
  - `TestChatOrderMixesEventsAndThreads`: comment, submit, comment: the three appear in that order in `#chat-list`.
  - `TestChatTailCountsMessagesOnly`: 60 messages and 30 events: `Show older (10)`.
  - `TestReturnReasonShownInChat`: after Return with a reason, the event row holds the reason.
- [x] **Step 2–4:** fail, implement, pass (update tests that read the Status panel). **Step 5:** commit: `feat(finding): status changes are read in the chat (D21)`.

### Task 5: retest Original collapsed; Attachments panel (D4 items 4 and 5)

**Files:** modify `internal/web/templates/retest.html:4-19`, `internal/web/templates/finding.html`, `internal/web/templates/assets.html` or a new template block `attachments_panel` in `finding.html`, the finding handler (sets `page.Attach`), `internal/web/retest_ui_test.go`, `internal/web/editstates_test.go`

**Interfaces produced:** `page.Attach *attachView` (filled with the existing `s.attachFor(ref)`).

Rules:
1. `retest.html`: `<section class="panel compact orig">` becomes `<details class="panel compact orig">` and its `<div class="panelhead">` becomes `<summary class="panelhead">` (the Open link stays in it). Closed by default.
2. New block, placed after the text sections and before the Checks strip:

```html
{{define "attachments_panel"}}
<section class="panel compact" id="attachments">
  <div class="panelhead"><h2>Attachments <span class="qcnt{{if not .Items}} zero{{end}}">{{len .Items}}</span></h2></div>
  <table class="table stable atttable flush">
    <thead><tr><th>Name</th><th class="c-kind">Type</th><th class="c-size">Size</th><th class="c-act">Action</th></tr></thead>
    <tbody>
      {{range .Items}}<tr><td class="mono clip" title="{{.Name}}">{{.Name}}</td><td>{{.Kind}}</td><td class="mono">{{.Size}}</td><td><a class="btn ghost sm w96" href="{{.URL}}">Open</a></td></tr>
      {{else}}{{template "empty_row" 4}}{{end}}
    </tbody>
  </table>
</section>
{{end}}
```

- [ ] **Step 1: write the failing tests.** `TestRetestOriginalCollapsed` (the retest page has `<details class="panel compact orig"` without ` open`); `TestAttachmentsPanelListsFiles` (after an upload the panel has the file's name, `PNG` and an Open link); `TestAttachmentsPanelEmptyRow`.
- [ ] **Step 2–4:** fail, implement, pass. **Step 5:** commit: `feat(finding): Original starts collapsed; attachments are listed on the page (D4)`.
- [ ] **Step 6: browser check** of the whole page against boards 3.1–3.7 at 1440 × 900, light theme. Push the branch and open PR #18 (title `Finding page: Checks strip, one error count, status in chat`).
