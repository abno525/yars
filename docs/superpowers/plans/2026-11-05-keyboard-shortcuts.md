# Keyboard shortcuts — most actions without a mouse

**Goal:** every common flow in YARS can be done with the keyboard alone, using the controls that already exist. No new flows: a shortcut only focuses or clicks a control the server already rendered for this user and state.

**Status:** research and plan only. No code has been changed. The open questions at the end need answers before work starts.

**Already decided by the user**
- **E** opens edit mode on the finding page.
- **Ctrl+S** saves and leaves edit mode. The browser's "Save page" dialog is suppressed.

---

## 1. Inventory: what exists today

### Shell (layout.html, app.js)
| Control | Keyboard today |
|---|---|
| Logo, nav links (Findings, Inbox, Admin, Developers), bell, user link, theme button, Log out | Reachable with Tab. Links and buttons use the browser's default focus ring; style.css has no `:focus-visible` rule for `.btn` or `a`. |
| Engagement picker `select.engpick` (`onchange="this.form.submit()"`) | **Problem:** in Chrome on Linux and Windows, ArrowUp/ArrowDown on a closed select changes its value and fires `change`, so the page leaves on the first arrow press. |
| Go to palette `dialog#goto` | **Ctrl+K / Cmd+K** opens it (app.js:126). Up/Down select, Enter opens, Esc closes (native dialog). The `Ctrl K` `<kbd>` in the header is the only shortcut shown in the UI. |
| Toasts | `aria-live`, click to dismiss. Not focusable. This is fine. |
| `beforeunload` guard | Runs when a `form[data-guard]` has text that differs from what the server sent (`yarsDirty`). `htmx:confirm` asks "Discard changes?" on `[data-guard-cancel]`. |

### Engagements list `/` (engagements.html)
- A table of name links and a "New engagement" link. Tab works. There are no row shortcuts.

### Findings board `/e/{eng}` (engagement.html, partials.html `findings`)
- Engagement tabs `nav.etabs` (Findings · N, Overview, Report, Settings) are links.
- Status filter `nav.seg` links use `hx-get` with target `#findings`, `outerHTML` and `hx-push-url`. **Focus is lost after the swap** because the links have no ids.
- Sortable column header links do the same swap and also lose focus.
- In each row, the ID link and the title link open the finding. There is no row selection.
- "Load N more" button: swaps `#findings-more`, and focus is lost.
- Header buttons: Export, New retest, New finding / Reopen.
- Clone "Copy" button (`data-copy`).

### Finding page `/e/{eng}/f/{fid}` (finding.html)
Panels in DOM order: workflow bar → retest panel → checks → duplicates → details → assets → CVSS → text sections (`panel` template) | side column: Status (activity), Chat.

| Area | Controls | Keyboard today / issues |
|---|---|---|
| Title row | Merge into, Save as template, History, Export (links) | Tab |
| **Workflow bar** `#workflow` (workflow.html, workflow.go `wfLayout`) | One fixed slot per status. draft: Withdraw, Submit. verification: Withdraw, Return, Sign off (`clear`), Approve. complete: Withdraw, Reopen, Mark reported (`report`). reported: Withdraw. withdrawn: Restore (`revise`). Immediate actions are plain `POST` forms (full page load, no confirm). Return and Withdraw toggle a reason form (`data-reason-toggle`), which focuses its textarea. Reviewer chips `+N` and the **reviewer picker** are `details.pop` with checkboxes, **Assign all** and **Save**. **Check** (`hx-post`, target `#workflow`). | Tab works. Esc does **not** close popovers or reason forms; they close only on an outside click or Cancel. **SSE refreshes `#workflow` with `outerHTML`**, and the buttons have no ids, so a focused button loses focus. The `htmx:beforeSwap` busy guard only protects typed text and open panels. Clicking Check replaces the button with a disabled "Checking" button, which also loses focus. |
| Retest result | `form.result-seg` radios, `hx-trigger=change`, swaps `#retest` | Arrow keys change the value. The radios have no ids, so **focus is lost after every arrow press**. |
| Checks `#checks` | Dismiss toggles a reason row (focuses the input), Cancel, Dismiss (htmx), Restore, Retry, the Dismissed `<details>` | Tab works. Esc is not handled. Focus is lost after dismiss or restore. The panel is refreshed by SSE. |
| Duplicates | Links and Merge links | Tab |
| Details `#details` | Edit → `details_editor` (`data-guard`, textareas). Save/Cancel use htmx. | The editor has no autofocus, so after Edit focus is lost. After Save or Cancel focus is lost too. |
| Assets `#assets` | Edit → editor with **Add row**/✕ (each re-renders the whole editor) | Focus is lost after every Add row or Remove. |
| CVSS `#cvss` | Edit/Calculate → `cvss_editor`. Each metric is a radio seg with ids `cvss-AV-N`. `hx-trigger=change` recalculates by swapping `#cvss`. Paste input (Enter applies). Reasoning textareas. Clear vector, Cancel, Save (disabled until complete). Without a vector: a Severity `<select>` with `hx-trigger=change`. | Radios keep focus after a swap because htmx 2 refocuses an element with the same id. The paste input has no id, so focus is lost after Apply. The Severity select saves on every arrow press in Chrome, the same problem as the engagement picker. **Pitfall:** the first submit button in the editor form is **Clear vector**. Any scripted submit must pass the Save button as the submitter. |
| Text sections (`panel` / `editor` in partials.html) | Comment (`yarsComment` points the composer at the section), Edit (htmx GET → editor). The editor has Write/Split/Preview, a textarea with `autofocus`, attachments (Add file is a file input inside a label, Insert, Redact), Restore draft, Cancel (`data-guard-cancel`), Save. A conflict state adds Show diff, Take theirs and Keep mine; Save is disabled. | Edit → the textarea gets focus (autofocus). After Save or Cancel focus is lost (body). Only Tab works. |
| Redact `dialog#redact` | Canvas drawing (pointer only), Undo, Cancel, Save | Boxes can only be drawn with a mouse. Esc closes (native dialog). |
| Chat `#chat` | Composer textarea `#chat-text`, section `#chat-section`, Send. For each open thread: Reply input (Enter sends) and Resolve. For each resolved thread: Show/Hide toggle and Reopen. "Show older". | Tab works. There is no Ctrl+Enter to send. After a reply, resolve or reopen POST, `#chat-list` is swapped and focus is lost. The reply inputs have no ids. |

### Report tab `/e/{eng}/report`
- Uses the same `panel`/`editor` templates as the finding page (route `/e/{eng}/report/s/{section}`). Edit, Save and Cancel behave the same. There is no Comment button (ReadOnly).

### Overview / Settings tabs
- Engagement settings: General form (Cancel link, Save), team Remove buttons, and an add-person select with an Add button.

### Inbox `/inbox` (inbox.html)
- Queues: Approve, Review, Returned (director), or Returned, Review. Row title link and Fix/Approve/Review links. "Load more" per queue.
- Director: `form.bulkform` with checkboxes per row, the bulk bar Approve, Mark reported, **Assign reviewers** (`details.bulkassign` → checkboxes and Assign), and Clear selection (`type=reset`). The bulk POST swaps `#inbox-lists`, and focus is lost. The "N selected" count is a CSS counter.

### Export `/e/{eng}/export`, Destinations
- Destination cards are submit buttons. The pick table has checkboxes. History has Retry/Open. Preview is a `formaction` GET. All are reachable with Tab.
- Destinations setup: a table of Edit links and a plain POST form (`rule_form`-style) with Delete (`form="dest-delete"`) and Save.

### Templates
- List: a new-template title input with a "New template" button, a search form, and row links.
- Template page: a meta form (title, severity, CVSS) with Save, History and Delete (`confirm()`), plus section `panel`s with Edit. These use the same editor and routes `/templates/{slug}/s/{section}`.
- Save as template (`template_save.html`).

### History (finding and template)
- Event links `.ev` (full page navigation), the Show filter seg, Diff/Full text seg, and Restore per section (POST).

### Notifications
- Mark all read. Each row is a button `.noteopen` (POST + redirect), with a focus ring.

### Admin `/admin?tab=…`
- Tab links `.atab`. Rules: level filter, New rule, toggle buttons, Edit links, `rule_form` (plain POST, multipart, Delete via `form="rule-delete"`, Save) and the test bench (htmx GET). Users, Engagements, AI, System, Health, Activity, Structure and Webhooks are plain forms and buttons.

### Settings `/settings`
- Section anchors. Account, Preferences (theme seg), Password, Notifications: each is a POST form with Save. Tokens: New/Revoke. Connections: Add key/Remove.

### New finding
- The title has `autofocus`. A Template/Blank radio seg, a template search (htmx), template radios, Cancel and Create. This works well with the keyboard already.

### Summary of gaps
1. No single-key shortcuts, no row or section selection, no Ctrl+S, no Esc for popovers or inline forms.
2. **Focus is lost after most htmx swaps**: workflow (SSE and Check), chat list, section, details, assets and CVSS save/cancel, assets rows, CVSS paste, retest radios, findings filters, sort and load more, inbox bulk, checks dismiss.
3. No visible focus ring for `.btn` and links beyond the browser default.
4. Closed selects that submit on `change` (engagement picker, CVSS severity) act on the first arrow press.

---

## 2. Principles

1. **The template decides what exists.** A shortcut is declared on the control with `aria-keyshortcuts="…"`. The JS dispatcher looks for a rendered, visible, enabled element carrying that shortcut. If the user may not act, or the state is wrong, the control and its shortcut are absent. Permissions stay on the server, and nothing has to be kept in sync by hand.
2. **Ignore keys while typing.** Single keys and Shift+key are ignored when the event target is `input`, `textarea`, `select` or `[contenteditable]`, when `evt.isComposing` is set, or when a modal dialog other than the shortcut overlay is open (Go to, Redact). The exceptions are **Ctrl/Cmd+S**, **Ctrl/Cmd+Enter**, **Esc** and Ctrl+K, which also work inside fields.
3. **Never press a state-changing button directly** (see Q1): a workflow or bulk shortcut moves focus to the button and Enter confirms. Opening, focusing, navigating and saving an editor happen immediately.
4. **Stable layout:** selection and focus are shown with `outline` (same as `.panel:target`), never with borders, padding or extra elements. Nothing moves.
5. **No helper copy:** shortcuts are not printed in the UI. The only hint is the existing `Ctrl K` in the Go to button. The full list appears only when **?** is pressed.
6. **Desktop only.** Square corners: the overlay reuses the `.gotodlg` look.

---

## 3. Proposed key map

### Global (every page with a signed-in user)
| Key | Action | Notes |
|---|---|---|
| Ctrl/Cmd+K | Go to (exists) | unchanged |
| `/` | Focus the page's search or filter field if there is one (templates search, new finding template search, admin activity filter). Otherwise open Go to. | Firefox quick-find conflict: we `preventDefault` only when we handle the key. |
| `?` | Shortcut overlay `dialog#keys` | See section 5 |
| `g` then key (within 1 s) | `g e` engagements `/` · `g f` findings board (current engagement) · `g o` overview · `g r` report · `g x` export · `g i` inbox · `g n` notifications · `g t` templates · `g s` settings · `g a` admin (only if the Admin link is rendered) · `g h` history (finding/template page) | Each target is a link already in the page, or a URL built from `data-eng` on `<body>`. `g` alone does nothing. |
| `[` / `]` | Previous/next tab in the page's tab bar (`nav.etabs`, `nav.atabs`) | Full page navigation |
| Esc | Closes the topmost thing, in this order: native dialog (browser) → open `details.pop` / `details.bulkassign` (focus back to its summary) → open `.wfpanel` / `.dismissrow` (click its Cancel) → open editor (click its Cancel, which keeps the existing "Discard changes?" guard) → blur the focused field so single keys work again | Works inside fields |
| Ctrl/Cmd+S | Save the editor or form that holds focus (section 4). Otherwise do nothing. **Always** `preventDefault` on every page, so the browser dialog never opens. | Works inside fields |
| Ctrl/Cmd+Enter | Submit the small form that holds focus: chat composer, reply input, Return/Withdraw reason, dismiss reason, reviewer picker | Works inside fields |

### Lists (board rows, inbox rows across all queues, engagements list, templates list, notifications, history events, admin rules, export picks, destinations)
| Key | Action |
|---|---|
| `j` / `k` (and ↓/↑ when no field has focus) | Move focus to the next/previous row's main link, marked `data-nav` in the template. The browser's focus ring plus `tr:focus-within` gives the row highlight. |
| Enter | Opens the focused link (native) |
| `x` | Toggle the row's checkbox (inbox director picks, export picks) |
| `j` on the last row | Focus "Load N more". Enter loads, and focus then moves to the first new row. |
| `1`–`9` | Pick the Nth segment of the page's filter seg (`nav.seg` with `data-filter`: board status, history Show, rules level) |
| `n` | New: clicks or focuses the page's create control (New finding, New template → focuses the title input, New rule, New destination, New token, New engagement) |

### Finding page (also report tab and template page, which use the same `panel` template)
| Key | Action |
|---|---|
| `j` / `k` | Move the **current section** through the main column panels (workflow bar, retest, checks, details, assets, CVSS, text sections). The panel gets `tabindex="-1"` + focus and the `:target`-style outline. |
| `e` | **Edit** the section (decided). Which section is picked is described in section 4. |
| Ctrl/Cmd+S | **Save and exit** (decided) |
| Esc (in editor) | Cancel, with the existing discard guard |
| `c` | Comment on the current section: calls the existing `yarsComment(section)`, which focuses the composer with the section preselected |
| `v` | Open the reviewer picker (`details.pop.assign`) and focus its first checkbox. Space toggles, Ctrl+Enter saves, Esc closes. |
| Shift+S | Submit (`data-slot="submit"`) |
| Shift+O | Sign off (`clear`) |
| Shift+A | Approve |
| Shift+R | Return: opens the reason form (focus goes to the textarea, as today). Ctrl+Enter submits. |
| Shift+W | Withdraw: same as Return |
| Shift+P | Mark reported (`report`) |
| Shift+U | Reopen (complete) / Restore (withdrawn). Only one of them is ever rendered. |
| Shift+C | Check (the `data-slot="check"` button) |
| `h` | History (link in the title row). The same as `g h`; drop one of them if Q8 says so. |

Workflow shortcuts follow principle 3: **focus the button, then Enter**. A disabled button (gated by errors, or Approve waiting for a sign-off) does nothing. Its `title` and the gate list already explain why.

### Chat
| Key | Action |
|---|---|
| `c` | Comment on the current section (see above). With no current section the composer gets "General". |
| Ctrl/Cmd+Enter | Send (composer) / Reply (reply input) |
| Esc in composer | Blur, so the page keys work again. The typed text is kept. |
| Threads | Tab through them (already works). After Reply, Resolve or Reopen, focus is restored (section 6). |

### Inbox (director bulk)
| Key | Action |
|---|---|
| `j`/`k`, Enter, `x` | As in lists. `x` toggles the row's `input[name=id]`. |
| Shift+A | Focus bulk **Approve** |
| Shift+P | Focus bulk **Mark reported** |
| `v` | Open **Assign reviewers** and focus its first checkbox. Ctrl+Enter assigns. |
| Shift+X | Focus **Clear selection** |

### Editors that are plain forms (not htmx)
For the template meta form, rule form, destination form, engagement General, Settings Account/Preferences/Notifications, the webhook form and the AI provider form, Ctrl+S submits the form that holds focus through its save button. Password, add-user and other create forms are left out (see Q5).

### Keys deliberately not bound
- **Alt+letter / Alt+digit**: menus and tab switching on Linux/Windows (Chrome and Firefox Alt+1..9).
- **Ctrl+Shift+…**: devtools, private window, reopen tab.
- **Space**: page scroll.
- **Ctrl+F/L/T/W/R/D/P**: browser.
- **Write/Split/Preview** switching: reachable with Tab. Ctrl+Shift+P would clash, so no shortcut.
- **Redact drawing**: pointer only; out of scope. Inside the Redact dialog, Ctrl+S = Save and Ctrl+Z = Undo are cheap to add (see Q7).

---

## 4. Ctrl+S and E in detail

### What E edits (finding page, report tab, template page)
Candidates are panels with an Edit/Calculate button, `[aria-keyshortcuts~="E"]` on the button. Locked panels render a lock slot instead of a button, so they never qualify. The section is chosen in this order:
1. **Focused:** `document.activeElement` is inside a panel (for example after Tab to its Comment button, or after `j`/`k`).
2. **Last selected:** the panel last chosen with `j`/`k` or by following a `#s-…` link (`:target`, which chat section refs use), if it is still in the DOM.
3. **Hovered:** the panel under the pointer, if the pointer moved in the last few seconds (see Q2; this might be left out).
4. **First:** the first editable panel in reading order. That is Details on a finding, unless a decision in Q3 picks the first text section instead.

If the chosen panel is already in edit mode, E does nothing (it is a letter typed in the textarea anyway). With no editable panel (archived, withdrawn, locked) E does nothing.

### What Ctrl+S does in each place
Rule: find the form that holds focus. If none does and **exactly one** editor is open on the page, use that one. Then call `form.requestSubmit(saveButton)`, where `saveButton` is the button inside the form carrying `aria-keyshortcuts="Control+S"`. htmx 2 honours `evt.submitter`. If the button is disabled, do nothing beyond `preventDefault`.

| Editor | Save button | Result | Special cases |
|---|---|---|---|
| Section editor (finding, report, template) | `.btn.save` in `.pfoot` | POST → view panel, so edit mode ends. Focus returns to that panel's Edit button. | **Conflict:** the bottom Save is disabled, so Ctrl+S does nothing and focus moves to "Keep mine". It does not press it (Q4). **401:** the existing `yarsExpired` draft flow handles it. |
| Details editor | Save | Same | 409 returns the editor with `data-dirty`; focus stays in it |
| Assets editor | Save (**not** Add row or ✕) | Same | Pass the submitter explicitly, because the `op` buttons also submit |
| CVSS editor | Save | Same | **Must pass Save as submitter**, because Clear vector is the first submit button. Disabled until complete: Ctrl+S then focuses the first `textarea[aria-invalid]` reason. |
| Reason forms (Return/Withdraw), dismiss reason, reviewer picker | n/a | Ctrl+S does nothing here (these are actions, not edits). Ctrl+Enter submits. | |
| Chat composer and reply | n/a | Ctrl+S does nothing. Ctrl+Enter sends. | |
| Plain forms (template meta, rule form, destination form, engagement General, Settings Account/Prefs/Notifications, webhook, AI) | the form's Save button | Full POST and redirect | Only when focus is inside that form, because Settings has several forms on one page |
| Redact dialog | Save | Uploads | Optional (Q7) |
| Anywhere else | — | `preventDefault`, nothing else | |

Multiple editors can be open at the same time (each panel swaps on its own). Ctrl+S never saves more than one.

---

## 5. Shortcut overlay (`?`)
- `dialog#keys` in layout.html, rendered for signed-in users and built like `#goto` (square, `kbd` styles, `showModal`, Esc closes).
- Server-rendered groups: Global, Lists, Finding, Chat, Inbox. JS hides groups that do not apply to the page, by checking for `body[data-page]` or for the controls. All rows use the same `<kbd>` styling as the Go to footer.
- It is the only place shortcuts are listed. No tooltips are changed (see Q6).

---

## 6. Focus after htmx swaps
There are two mechanisms. Both are generic.

1. **Stable ids, so htmx 2's built-in focus restore works.** On swap, htmx refocuses an element with the same id as the old active element, which is why the CVSS radios already behave. Add ids to:
   - workflow slot buttons (`wf-{slot}`, check `wf-check`), so an SSE refresh keeps focus;
   - reply inputs (`reply-{rootID}`) and the Reply, Resolve and Reopen buttons (`resolve-{rootID}`, `reopen-{rootID}`);
   - retest radios (`retest-{code}`), the CVSS paste input (`cvss-paste`) and the severity select (`cvss-sev`);
   - status filter links (`flt-{key}`) and sort links (`sort-{key}`);
   - checks Restore buttons.
2. **Focus return in `htmx:afterSettle`:** if the active element was inside the swap target before the swap and is now `body`, focus the new content's `[data-focus-return]`. Where that goes:
   - the Edit button of a panel after Save/Cancel;
   - the first `autofocus` field of an editor (add `autofocus` to the first field in the details, assets and CVSS editors);
   - the first new row after "Load more";
   - the bulk bar after an inbox bulk action;
   - the checks panel heading after dismiss.

When Check starts, the button becomes a disabled "Checking" button and cannot hold focus, so focus goes to the `#workflow` section (`tabindex="-1"`).

The busy guard in app.js:88 stays as it is.

Also fix the two closed selects that submit on `change`:
- **Engagement picker:** navigate only on `change` caused by a pointer, or on Enter. Keep `onchange` for the mouse, but skip it when the last event was a keydown.
- **CVSS Severity:** use `hx-trigger="change[!yarsKeyNav]"` plus Enter/blur. Both changes are small JS with no server change.

---

## 7. Accessibility
- Every bound control carries `aria-keyshortcuts` (for example `Shift+A`, `Control+S`, `E`, `Escape`).
- A visible focus ring for everything: `:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px }` on `.btn`, `a`, `summary`, `.panel[tabindex]`, `tr:focus-within` (the row highlight). It uses outline only, so the layout is unchanged.
- **WCAG 2.1.4 (Character Key Shortcuts):** single-letter shortcuts need an off switch. Screen readers in browse mode and extensions such as Vimium also use j/k/e. Proposal: Settings → Preferences → "Keyboard shortcuts On/Off", stored like `Theme` (`config.User.Keys`), and rendered as `data-keys="off"` on `<html>`. When off, only Ctrl+K, Ctrl+S, Ctrl+Enter and Esc remain (Q9).
- Non-US layouts: match on `evt.key`, not `evt.code`. For `[ ] / ?` accept AltGr (`getModifierState('AltGraph')`), because on Windows AltGr reports ctrl+alt.
- Holding a key down: ignore `evt.repeat` for every shortcut except `j`/`k`.

---

## 8. Feasibility and files

| Item | Effort | Server change? | Files |
|---|---|---|---|
| Dispatcher (typing guard, `aria-keyshortcuts` lookup, `g` sequences, Esc stack) | easy | no | `static/app.js` |
| Ctrl+S everywhere + suppressing the dialog | easy | templates only (`aria-keyshortcuts="Control+S"` on save buttons) | `app.js`, `partials.html` (editor), `details.html`, `assets.html`, `cvss.html`, `template.html`, `admin.html` (rule_form, webhook, AI), `export_setup.html`, `eng_settings.html`, `settings.html` |
| E: pick and open section | easy | templates (`aria-keyshortcuts="E"` + id `edit-{anchor}` on Edit buttons) | `partials.html` `panel`, `details.html`, `assets.html`, `cvss.html` |
| Section j/k + current-section outline | easy | no (JS sets `tabindex=-1`) | `app.js`, `style.css` |
| List j/k/x/Enter/Load more | easy | templates (`data-nav` on the main link of each row) | `partials.html` (finding_rows), `inbox.html`, `engagements.html`, `templates.html`, `notifications.html`, `history.html`, `admin.html` (rules), `export.html`, `export_setup.html` |
| Filter digits, `[ ]` tabs, `n` new | easy | templates (`data-filter`, `aria-keyshortcuts="N"`) | `partials.html`, `history.html`, `admin.html`, page headers |
| Workflow Shift+keys | easy-medium | **yes, small:** `wfSlot` gets a `Key` field from a map in `workflow.go` (`submit→Shift+S` …), and the template renders `aria-keyshortcuts` and `id` | `workflow.go`, `workflow.html` |
| Chat Ctrl+Enter, `c`, ids for focus restore | easy | templates (ids) | `chat.html`, `app.js` |
| Inbox bulk keys | easy | templates | `inbox.html` |
| Focus restore ids + `data-focus-return` + autofocus in editors | medium (many small touches; the SSE races need browser checks) | templates | `workflow.html`, `chat.html`, `retest.html`, `cvss.html`, `details.html`, `assets.html`, `checks.html`, `partials.html`, `inbox.html` |
| Select-on-change fixes | easy | no | `app.js`, `cvss.html` (trigger), `layout.html` |
| `?` overlay | easy | templates | `layout.html`, `style.css`, `app.js` |
| Focus rings | easy | no | `style.css` |
| Preference to turn shortcuts off | medium | **yes:** a new user field, the prefs handler, and the attribute on `<html>` | `config/config.go`, `web/settings.go`, `settings.html`, `layout.html`, plus how users are persisted (same path as `Theme`) |
| Direct-fire workflow and bulk shortcuts (if Q1 = fire) | **risky** | no | there is no undo for Approve or Mark reported, and full page POSTs |
| Keyboard redaction (arrow-key box drawing) | risky / large | no | out of scope |

**Size:** about 400–600 lines of JS/CSS/template and about 300 lines of tests. One PR (well under 8k). Split it in two if the preference toggle is wanted: (1) dispatcher, Ctrl+S/E/Esc, focus restore, overlay; (2) lists, workflow and bulk keys, preference.

---

## 9. Testing

### Go handler tests (new `internal/web/keys_test.go`, same style as `goto_test.go` / `shell_test.go`)
- Finding page, **draft, author**: the submit slot button has `id="wf-submit"` and `aria-keyshortcuts="Shift+S"`. Withdraw has `Shift+W`. No `Shift+A` is present.
- **Verification**:
  - as an assigned reviewer, Sign off has `Shift+O`;
  - as a director, Approve has `Shift+A`, and when it waits for a sign-off it is rendered disabled;
  - as the author, there is no Sign off.
- **Archived engagement:** no workflow `aria-keyshortcuts` and no `aria-keyshortcuts="E"`.
- **Locked section** (complete status): its panel has no `E`. Editable panels do.
- The editor fragment (`GET …/s/{section}/edit`) has the Save button with `aria-keyshortcuts="Control+S"`, and Cancel with `Escape`.
  - CVSS editor: Save has `Control+S` and **Clear vector does not**.
  - Assets editor: only Save has it.
- Rows: the board has `data-nav` once per row; inbox director rows have checkboxes plus `data-nav`.
- The layout has `dialog#keys` for a signed-in user, and not on the login or bare pages.
- Preference off: `data-keys="off"` on `<html>`. Posting prefs saves it.
- `app.js` contains the dispatcher markers (the existing "app.js lacks %q" pattern).

### Browser checks (chrome-devtools MCP, desktop width; run the app with the `run` skill)
1. Board: `j j Enter` opens the 2nd finding. `2` filters to draft, and focus stays on the filter. `j` past the end then Enter loads more, and focus lands on the first new row.
2. Finding: `j j e` opens that section with the textarea focused. Type, then Ctrl+S: the panel is back in view mode, focus is on its Edit button, and no save dialog appears (check by hand once; CDP key events do not open the browser dialog). `e` then typing then Esc gives the "Discard changes?" confirm.
3. CVSS: Calculate, arrow through the metrics (focus stays), then Ctrl+S with missing reasons focuses the first reason. Fill it, Ctrl+S saves (not Clear).
4. Workflow: Shift+S focuses Submit, Enter submits. With focus on a slot button, trigger an SSE `workflow` event from a second session; focus survives.
5. Return: Shift+R, type a reason, Ctrl+Enter. Esc closes the reason form and returns focus to the toggle.
6. Chat: `c` on the current section gets the composer with that section. Ctrl+Enter sends. Reply with Enter or Ctrl+Enter, and focus stays on that thread's reply input.
7. Inbox (director): `j x j x`, Shift+A, Enter. Results show and focus is on the bulk bar.
8. Typing guard: in every input, `j e c ? g` type text. Ctrl+K and Esc still work.
9. Layout: take a screenshot before and after selection or focus. No element moves (compare bounding boxes with `evaluate_script`).
10. Preference off: single keys do nothing. Ctrl+S, Ctrl+K and Esc still work.

---

## 10. Open questions for the user
1. **Workflow and bulk shortcuts:** should Shift+S/A/O/P only **focus** the button (Enter confirms, as proposed), or **fire** at once? Approve and Mark reported cannot be undone from the UI.
2. **E with hover:** should the hovered section count (rank 3)? It is convenient, but it can surprise when the mouse is resting somewhere random. The proposal leaves it out unless you want it.
3. **E with nothing selected:** should it pick the first editable panel (Details), or the first **text** section (usually Description)?
4. **Ctrl+S in a conflict:** should it do nothing and move focus to "Keep mine" (proposed), or act as "Keep mine"?
5. **Ctrl+S scope for plain forms:** which ones? The proposal covers template meta, rule, destination, engagement General, Settings Account/Prefs/Notifications, webhook and AI, and leaves out Password, Add user, New engagement and Connections.
6. **Hints:** is the `?` overlay the only place shortcuts show up, or may `title` tooltips add the key (for example "Approve · Shift+A")? Strict no-helper-copy says the overlay only.
7. **Redact dialog:** is Ctrl+S = Save / Ctrl+Z = Undo inside it wanted? Drawing boxes stays mouse-only.
8. **Key names:** `g`-sequences plus `[ ]` tabs plus `h` for History. Is that too many? Which mnemonics would you change? Should `n` (new) be `c` (create) instead, given that `c` is Comment here?
9. **Off switch:** add "Keyboard shortcuts On/Off" to Preferences (needs a user field, recommended for WCAG 2.1.4)? Or always on?
10. **Select-on-change fixes** (engagement picker, CVSS severity): include them in this work, or handle them separately as bugs?
11. **Inbox range select:** is Shift+x (select a range from the last toggled row) wanted?
