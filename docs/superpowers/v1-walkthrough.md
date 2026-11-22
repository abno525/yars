# v1.0 walkthrough

The final test of 2026-11-22. (The first run, on 2026-11-12 with `v1.0.0-rc`, is in this file's git history.)

It ran on a fresh data folder (`yars init`), served at 127.0.0.1:8099, with a binary built from `pr/30-decisions` at f714460: `go build -ldflags=-X=main.version=v1.0.0-rc2`. What this run found was fixed afterwards, each fix with a test that failed first (see the end).

- **Browser:** an emulated 1440 × 900 viewport at scale 1, light theme. Chrome's zoom for 127.0.0.1:8099 is 90%, so those pages laid out at 1600 × 1000 CSS px. The page sweep afterwards used exactly 1440 × 900 CSS px (1296 × 810 at scale 1.11).
- **Machine:** git 2.56, pandoc 3.10 and xelatex. No AI provider is configured.
- **Input:** at first the browser tool's clicks and keys did not reach the page. So `/setup`, Admin › Users and New engagement were filled and sent with a script in the page. After the browser restarted, typing, clicks and key presses were real for every line below.

**Setup.**
- `/setup` created dana (director, admin).
- Admin › Users added pat (pentester) and rex (reviewer) with temporary passwords. Each set a new one at first login.
- dana created engagement `acme` (ACME Web, client ACME Corp) with pat and rex on its team.

| # | Line | Result |
|---|---|---|
| 1 | Three accounts take a finding from draft to reported, then revert it twice with reasons | pass |
| 2 | A check finds an error; the Checks strip opens for the author; the error is fixed by hand; the thread resolves; a reviewer signs off; the director approves from Ready to approve | pass (Fix with AI: `skipped: no AI provider`) |
| 3 | Clone with submodules; `yars hook install`; a commit with a rule error warns and goes through; a broken CVSS vector is refused with how to fix it; the fixed push lands and the open page updates | pass |
| 4 | Export to HTML, PDF and Word | pass |
| 5 | An MCP client over HTTP lists the drafts, reads one, edits a section, submits | pass |
| 6 | Redact an image, see the mark, purge it as director, clone again, the old blob is gone; new: the redaction reaches the retest's copy, the purge page names that retest | pass |
| 7 | Keyboard only: inbox, finding, section, edit, save, submit | pass (the finding opened from the findings list: the inbox has no drafts since cbd553b) |
| 8 | `yars backup`, `yars restore` into a new folder, serve it on another port, the findings are there | pass |
| 9 | Admin › System: Run integrity is all OK | pass (AI provider Off: none configured) |
| 10 | New: AI agents (opencode with DeepSeek) run three findings from notes to reported over MCP, including a return and a fix | pass |

## 1. Draft to reported, two reverts — pass

1. pat created F-001 "SQL injection in login" (draft), set severity high and reviewer rex (Change reviewers), then Submit (Shift+S): verification.
2. rex ran Check (Shift+C), then Sign off (Shift+O): signed off. A sign-off needs a current check; on F-003 later, Sign off without one said "Run Check first".
3. dana, Inbox › Ready to approve, ticked the row:
   - Set state › Complete · approve ("1 moved · 0 skipped");
   - then Set state › Reported · mark reported: reported.
4. dana on F-001, Revert (Shift+U):
   - with "The client asked for the payload table to name the endpoint.": complete;
   - again with "The endpoint changed: the reviewer should read it again.": verification.
5. The chat lists every step: submitted, signed off, approved, marked reported, and both reverts with their reasons.

## 2. Check, fix by hand, sign-off, approval — pass

This ran on F-001 while it was a draft, before line 1's Submit; the sign-off and the approval are line 1's.

- pat wrote the Description with a table whose cells were in backticks. The live hint in the editor showed the error before the save.
- After Ctrl+S and Check:
  - Check reported "Do not use backticks in table fields (backticks are not allowed in table cells)".
  - The Checks strip was open for the author.
  - `yars` opened a thread on Description.
- pat rewrote the table without backticks and ran Check: the thread shows "Resolved by yars".
- The AI rule `acronyms-expanded` reported "AI rules skipped: no AI provider configured". The strip groups that under the orange "AI checks failed" badge (as it has since aca92e8). Fix with AI is disabled without a provider, so it was not run.

## 3. Git — pass

Setup:
- `git clone --recurse-submodules http://pat:…@127.0.0.1:8099/git/yars wtclone`: the `acme` submodule was checked out.
- `git -C wtclone/engagements/acme switch main`.
- `yars hook install --data wtclone`: "installed acme".
- F-002 "Open redirect after logout" was made on the website as pat. Its page was left open with a marker set in it.

Commits and pushes:
- **A rule error warns and goes through.** A title ending in a dot and a description, then `git commit -a`:
  - "error title-no-trailing-dot: The title must not end with a dot (".") [title]" and "yars: 1 errors, 0 warnings in 1 findings (commit not blocked)";
  - the commit was made.
  - The first try ran inside this session's network sandbox, which cannot reach the server. The hook said "could not ask 127.0.0.1:8099 …; nothing checked" and let the commit through.
- **Authorship.** The first push was refused because the commits carried this machine's git identity, not pat's. The message said what to do: `git config user.email pat@yars.local`, then `git commit --amend --reset-author`. The clone was set to pat and recommitted.
- **A broken vector.** `cvss: CVSS:3.1/…/I:Q/A:N`, then `git push`: refused with "invalid value Q for I (Integrity): use N, L or H".
- **Severity.** Amended to `I:L`: refused with "severity (none) does not match the CVSS vector (score 5.4 is medium); set severity: medium".
- **The fixed push lands.** Amended again: the push landed (`9698094..4b05f1c`).
  - The rule errors were printed as checks that block Submit.
  - The AI rule printed "could not run: AI rules run with Check on the finding page, not on push".
- **The open page updates.** pat's F-002 page showed the new title, the description and "MEDIUM 5.4" without a reload. The marker survived.

## 4. Export — pass

First rex signed F-001 off again and dana approved it (Shift+A), so F-001 was complete. dana's Export page had F-001 ticked and F-002, a draft, disabled. Each download was posted from the page:

| Download | Answer |
|---|---|
| `zip` | 200 `application/zip`, `acme-html.zip`, 488 bytes; its `acme/index.html` holds F-001's title, its severity and its description, and not F-002 |
| `pdf` | 200 `application/pdf`, `acme.pdf`, 15,112 bytes, begins `%PDF-` (pandoc and xelatex, 1.5 s) |
| `docx` | 200 Word type, `acme.docx`, 11,088 bytes; its `word/document.xml` holds the title, the severity, the description and the payload table, and not F-002 |

## 5. MCP over HTTP — pass

`yars token add --kind mcp --name walkthrough pat`. A Go client using only `net/http` and `encoding/json` POSTed JSON-RPC to `/mcp` with the bearer token:

1. `initialize`: `serverInfo` `yars v1.0.0-rc2`, protocol 2025-06-18
2. `list_findings` (acme, status draft): F-002
3. `read_finding` F-002: draft, 4 violations, the Impact section's base
4. `set_field` on the title, `cvss_reason.UI`, `.C` and `.I`, and reviewers `rex`, which cleared the errors the push left
5. `update_section` Impact, with the base
6. `start_check`, then `get_check_results` until done
7. `transition` submit: "submit done; status is now verification"

On the website F-002 then showed verification and the new Impact.

## 6. Redact and purge, with a retest — pass

1. **Upload.** pat made F-003 "Session token in screenshot" and used the Description editor's Add file (an 87 KB PNG).
   - The Redact dialog opened before the upload.
   - Saved with no boxes, the original was uploaded and its link inserted; then Description was saved.
   - A pull gave the image's blob, `115a4f0`.
2. **Retest.** F-003 went through review to complete. dana started a retest, `acme-retest`, from New retest, where F-001 and F-003 were ticked by default (the complete ones). The retest's copy of the image is the same blob, `115a4f0`.
3. **Redact.** dana opened the Description editor, chose Redact on the image, drew one box and saved:
   - one redaction commit in `acme` and one in `acme-retest`, the image 88,827 → 98,216 bytes in both;
   - no "not redacted" message.
4. **The mark.** dana's attachments row showed the dot "An earlier version is in git history" and a Purge action.
5. **The Purge page** names:
   - the file and the engagement;
   - under Retests, "ACME Web — retest";
   - and says "Existing clones of this engagement must be cloned again".
6. **Purge.** After Purge, the row had no dot and no Purge.
7. **The blob is gone.** In a new `git clone …/git/e/acme`, `git cat-file -t 115a4f0` fails, as it does in the server's repository.
8. **The retest.** The retest's history still held `115a4f0`, as its listing said. Its own row showed the dot and Purge; purging there (Retests: None) removed it too.

## 7. Keyboard only — pass

F-004 "Verbose error page" was given a severity (low) and a reviewer (rex) with the mouse first. Then, as pat, from the engagement list, keys only:

1. `i` opened the Inbox. The inbox no longer lists drafts (cbd553b, PR #30), so:
2. `f` opened the findings list, `j` four times selected the F-004 row (focus on its link), and Enter opened it.
3. `j` five times selected the panels in order: workflow, Details, Assets, CVSS, Description.
4. `e` opened the Description editor with the text focused.
5. Ctrl+End, then a sentence typed.
6. Ctrl+S saved: the editor closed and the panel stayed selected.
7. Shift+S: verification.

## 8. Backup and restore — pass

While 8099 served:

1. `yars backup --data final --out final-backup.zip`: "444.0 KB, 2 engagements, 6 findings".
2. `yars restore --from final-backup.zip --data final-restored`:
   - schema v24, 2 engagements, 6 findings;
   - secret key: no, "stored AI and personal keys must be entered again".
3. `yars serve --data final-restored --addr 127.0.0.1:8097`.

dana logged in there with her password. `/e/acme` lists:
- F-001 complete (signed off by rex);
- F-002 in verification;
- F-003 complete;
- F-004 in verification.

That is as on the live server.

## 9. Integrity — pass (AI provider Off)

dana, Admin › System, Run integrity. The Health heading reads "Checked 18:07", with no error or warning tag. The Server panel shows Version `v1.0.0-rc2`.

| Check | Status | Result | Detail |
|---|---|---|---|
| Rules | OK | 5 loaded | — |
| Destinations | OK | Confluence HTML, Client report (DOCX) | 2 destinations |
| pandoc + PDF engine | OK | pandoc 3.10 · xelatex | XeTeX 3.141592653-2.6-0.999998 (TeX Live 2026/TeX Live for SUSE Linux) |
| Git server repos | OK | 3 repos | git version 2.56.0 |
| AI provider | OFF | Off | — |
| Disk free | OK | 9.9 GB of 15.2 GB | (the data folder) |
| Database integrity | OK | 224.0 KB | integrity_check ok · schema v24 |
| Git repositories | OK | 3 repos | fsck |

## 10. AI agents run the workflow — pass

**Setup:**
- A separate data folder: `yars seed --engagements 1 --findings 0` gives accounts dir1, rev1 and pen1 and an empty engagement `e001`. It was served on 127.0.0.1:8098.
- opencode 2.3.2, model `deepseek/deepseek-v4-pro`, run with `opencode run --auto`.
- One MCP token per account (`yars token add --kind mcp`), in a config of its own (`OPENCODE_CONFIG`). File edits, the shell and web fetch were denied, so the agents could use only YARS's MCP tools.
- Each agent got a written brief: its role, the team's review rules, and the pentester's notes.

**Round 1:**
- **Pentester agent (pen1).** It started with `whoami`, `get_config` and `list_engagements`. Then it wrote up F-001 (SQL injection) and F-002 (stored XSS) from the notes:
  - all five sections, the five details rows, the asset, the CVSS vector with a reason for each non-standard metric, and reviewer rev1;
  - Check found backticks in two details rows; it fixed them, checked again and submitted both.
  - Two refusals it corrected by itself: the asset list sent as an object, then with the port as a number (the tool description gives a list with the port as a string).
  - Its closing summary gave F-002 a score of 4.8; YARS shows 5.4, which is right for the vector.
- **Reviewer agent (rev1).** It read both findings and their chats, ran a current check, judged them against the four team rules and signed both off, passing the `hash` from `read_finding` as `base`.
- **Director agent (dir1).** It approved both with `base`, then marked them reported.

**Round 2 (a return):**
- **Pentester agent.** It wrote up F-003 (other customers' orders visible) from a note without the exact request, and submitted it.
- **Reviewer agent.** It returned F-003, with a chat message to @pen1 naming two changes: the exact request in Steps to Reproduce, and a remediation that names the endpoint.
- **Pentester agent**, told only to deal with review feedback:
  - it found the returned finding and read the thread;
  - it made both changes from its extra notes (`GET /account/orders/100244` and `…/100245`);
  - it replied in the thread and resolved it;
  - it ran the checks and submitted again.
- **Reviewer agent.** It saw both changes made and signed F-003 off.
- **Director agent.** It approved F-003 and reported it, and left F-001 and F-002 alone (already reported).

F-003's chat holds the whole trail: submit, the reviewer's thread with pen1's reply (resolved by pen1), return with its reason, submit, sign-off, approve, report. Each agent run took one to two minutes.

## Found by this test, and fixed

Each fix has a test that failed first, and a reviewer read each fix; what a reviewer found was fixed the same way (the follow-ups below).

- **18f7b3e, 9a90fd5:** the New retest page showed "Findings to retest · N of M" under its table. a2ef636 had removed the CSS rule that lifted the head, and fixed only the export page's markup. Follow-up: a refused New retest now counts the ticked rows, not the posted values.
- **ba9c7c2:**
  - a redaction named, as "failed", a retest the redactor cannot see when its copy could not be read;
  - the purge page was a 500 while any retest of the engagement had an unreadable repository (also while one is being made).
- **67a9a06, e7962b7, f4de042:** in the assets editor, typed rows counted as saved, so Cancel, Esc and leaving dropped them without asking. That happened:
  - after a refused or conflicting save, for a row with a URL and no host;
  - after Add row or Remove;
  - after every saved row was removed.
- **02ae98e, 5791c5b:** a script rule changed during a check, or changed and changed back while it ran, stored its result under the rules version the check began with. After a revert, the stored result came back instead of a run. A result is now kept only when the rules folder's signature is unchanged after the run; that is cheap stat calls, not a hash of the folder.
- **c88181f, 421b1c9:** a check run kept the rules version of when it was asked for. With the Q3 queue it could run newer rules, and a revert then made it current again. It now records the version it began with, and "+changed" when the rules changed while it ran, including a change undone. A queued retry whose rules changed runs every rule.

## Every page, both themes

**The sweep:**
- An agent opened every page as dana, pat and rex at 1440 × 900 CSS px, in light and in Graphite (dark).
- About 80 screenshots: no horizontal scroll, no console error, no broken image, no raw template text.
- It listed about 30 layout points.
- Five builders, one area at a time, each with a reviewer, checked each point against the history: a recorded choice stays, anything else is fixed with a test that failed first.
- The reviewers' findings were fixed the same way.

**Fixed:**
- **Developers:**
  - MCP parameter text wraps instead of being cut mid-word;
  - commands break at spaces, not inside "Bearer".
- **Top bar:**
  - the user name's underline sits under the name;
  - beside the bar, no light strip on pages that do not scroll;
  - Templates' count stands level with its search;
  - Go to shows its empty list and lines its titles up.
- **Retest result:**
  - the control is 40 px high (a panel margin hit its segments);
  - choosing a result moves nothing (border and error slot).
- **New finding:**
  - the duplicates stripe runs its whole height;
  - the lists' header band runs into the scrollbar room.
- **History** fits the window (the list scrolls, the page does not).
- **New retest:**
  - Cancel, then Create retest, at the bottom right as on New finding;
  - a free ID is filled in.
- **Overview:** the severity tiles stand in one row, with a kept place for "—".
- **Engagement tabs:**
  - Export, New retest and New finding stand in one place on every tab;
  - New lead keeps its place, last; other tabs keep it as an empty slot.
- **Team board:**
  - fits the window;
  - with no lead open, its thread pane shows "—".
- **Settings › Team:** the add row lines up with the table; when everyone is on the team, its select shows "—" and gives up its key.
- **Export:** Preview and Destinations are alike.
- **Inbox:**
  - the action column holds Mark reported (w128 for every row action);
  - no dangling dot after a name;
  - an unrecorded approver shows "—".
- **Tokens:** Last used gets a date-and-time column.
- **Activity:**
  - Object has room;
  - empty cells show "—";
  - the pager keeps disabled Previous and Next;
  - lists read "a, b";
  - "1 earlier version".
- **Users:** the Unlock slot shows a disabled Unlock instead of a gap.
- **Sentence case:** New token's and AI's Provider choices read as written.
- **Graphite:** no navy left from the light theme. The top-bar borders take Graphite's grey; navy fills take Graphite's Complete blue.
- **File inputs** (Restore, Script) look like fields.
- **System:** a wide stat ends where five cells end.
- **Rules:**
  - the test bench lines up with New rule;
  - Try is as wide as Run;
  - empty tables and values show "—".
- **Structure:** the lists sit two to a row; the add inputs are as wide as the items'.

**Kept as recorded choices:**
- the workflow bar's per-action button widths (M13, M27);
- the finding head aligned over the bar (`TestFindingHeadAlignsWithBar`);
- the scroll lists' reserved scrollbar room (9aca3c8);
- History's reserved Restore slot;
- New engagement's 640 px panel (B4);
- Export History's empty action slots;
- Webhooks without an Admin tab (B2);
- Notifications' unread count beside Mark all read.

ba9c7c2, 67a9a06 and 02ae98e came from the final code review of PRs #30 and #31: four reviewers, each finding verified by a second agent that reproduced it. Store, workflow, MCP and git server came back with nothing. The follow-ups came from the reviewers of the fixes.
