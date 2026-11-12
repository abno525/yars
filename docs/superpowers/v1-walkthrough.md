# v1.0 walkthrough

Run on 2026-11-12 with the binary built from `pr/29-release` (`go build -ldflags "-X main.version=v1.0.0-rc"`), on a fresh data folder (`yars init`), served at 127.0.0.1:8099. The browser was 1440 × 900, light theme. The machine has git 2.56, pandoc 3.10 and xelatex; no AI provider is configured.

**Setup.** `/setup` created dana (director, admin). Admin › Users added pat (pentester) and rex (reviewer) with temporary passwords; each set a new one at first login. dana created engagement `acme` (ACME Web) with pat and rex on its team.

| # | Line | Result |
|---|---|---|
| 1 | Three accounts take a finding from draft to reported, then revert it twice with reasons | pass |
| 2 | A check finds an error; the Checks strip opens for the author; the error is fixed by hand; the thread resolves; a reviewer signs off; the director approves from Ready to approve | pass (Fix with AI: `skipped: no AI provider`) |
| 3 | Clone with submodules; `yars hook install`; a commit with a rule error warns and goes through; a broken CVSS vector is refused with how to fix it; the fixed push lands and the open page updates | pass (after a fail, fixed in 54cac0f) |
| 4 | Export to HTML, PDF and Word | pass |
| 5 | An MCP client over HTTP lists the drafts, reads one, edits a section, submits | pass |
| 6 | Redact an image, see the mark, purge it as director, clone again, the old blob is gone | pass |
| 7 | Keyboard only: inbox, finding, section, edit, save, submit | pass |
| 8 | `yars backup`, `yars restore` into a new folder, serve it on another port, the findings are there | pass |
| 9 | Admin › System: Run integrity is all OK | pass |

## 1. Draft to reported, two reverts — pass

- pat: New finding "SQL injection in login" (F-001, draft), severity high, reviewer rex, Submit (Shift+S): verification.
- rex: Sign off was disabled with "Run Check first" (Require Check, Q1). After Check (Shift+C), Sign off (Shift+O): signed off.
- dana, Inbox › Ready to approve: ticked the row, then Set state › Complete · approve ("1 moved · 0 skipped"); then Set state › Reported · mark reported: reported.
- dana on F-001, Revert (Shift+U):
  - with "The client asked for the payload table to name the endpoint.": complete;
  - Revert again with "The endpoint changed: the reviewer should read it again.": verification.
- The chat lists every step: submitted, signed off, approved, marked reported, and both reverts with their reasons.

## 2. Check, fix by hand, sign-off, approval — pass

- pat wrote the Description with a table whose cells were in backticks.
  - The live hint showed the error, and Check reported "Do not use backticks in table fields (backticks are not allowed in table cells)".
  - The Checks strip was open for the author, and the check opened a thread by `yars` on Description.
- pat rewrote the table without backticks and ran Check: the thread shows "Resolved by yars".
- rex signed off, and dana approved from Ready to approve, as in line 1.
- The AI rule `acronyms-expanded` reported "AI rules skipped: no AI provider configured". Fix with AI is disabled without a provider, so it was not run; its unit tests stand for it.

## 3. Git — fail, fixed, then pass

Setup:

- `git clone --recurse-submodules http://pat:…@127.0.0.1:8099/git/yars wtclone`: the `acme` submodule was checked out.
- `git -C wtclone/engagements/acme switch main`.
- `yars hook install --data wtclone`: "installed acme".
- F-002 "Open redirect after logout" was made on the website as pat.

Commits and pushes:

- **A rule error warns and goes through.** In the clone, a title ending in a dot, then `git commit -a`: "error title-no-trailing-dot: The title must not end with a dot … (commit not blocked)", and the commit was made.
- **First push: fail.** A commit with `cvss: CVSS:3.1/…/I:Q/A:N`, then `git push`: refused with "invalid value Q for I". That says what is wrong, not how to fix it.
- **The fix.** Commit 54cac0f, with the test `TestParseErrorsSayHowToFix` seen failing first. A vector that does not parse now names the values the metric takes, and a missing metric by name.
- **Run again** with the rebuilt binary:
  1. The same push: refused with "invalid value Q for I (Integrity): use N, L or H".
  2. Amended to `I:L` (every commit of a push is checked, D9): refused with "severity (none) does not match the CVSS vector (score 5.4 is medium); set severity: medium".
  3. Amended again: the push landed (`4e840aa..8549a32`). The rule errors were printed as checks that block Submit.
- **The open page updates.** pat's F-002 page, left open, showed the new title, the description and "MEDIUM 5.4" without a reload: a marker set on the page survived.

## 4. Export — pass

- First rex signed F-001 off again and dana approved it (Shift+A), so F-001 was complete.
- dana's Export page had F-001 ticked and F-002, a draft, disabled. Each download was posted from the page:

| Download | Answer |
|---|---|
| `zip` | 200 `application/zip`, `acme-html.zip`; its `acme/index.html` holds the finding, its severity and its table |
| `pdf` | 200 `application/pdf`, `acme.pdf`, begins `%PDF-`, 14,847 bytes (pandoc and xelatex, 1.5 s) |
| `docx` | 200 Word type, `acme.docx`, 11,021 bytes |

## 5. MCP over HTTP — pass

`yars token add --kind mcp --name walkthrough pat`. A Go client using only `net/http` and `encoding/json` POSTed JSON-RPC to `/mcp` with the bearer token:

1. `initialize`
2. `list_findings` (acme, status draft): F-002
3. `read_finding` F-002: draft, 4 violations, the Impact section's base
4. `set_field` on the title, `cvss_reason.UI`, `.C` and `.I`, and reviewers `rex`, which cleared the errors the push left
5. `update_section` Impact, with the base
6. `start_check`, then `get_check_results` until done
7. `transition` submit

`read_finding` then answered verification. pat's open page showed VERIFICATION and the new Impact without a reload.

## 6. Redact and purge — pass

- pat made F-003 "Session token in screenshot" and used the Description editor's Add file (a PNG).
- The Redact dialog opened before the upload. It was saved with no boxes, so the original was uploaded and its link inserted; then Description was saved.
- A pull gave the image's blob, `80321ec`.
- In the editor, Redact on the image, one box drawn, Save: 98 KB became 111 KB.
- dana's attachments row then showed the dot "An earlier version is in git history" and a Purge action.
- The Purge page names the file and the engagement, and says "Existing clones of this engagement must be cloned again". After Purge, the row had no dot and no Purge.
- In a new `git clone …/git/e/acme`, `git cat-file -t 80321ec` fails, as it does in the server's repository. The image's log is the one redaction commit.

## 7. Keyboard only — pass

F-003 was given a severity (low) and a reviewer (rex) with the mouse first. Then, as pat, from the engagement list, keys only:

1. `i` opened the Inbox (My drafts 1).
2. `j` selected the F-003 row (focus on its link), and Enter opened it.
3. `j` five times selected the panels in order: workflow, Details, Assets, CVSS, Description.
4. `e` opened the Description editor with the text focused.
5. Ctrl+End, then a sentence typed.
6. Ctrl+S saved: the editor closed and the panel stayed selected.
7. Shift+S: verification.

## 8. Backup and restore — pass

While 8099 served:

1. `yars backup --data wt --out wt-backup.zip`: "277.4 KB, 1 engagement, 3 findings".
2. `yars restore --from wt-backup.zip --data wt-restored`: schema v22, 1 engagement, 3 findings, secret key: no.
3. `yars serve --data wt-restored --addr 127.0.0.1:8097`.

dana logged in there with her password. `/e/acme` lists F-001 complete (signed off by rex), F-002 in verification and F-003 in verification, as on the live server.

## 9. Integrity — pass

dana, Admin › System, Run integrity:

| Check | State | Result |
|---|---|---|
| Rules | OK | 5 loaded |
| Destinations | OK | 2 destinations |
| pandoc + PDF engine | OK | pandoc 3.10, XeTeX |
| Git server repos | OK | 2 repos |
| AI provider | Off | none configured |
| Disk free | OK | 13.3 GB of 15.2 GB |
| Database integrity | OK | `integrity_check ok`, schema v22 |
| Git repositories | OK | 2 repos, fsck |
