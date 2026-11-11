# RUN — how a builder and a reviewer finish YARS unattended

This file is the entry point. Where it disagrees with a milestone plan, this file wins.

## Start

Give a new session this prompt, in the repository root:

> Read `docs/superpowers/plans/RUN.md` and follow it to the end. You are the builder; start a second agent as the reviewer for every task. Do not ask me anything: every decision is in the plans, and what is not is covered by the rules in RUN.md. Stop only when `PROGRESS.md` shows every milestone done or blocked.

## What is already done

- M19: `feat/redesign` is pushed; PRs #8–#13 are open (branches `pr/08-review-fixes` … `pr/13-push-rules-round-3`).
- M20 task 1: the decisions file, the keyboard inventory and these plans are committed on `feat/redesign`.

Start with M20 task 2 on a new branch `pr/14-hygiene-ci` cut from `feat/redesign`.

## Order and branches (replaces every "Branch:" line in the plans)

One linear stack. Each branch is cut from the one above it when that milestone's PR is open.

| # | Plan file | Branch | PR |
|---|---|---|---|
| M20 | `2026-11-11-m19-m20-land.md` (tasks 2–5) | `pr/14-hygiene-ci` | #14 |
| M21 | `2026-11-11-m21-backup-restore.md` | `pr/15-backup-restore` | #15 |
| M22 | `2026-11-11-m22-hardening.md` | `pr/16-hardening` | #16 |
| M23 | `2026-11-11-m23-catch-up.md` | `pr/17-catch-up` | #17 |
| M24 | `2026-11-11-m24-finding-page.md` | `pr/18-finding-page` | #18 |
| M25 | `2026-11-11-m25-admin-system.md` | `pr/19-admin-system` | #19 |
| M26 | `2026-11-11-m26-redaction.md` | `pr/20-redaction` | #20 |
| M27 | `2026-11-11-m27-revert.md` | `pr/21-revert` | #21 |
| M28 | `2026-11-11-m28-structure.md` | `pr/22-structure` | #22 |
| M29 | `2026-11-11-m29-keyboard.md` | `pr/23-keyboard` | #23 |
| M30 | `2026-11-11-m30-precommit-hook.md` | `pr/24-precommit-hook` | #24 |
| M31 | `2026-11-11-m31-ai-fix.md` | `pr/25-ai-fix` | #25 |
| M32 | `2026-11-11-m32-mcp-v2.md` | `pr/26-mcp-v2` | #26 |
| M33 | `2026-11-11-m33-m35-finish.md` | `pr/27-colour-tokens` | #27 |
| M34 | same file | `pr/28-polish` | #28 |
| M35 | same file | `pr/29-release` | #29 |

Schema versions follow this order: v19 in M23 task 7, v20 in M25 task 3, v21 in M26 task 1, v22 in M29 task 6.

## Rules for an unattended run

1. **No gates.** Every "Gate:" line in a plan that waits for the user or for the canvas is lifted. The user's answers are in the roadmap. Build with the visual defaults below. Do not edit the canvas.
2. **Never ask the user.** A choice the plans do not make is made by this order: (a) do what the same kind of thing already does elsewhere in the code; (b) the smaller change; (c) the stricter behaviour. Write every such choice, and every place the result differs from a plan, in `docs/superpowers/review-after.md` (milestone, task, what, why), and commit it with the task.
3. **Never merge, never force-push, never touch `master`.** Push branches and open PRs. Each PR's base is the previous PR branch.
4. **One task = one TDD cycle**, as each plan describes. A test that cannot fail first is not a test: see it fail.
5. **Builder and reviewer.** After each task the reviewer, a fresh agent that sees only the plan's task and the diff, checks: the named tests exist and assert what the plan says; nothing outside the task changed; the "Review focus" lines that name this task hold; `go vet ./...` and `go test ./...` pass. The builder fixes what the reviewer finds before the next task. At the end of a milestone the reviewer reads the whole branch diff once more.
6. **PR size.** Before opening a PR run `git diff --shortstat <base> <branch>`. Above 8,000 changed lines: split at a task boundary into two branches (`pr/NNa-…`, `pr/NNb-…`) and two PRs.
7. **Browser checks.** Where a task has one: build (`go build -o <scratchpad>/yars ./cmd/yars`), make data (`<scratchpad>/yars seed --data <scratchpad>/data --engagements 2 --findings 20 --messages 50`; it prints the users and their password), serve on a free port (`serve --data <scratchpad>/data --addr 127.0.0.1:8099`), and use the browser tools at 1440 × 900, light theme. A browser check that cannot run (no browser tool in the session) is recorded in `review-after.md` as "not run", and the task goes on.
8. **Optional tools.** No AI provider, pandoc or xelatex is assumed. Tests use fakes; a manual step that needs one is recorded as "skipped: not available".
9. **Blocked.** When a task's tests cannot be made to pass in three honest attempts: undo its changes (`git restore` the files; keep earlier commits), write the task into `PROGRESS.md` as `blocked` with what was tried and the failing output, and go on with the next task that does not use what the blocked one produces (its "Interfaces produced"). A milestone with a blocked task still gets its PR; the PR body lists the blocked task.
10. **Shell.** This repository's session hook refuses commands with quotes, pipes, `$`, `*`, `;`, `&`, `<`, `>` or line breaks. So: one plain command per call; search with `git grep -n -e <word> -- <path>` or the Read tool; write files with the Write and Edit tools; commit with `git commit -F <file>` where the file (in the scratchpad) holds the message; open PRs with the GitHub tool `create_pull_request` (owner `abno525`, repo `yars`), not `gh` with a quoted title.
11. **Commit messages** are `type(scope): sentence`, a blank line, then `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`. PR bodies end with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
12. **UI rules** (always): labels and values only, no explanatory text; fixed button widths (`w96`, `w112`, `w128`, `w136`, `w152`) and positions; an absent control leaves `<span class="slot wNNN"></span>`; every table has a header row; an empty table uses `{{template "empty_row" N}}`; desktop width only.

## Progress file

Keep `docs/superpowers/plans/PROGRESS.md`, one line per task, committed with each task:

```
M21 task 1  done     <commit>
M21 task 2  done     <commit>
M22 task 4  blocked  see below
M21 PR      opened   #15
```

A session that starts and finds this file continues at the first task without a line. Tick the plan's checkboxes as well.

## Visual defaults (used where a plan says "from the canvas")

| Thing | Default |
|---|---|
| Selected panel (M29) | `[data-kpanel][data-sel] { outline: 1px solid var(--ink); outline-offset: -1px; }` |
| Checks strip (M24) | closed height 48 px; `summary.panelhead { cursor: pointer; list-style: none; }`; the open body is the existing `.checkbody` |
| Status event in chat (M24) | reuse the rules of `.events .event` for `.chatev` (same marker colours per `ev-<kind>`) |
| More menu (M24) | the existing `details.pop` and `.poplist` styles |
| Duplicates in the side column (M24) | the existing table with class `compact`; if it is wider than the 560 px column, hide its score column with `.side .dups .num { display: none; }` |
| Attachments panel (M24) | `.table.stable`; columns Name (rest), Type 96 px, Size 96 px, Action 224 px holding two fixed `w96` slots side by side: Open, then Purge or an empty slot |
| History mark (M26) | `.histdot { display: inline-block; width: 8px; height: 8px; background: var(--accent); }`; on a thumbnail `position: absolute; top: 4px; right: 4px`; in a table cell `margin-left: 8px` |
| Purge confirm page (M26) | copy `merge.html`'s layout |
| Revert (M27) | slot `w136`, class `secondary`; its reason form is the existing `.wfpanel` |
| Fix with AI (M31) | label `Fix with AI`, slot `w152`, class `secondary`; while running `Fixing` with the same progress element as `Checking` |
| AI mark (M31) | `<span class="tag ai">AI</span>` with `.tag.ai { background: var(--off-bg); color: var(--ink); }` |
| Shortcut list (M29) | the `.gotodlg` dialog styles; two columns of `kbd` and text |
| Keyboard preference (M29) | a `.frow` in Preferences with a two-option `.seg` (On, Off), as Theme has three |
| Overview (M23) | a second `.tiles` panel "By severity"; bars keep their size; no text inside bars |
| Admin panels (M25) | the existing `.panel.sys` with `.stats` and `.sfields`, as Backup |

Every new colour is a token in `:root` with a value in both dark blocks (use the nearest existing token's values).

## Code locations the plans refer to by name

| What | Where |
|---|---|
| The findings list page: query, links, paging | `internal/web/server.go` `engPage` (`:543`); the `mk` helper builds every list URL from the request's query |
| Bulk bar rows and their actions | `internal/web/bulk.go` `bulkBarFor` (`:264`), `addRow` (`:300`); the inbox's bar at `internal/web/inbox.go:546` |
| Bar and legend templates | `internal/web/templates/board.html:3` (`bar`), `:9` (`legend`) |
| Attachment strip, duplicates panel, presence | `internal/web/templates/assets.html:85`, `:57`, `:83` |
| Field/Value table header | `internal/web/templates/details.html:22` (`kv_head`) |
| Attachments in the store | `internal/store/assets.go`: `Attachments` (`:110`), `AddAttachment` (`:312`), `ReplaceAttachment` (`:330`, the Redact save) |
| Export summary counts | `internal/export/report.go` `Input.Counts` (`:60`), `Report` (`:105`) |
| Remote page links of exports | `internal/db/export.go`: `SetExportRemote` (`:69`), `ExportRemote` (`:79`) |
| Who is notified of what | `internal/notify/notify.go` `recipients` (`:95`), `text` (`:142`) |
| A finding's versions | `internal/history/history.go` `Versions` (`:24`); the page's view in `internal/web/history.go` `historyOf` (`:165`) |
| Preferences form handler | `internal/web/settings.go` `settingsPrefs` (`:291`) |
| AI settings page and wiring | `internal/web/admin_ai.go`: `wireAI` (`:65`), `aiSave` (`:153`) |
| Background workers start and stop | `internal/web/notifications.go`: `startHooks` (`:44`), `Close` (`:52`) |
| Check runs in the database | `internal/db/checks.go`: `StartRun` (`:128`), `LatestRun` (`:159`), `LatestRuns` (`:212`), `FinishedRuns` (`:183`) |
| Chat message kinds and the timeline | `internal/chat/chat.go`: `Timeline` (`:82`), `Validate` (`:125`) |
| The chat panel's view | `internal/web/chat.go`: `chatView` (`:90`), `eventText` (`:107`) |
| Workflow bar layout | `internal/web/workflow.go`: `wfLayout` (`:124`), `arrange` (`:147`), `wfGated` (`:277`) |
| The push hook process | `cmd/yars/main.go` `cmdHook` (`:393`); `pushRunner` (`:488`) |

Line numbers are of commit `8f570ff`; after M28 the store's functions live in the files M28 names.

## When everything is done

The last commit of the run updates `PROGRESS.md` and `review-after.md`. The user then reviews and merges PRs #1–#29 in order, reads `review-after.md` and `docs/known-limits.md`, and tags `v1.0.0`.
