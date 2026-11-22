# YARS — roadmap from M18 to v1.0

> **For agentic workers:** this file is the index. Each milestone has its own plan file, listed below. REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans on one milestone file at a time. Read this file first: its constraints, fixtures and architecture notes apply to every milestone.

**Goal:** land the work that exists, build everything already decided, make the server safe to run for real, and stop at a defined v1.0.

**Tech stack:** Go 1.27, `modernc.org/sqlite`, `goldmark`, `yaml.v3`, htmx 2, the `git` CLI, pandoc + xelatex (optional).

**Specs:**
- `docs/superpowers/specs/2026-11-03-yars-design.md` — original design
- `docs/open-decisions-2026-11-07.md` — every D/K/R/Q answer; the source of truth for behaviour
- `docs/superpowers/plans/2026-11-05-keyboard-shortcuts.md` — control inventory and focus work (key map superseded by M29)
- `docs/superpowers/deferred-minors.md` — polish backlog (triaged in M34)

## Milestones

| # | Plan file | Depends on | Gate before code |
|---|---|---|---|
| M19 | `2026-11-11-m19-m20-land.md` — push, PRs #8–#13 | — | — (push approved) |
| M20 | same file — hygiene and CI (PR #14) | M19 | — |
| M21 | `2026-11-11-m21-backup-restore.md` | M20 | — |
| M22 | `2026-11-11-m22-hardening.md` | M20 | — |
| M23 | `2026-11-11-m23-catch-up.md` — audit, search, overview, Q10–Q13 | M20 | user: Q10–Q13 |
| M24 | `2026-11-11-m24-finding-page.md` — D2, D3, D4, D21 | M23 | canvas; user: question 3 below |
| M25 | `2026-11-11-m25-admin-system.md` — D24 | M21 | — (board 6.8 exists) |
| M26 | `2026-11-11-m26-redaction.md` — D28 | M24 | canvas |
| M27 | `2026-11-11-m27-revert.md` — R4 | M20 | canvas |
| M28 | `2026-11-11-m28-structure.md` — file splits, test names | M23–M27 merged | — |
| M29 | `2026-11-11-m29-keyboard.md` | M24, M27, M28 | canvas; user: question 5 |
| M30 | `2026-11-11-m30-precommit-hook.md` — R8 | M20 | — |
| M31 | `2026-11-11-m31-ai-fix.md` — R7 | M23, M24, M25, M28 | canvas |
| M32 | `2026-11-11-m32-mcp-v2.md` — D7, R2 | M27, M31 | user: sign off the proposal |
| M33–M35 | `2026-11-11-m33-m35-finish.md` — colour tokens, polish, release candidate | all | — |

**To run the plans unattended, start from `RUN.md`.** It sets one linear order (M20 to M35, each branch cut from the one before), lifts the gates in the table above, gives the visual defaults to use in place of canvas sign-off, and says what to do when a task is blocked. Where RUN.md and a plan disagree, RUN.md wins. M33 is the colour-token clean-up only: new dark colours are a design task for the user after v1.0.

## Answers from the user (2026-11-11)

1. **Push.** Yes: push `feat/redesign` and the PR branches to `abno525/yars`.
2. **Q10–Q13.** The recommendations in the decisions file.
3. **D3 against R7.** Keep the check threads; D3 only removes the error list under the workflow bar and makes the counts agree.
4. **Pre-commit hook.** The hook asks the server, and the server runs the rules as it runs them for Check, AI rules included (M30).
5. **Single keys from R6.** `n` new finding, `b` team board, `f` findings list, `/` search, `?` shortcut list.
6. **Revert.** A director can revert anything. The author can always move their own finding's state backwards: Reported to Complete and Complete to Verification (M27).

## Global constraints

- Every task is one TDD cycle: write the failing test named in the task, run it and see it fail, implement, run it and see it pass, run `go vet ./...` and `go test ./...`, commit with the message given. The cycle is not repeated in each task.
- A milestone's PR stays under 8,000 changed lines and 500 files. Claude pushes branches and opens PRs and never merges.
- Every builder agent has a reviewer agent. Independent tasks in a milestone run in parallel.
- UI: labels and values only, no explanatory copy; fixed button widths and positions; an absent control leaves an empty slot of the same width; full-width panels; desktop width only; every table has a header row; an empty table shows `{{template "empty_row" N}}`; no dark-mode work before M33.
- A UI change the canvas (https://claude.ai/artifact/8oFftu89VUgY7Kim1zhUS6) does not show is drawn there first. Re-read each artboard from the artifact before editing it. Code starts after the user signs the boards off.
- The website, MCP and a git push behave the same. A rule lives in `internal/store` or `internal/workflow` and is called from all three.
- Every refusal says what to do next and names the file, commit or rule.
- A schema change is a new entry at the end of `migrations` in `internal/db/db.go` and bumps `schemaVersion`. The numbers in the plans assume milestone order; if one is taken, use the next free one.
- Commit messages: `type(scope): sentence`, ending with the Co-Authored-By line.
- Shell commands in the plans are single plain commands (the session's hook refuses pipes, quotes and globs).

## How YARS is built (read before any task)

- **Processes.** `yars serve` is the only long-lived process. `yars hook pre-receive` runs as a separate process inside every push (it opens the same database). CLI commands open the data folder directly.
- **Data folder.** A non-bare main git repo holding `.yars/` (config, rules, exporters, templates) and each engagement as a submodule at `engagements/<id>`, itself a non-bare repo. The work trees are the live data: the store reads files from disk, not from git objects. `.yars/yars.db` (SQLite, WAL) holds accounts, sessions, tokens, workflow state, reviewers, chat, check runs, dismissals, teams, the board, notifications, webhooks and settings.
- **`internal/store`** is the only writer. Content edits go `mutateContent` → `mutateLocked`: take the engagement lock, read, change, check HEAD did not move, write the file with a temp file and rename, commit as the user, release, emit an event. State changes go `changeState`: one database transaction, no git. Approvals and sign-offs are bound to the SHA-256 of `finding.md`, so a change of the text voids them without any reset. A sign-off covers the attachments too: a change to them in verification clears the sign-offs (`dropSignOffs`, through YARS and on push).
- **Locks.** One mutex per engagement repo, one for the main repo; order: engagement before main. A push holds the same lock (`ReceivePush`).
- **`internal/workflow`** holds who may do what (`Check`, `Gate`, `Target`). `internal/policy` checks pushes with the same store validators (`store.FindingProblems`, `CheckEngagement`, `CheckConfig`).
- **`internal/rules`**: rule files in `.yars/rules/*.yaml`; kinds regex, built-in, script, AI; `Engine.Lint` (fast or all) and `Engine.CheckWith` (per-rule hooks). A check run is stored (`check_runs`, `check_steps`, `check_results`) and posts one chat thread per new violation.
- **`internal/index`** is an in-memory table of every finding, rebuilt per engagement when its HEAD or its database counter moves.
- **`internal/web`**: `html/template` pages (`templates/*.html`, shared partials parsed into every page), htmx fragments, one SSE stream per page (`/events`), `static/app.js` (no build step). Handlers are grouped by feature file; each has a `routesX(mux)`.
- **`internal/mcp`**: JSON-RPC over HTTP (`/mcp`, bearer token) and stdio; each tool is an entry in `tools` and calls the store as the user.

## Test fixtures (use these, do not invent new ones)

- **web:** `e := setup(t)` (parallel) or `setupSerial(t)`; `e.do(t, user, method, path, form, headers)` returns a recorder. Users: `alice` (pentester), `bob` and `carol` (reviewers), `dora` (director, admin). Engagement `acme`, finding `F-001-sql-injection` (URL `/e/acme/f/001`). `e.srv.Store`, `e.srv.Rules`, `e.dir`.
- **store:** `s, dir := withEngagement(t)`; the engagement id is the constant `eng`; authors `alice`, `bob` (`gitrepo.Author`); `last(t, dir, "%s")` reads the newest commit.
- **db:** `d, path := open(t)`; `d.now` can be replaced for time.
- **cmd/yars:** `initData(dir)`, `openDB(t, dir)`, and the command functions (`cmdLint(args, out)` and so on) are called directly.

## Decisions: what is built (checked against the code on 2026-11-11)

| Built | Not built (milestone) |
|---|---|
| D9–D12 push checks; D14 per-row edits; D15 live panels; D16 Field/Value header; D17 empty rows; D18 dismiss per row; D20 score dash; D22 two-row bar; D25 clean findings for directors; D26 temporary password; D27 lockout; K10 selects; Q1–Q9; R1.2 clone box kept; R9 dark toggle kept; `e` and Ctrl+S on sections | D2, D3, D4, D21 finding page (M24); D23 search (M23); D24 Admin › System panels (M25); D28 redaction mark and purge (M26); R1.1 overview legends and tables (M23); R10 unscored row (M23); R4 revert (M27); K1–K9, R3, R5, R6 keyboard (M29); R8 hook (M30); R7 AI fix (M31); D7, R2 MCP (M32); D6 dark mode (M33); Q10–Q13 (M23) |

## Not in v1.0

New dark-mode colours (the remake), scanner imports, SSO, a product or asset hierarchy, mobile layouts, keyboard box drawing in Redact, a REST API, export and attachment upload over MCP.
