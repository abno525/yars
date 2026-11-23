# YARS — git-backed pentest findings tracker (design)

## Context
The team (~6: 3 pentesters, 2 reviewers, 1 director) uses DefectDojo today and it hurts:
bloated UI with tiny fields, clumsy status changes / reviewer assignment, poor status sorting,
easy to create a finding outside the current pentest, no way for a local AI to edit findings,
and discussion happens in a separate chat with pasted links. Goal: a small, visually clear tool
where **findings are Markdown files in git**, the website is a friendly git viewer/editor,
each finding has an attached chat, and **user-written style rules** make findings uniform
enough that the verification step shrinks to almost nothing.

## Goals / non-goals / anti-goals
- Goals: engagement-scoped workflow, finding content as Markdown in git; accounts, workflow
  state and chat in the server's database (since M10), per-finding chat, Draft→Verification→Complete→Reported flow with role enforcement, retests as new
  engagements seeded from old ones, pluggable rule engine (regex + scripts + AI), pluggable
  exporters (pandoc, Confluence HTML), MCP server for local AI editing.
- Non-goals (v1): scanner imports, product/asset hierarchy, metrics dashboards, SSO, email
  notifications, UI rule builder (rules are files; revisit later).
- Anti-goals: anything resembling Dojo's bloat — deep navigation, tiny form fields, a finding
  that can exist outside an engagement, a database that drifts from git. A git clone is not a
  backup; `yars backup` is.

## Stack (user's choice: Go + htmx)
- Single Go binary, `net/http` + `html/template` + htmx, minimal CSS (no SPA).
- Git via the `git` CLI (shelled out; simplest, fully compatible). Markdown via goldmark;
  YAML front matter via `gopkg.in/yaml.v3`.
- Big, readable editor fields: one large textarea per Markdown section with live preview.

## Repository layout (one data repo, served by the app)
```
yars-data/
  .yars/
    config.yaml          # severities, finding template (section list), AI provider, exporters
    users.yaml           # local accounts: username, bcrypt hash, role
    rules/*.yaml         # style rules
    rules/scripts/*      # rule scripts (any executable)
    exporters/*          # exporter configs / pandoc templates
  engagements/
    2026-11-acme-webapp/
      engagement.yaml    # name, client, type: pentest|retest, source: <engagement id>, dates, members
      findings/
        F-001-sqli-login/
          finding.md     # front matter + sections
          chat.jsonl     # append-only; .gitattributes: merge=union
          attachments/   # screenshots, PoC files
```
`finding.md`:
```markdown
---
id: F-001
title: SQL injection in login form
status: draft            # draft|verification|complete|reported
severity: high
cvss: CVSS:3.1/AV:N/...
author: alice
reviewers: [bob]
retest: { source: <engagement>/F-001, result: not_fixed }   # only in retests
---
## Description
## Location
## Impact
## Steps to Reproduce
## Remediation
## References
```
Section list comes from `config.yaml` template; the UI renders one panel per `##` section and
writes back only that section (round-trips cleanly with local edits).

## Git model
- The server holds the canonical repo and exposes it over **git smart HTTP** (`git http-backend`
  behind the app's own auth). Pentesters clone, edit locally (or with AI), and push.
- Every web edit = one commit authored as the logged-in user ("F-001: edit Impact").
- A **pre-receive check** on push enforces the same rules as the web: role-allowed status
  transitions, error-level rule violations block moving to `verification`, findings must live
  under an engagement.
- History/diff tab per finding = `git log -p` on that directory, rendered per section.
- In-memory index (status, severity, author, reviewer, engagement) rebuilt on HEAD change →
  fast sorting/filtering by status.

## Workflow & roles
| Transition | Who | Gate |
|---|---|---|
| draft → verification | author (pentester) | no error-level rule violations; reviewers assigned |
| verification → draft | reviewer | requires a chat message (reason) |
| verification → complete | director (after reviewer clear) | ≥1 reviewer "cleared" |
| complete → reported | exporter run | set automatically on successful export |
- Notifications: in-app only — "Awaiting my review / My returned drafts" inbox + badge.
- UI is always **inside one engagement** (engagement switcher at top; "New finding" only
  exists within an engagement). Main view: one table, sortable/filterable by status, severity,
  author; one-click status buttons; reviewer assign inline.

## Retests
"New retest from engagement X" creates a new engagement (`type: retest`, `source: X`), copies
selected findings with fresh status `draft` and a `retest.result` field
(fixed / not_fixed / partially_fixed) plus a link to the original. Original engagement is
never modified. New findings can be added normally.

## Chat
`chat.jsonl` per finding: `{ts, user, text, section?, resolves?}`. Messages can be anchored to a
section (shown next to it) and marked resolved. Open threads show as a count in the table.
Live updates via htmx polling (SSE later if needed). Committed in batches to keep history readable.

## Rule engine
Rule file example:
```yaml
- id: title-no-trailing-dot
  target: title
  regex_forbid: '\.$'
  level: error
  message: "Title must not end with a dot"
- id: no-backticks-location
  target: section:Location
  regex_forbid: '`'
  level: error
- id: cvss-nonstandard-justified
  script: scripts/cvss_justified.py   # gets finding JSON on stdin, prints violations JSON
  level: error
- id: acronyms-defined
  ai: "Every acronym must be expanded on its first use, e.g. 'Cross-Site Scripting (XSS)'."
  target: section:Description
  level: warning
```
- Kinds: `regex_require`/`regex_forbid`, built-in checks (e.g. `table-cells` for backticks in
  table cells), `script` (any executable, JSON in/out, timeout), `ai` (plain-English rule sent to
  the configured LLM, returns structured violations with quotes).
- Runs: live in editor (regex/built-ins on keystroke-debounce; script/AI on save), on submit,
  in pre-receive, and via CLI `yars lint <path>` / MCP tool.
- AI provider: OpenAI-compatible client configured with base URL + key (covers OpenAI, LiteLLM
  proxy) plus a native Anthropic option. AI results cached by content hash.

## Exporters
Exporter = config in `.yars/exporters/` that renders findings (engagement or selection) to an
output. Built-in: **pandoc** (Markdown → docx/pdf/html with user templates) and
**Confluence HTML** (HTML suited for pasting/pushing into Confluence; optional API push).
Script exporter type for anything else. Successful export marks findings `reported`
(commit by exporter run user).

## MCP server
`yars mcp` (stdio, for local clone) and HTTP endpoint (token per user) exposing tools:
list_engagements, list_findings(filter), read_finding, update_section, set_field,
add_chat_message, lint_finding, create_finding. Same role/transition enforcement.

## Auth
Local accounts in `users.yaml` (bcrypt), roles: pentester / reviewer / director / admin.
Session cookies for web; same credentials (or per-user token) for git HTTP and MCP.

## Build order (each a usable milestone)
1. Data model + repo layout + index + read-only web viewer (engagement → table → finding).
2. Web editing per section with commits; auth; engagement scoping.
3. Status workflow, reviewer assignment, inbox.
4. Chat.
5. Rule engine (regex/built-in → script → AI) + `yars lint`.
6. Git smart HTTP + pre-receive enforcement.
7. Retests.
8. Exporters (pandoc, Confluence HTML).
9. MCP server.

## Verification
- Go unit tests: front-matter/section round-trip, rule engine per kind, transition matrix,
  retest copying.
- Integration test: temp repo → create engagement/finding via HTTP → edit section → assert git
  commit/author; push a forbidden transition via git and assert rejection.
- Manual: run `yars serve` on a sample repo, walk a finding draft→reported with 3 accounts,
  clone + edit locally + push, run `yars lint`, connect MCP from Claude Code and edit a section,
  export via pandoc to docx.

## My calls (please check)
- Single data repo for all engagements; server hosts it over git HTTP (not an external Gitea).
- Chat stored in git as `chat.jsonl` (union merge), not a database.
- In-app notifications only; no email in v1. No UI rule builder in v1.
- Retest findings restart at `draft`.
- Reviewer "clear" is a recorded action; director moves to complete.
