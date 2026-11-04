# Deferred minors (polish backlog)

Small issues found by the end-of-milestone reviews and deliberately left for the polishing phase.

## Core (M1–M2)
- Section anchor IDs can collide for non-ASCII section names.
- Heading trailing spaces are trimmed; an empty `## ` heading creates a section with no route.
- A BOM, empty front matter, or a file ending in `---` without a newline is rejected; the finding page shows a bare 500.
- Writes aren't atomic (truncate + write).
- Sessions never expire; users load only at startup; no login rate limit.
- No server timeouts or request body limits.

## M3 Workflow
- A 403 after a finding gets locked is invisible in an open htmx editor (plain-text 403 isn't swapped).
- The workflow bar isn't refreshed after a content save drops clearances (stale ✓ until reload).
- A denied action re-renders at the POST URL; a typed return reason is lost.
- The author can empty the reviewer list during verification.
- Every full page 500s if the index fails (the inbox badge is computed in `base()`).
- `cvss/calc` renders the editor on a locked finding (writes nothing).

## M4 Chat
- Readers can briefly see a half-written chat.jsonl (truncate-then-write; readers don't take the lock).
- A failed reply's text lands in the main composer.
- Resolving an already-resolved thread (double click) makes an extra commit.
- Replies can carry a section tag that means nothing.
- Missing timestamps in hand-edited lines show as `0001-01-01 00:00`.
- Sorting by Chat starts ascending (0 open first).
- Section open-thread counters only update on reload.
- After a server restart, polling with an expired session swaps the login page into the chat column.
- Test gaps: commit-failure rollback for chat; `.gitattributes` created by a transition; composer untouched by poll swaps.

## M5 Rules
- `yars lint`: a scope that matches nothing exits 0; flags after the positional scope are ignored; scope takes the dir name, not the ID; rule problems repeat per finding (and aren't printed with zero findings).
- `Errors()` doesn't de-duplicate: 20 identical backtick errors show 20 times in the bar/banner.
- The `cvss-explained` built-in duplicates the workflow gate's CVSS check (both messages shown).
- Script/AI messages aren't length-capped; the AI cache grows without bound; script results aren't cached; `/checks` has no rate limit.
- Anthropic `max_tokens: 1024` can truncate long replies; `base_url` ending in `/v1` for Anthropic gives `/v1/v1/messages`.
- AI error text (first 80 chars of a 401 body) is shown to users; show only the status code.
- Live hints run on the untrimmed body; the panel on the trimmed one (`$` at end can differ).
- Table check: rows in indented code blocks flagged, tables in blockquotes missed, continuation rows without `|` missed.
- Rules dir signature (name/size/mtime) can miss a same-size rewrite within mtime resolution.
- Script timeout kills only the direct child; grandchildren survive (use a process group).
- No test for a symlink pointing outside the rules dir; problems for a rule without an id have an empty rule field.
- Error-level AI rules can flip between runs (LLM variance, in-memory cache only); prompt injection in finding text can pass an AI rule.

## M6 Git
- Old repos still have password hashes in their git history (users.yaml is untracked from now on; rewrite history if that matters).
- Credential cache: a removed/re-passworded user keeps fetch access until restart; expired entries are never purged.
- Hook ignores scanner errors / malformed stdin lines (should fail closed).
- Intermediate commits of a push aren't path-checked (only authorship and the final tree).
- Git prints "warning: redirecting to …/git/yars/" (an extra round trip); serve the no-slash form directly.
- `TestPushForceRejected` doesn't assert the rejection reason; no end-to-end tests for branch delete or tags.
- A dirty server working tree blocks every push ("unstaged changes") — needs an operator note/log line.
- No rate limit on failed git Basic auth.

## M7 Retests
- A `retest.source` without "/" renders an empty link and status pill.
- "Result" sorts alphabetically (Not fixed before Partially fixed).
- Retest result form has no optimistic-concurrency base (last writer wins).
- Non-validation errors from creating a retest were shown raw (now routed to the generic error page — verify the copy).
- Banner links to `/e/` when a hand-made retest engagement has no `source`.
- Attachments aren't copied; section Markdown referencing `attachments/…` breaks in copies.

## M8 Exporters
- Formats with pandoc extensions (`docx+styles`) are rejected rather than supported.
- `#` headings inside finding bodies render at the same level as finding titles (breaks TOC).
- Control characters (ANSI escapes from pasted output) make Confluence storage XML invalid; task-list checkboxes may be rejected by Confluence.
- CLI `yars export`: `--mark/--as` validated after writing; marking failures exit 0; unknown dirs silently dropped; config load errors show as "unknown exporter"; flags after the engagement are treated as dirs.
- Duplicate `finding=` values duplicate a finding in the report.
- Client disconnect is reported as "pandoc timed out"; a full stderr cap can stall pandoc until the timeout.
- Script exporter JSON has capitalised engagement keys (`ID`, `Name`).
- `safePath` rejects a missing file literally named `..foo`; weak path-escape tests (depend on /etc/hostname).
- Content types rely on the system mime table (octet-stream fallback).
- No limit on concurrent exports (100 MB buffers each).
- Confluence push embeds images as data URIs, which Confluence may not render (needs the attachments API).
- This pandoc build can't run docx under `--sandbox`; the fallback runs unsandboxed (images/HTML are pre-sanitised).

## M9 MCP
- `create_finding` doesn't apply `UpdateTitle`'s one-line/200-char check.
- Lookup by ID matches front-matter `id`, not the dir prefix; duplicates pick the first silently (should be "ambiguous").
- JSON-RPC: batches get -32700 (should be -32600); `jsonrpc` field unchecked; a stdio line over 8 MB ends the session.
- HTTP: `Bearer` matched case-sensitively; no OAuth protected-resource metadata (Claude Code may show "needs authentication" on a bad token — documented).
- Token CLI: revoking an unknown user succeeds silently; no per-token revoke or token ids in `list`; `.gitignore` migration can duplicate the comment line.
- Test gaps: non-author pentester `set_field reviewers`/`clear` via MCP; revoke on a running server over HTTP end-to-end.
