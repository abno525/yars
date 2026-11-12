# Deferred minors (polish backlog)

Small issues found by the end-of-milestone reviews and deliberately left for the polishing phase.

Triaged in M34 (2026-11-12). Each line has one mark: `[fixed <commit>]` (with the test that fails without the fix), `[do]` (fixed in M34 task 2, one commit each), `[won't: <reason>]`, or `[ask]` (goes to `docs/known-limits.md`, "Needs a decision"). A bullet whose parts got different marks is split into one line per part. Tests marked "new" were written in the triage commit: the rule's test for a line that had none.

## Core (M1–M2)
- [do] Section anchor IDs can collide for non-ASCII section names.
- [ask] Heading trailing spaces are trimmed (a save writes the canonical `## Name`).
- [do] A heading of `##` and two or more spaces makes a section with an empty name and no route.
- [do] A BOM, empty front matter, or a file ending in `---` without a newline is rejected.
- [do] A finding that does not parse shows a bare 500 on its page.
- [fixed e656844] Writes aren't atomic (truncate + write). Test: `TestEditReplacesFileAtomically`.
- [fixed dfbdda7] Sessions never expire. Tests: `TestSessionsExpireWhenIdle`, `TestSessionIdleFollowsRetention`.
- [fixed 798aca6] Users load only at startup. Test: `TestAccountChangesApplyAtOnce`.
- [fixed a224c76] No login rate limit (D27: lockout per username). Test: `TestLoginLockout`.
- [fixed e656844] No server timeouts. Test: `TestHTTPServerTimeouts`.
- [do] No request body limits (only attach, restore, rules upload, git and MCP have one).

## M3 Workflow
- [fixed e656844] A 403 after a finding gets locked is invisible in an open htmx editor (plain-text 403 isn't swapped). Test: `TestLockedSaveShowsWhy` (new).
- [fixed e656844] The workflow bar isn't refreshed after a content save drops clearances (stale ✓ until reload). Test: `TestWorkflowBarFollowsContent` (new).
- [do] A denied action re-renders at the POST URL; a typed return reason is lost.
- [do] The author can empty the reviewer list during verification.
- [do] Every full page 500s if the index fails (the inbox badge is computed in `base()`).
- [do] `cvss/calc` renders the editor on a locked finding (writes nothing).

## M4 Chat
- [won't: chat.jsonl no longer exists; chat is in the database since M10] Readers can briefly see a half-written chat.jsonl (truncate-then-write; readers don't take the lock).
- [fixed d1d5fb6] A failed reply's text lands in the main composer. Test: `TestChatBadRef400` (new assertion).
- [do] A failed reply's own text is lost: the list comes back with an empty reply box (found in triage).
- [fixed 172c428] Resolving an already-resolved thread (double click) makes an extra commit. Test: `TestValidateResolveTwice`.
- [do] Replies can carry a section tag that means nothing.
- [won't: hand-edited chat lines no longer exist; chat is in the database since M10] Missing timestamps in hand-edited lines show as `0001-01-01 00:00`.
- [do] Sorting by Chat starts ascending (0 open first).
- [do] Section open-thread counters only update on reload.
- [fixed 43ee24c] After a server restart, polling with an expired session swaps the login page into the chat column. Test: `TestSessionExpiredHX`.
- [won't: chat makes no commit since M10] Test gap: commit-failure rollback for chat.
- [won't: no transition writes `.gitattributes` any more] Test gap: `.gitattributes` created by a transition.
- [fixed e656844] Test gap: composer untouched by poll swaps. Tests: `TestFindingPageLive`, `TestChatPoll204` (new assertion).

## M5 Rules
- [do] `yars lint`: a scope that matches nothing exits 0.
- [do] `yars lint`: flags after the positional scope are ignored.
- [do] `yars lint`: the scope takes the dir name, not the ID.
- [do] `yars lint`: rule problems repeat per finding (and aren't printed with zero findings).
- [fixed edae718] `Errors()` doesn't de-duplicate: 20 identical backtick errors show 20 times in the bar/banner (de-duplicated by its only caller). Test: `TestChecksCountsMatchRows`.
- [fixed 8976f09] The `cvss-explained` built-in duplicates the workflow gate's CVSS check (both messages shown). Test: `TestCVSSProblemListedOnce`.
- [do] Script/AI messages aren't length-capped.
- [fixed e656844] The AI cache grows without bound. Test: `TestAICacheBounded`.
- [ask] Script results aren't cached.
- [ask] `/checks` has no rate limit (one run per finding at a time already).
- [do] Anthropic `max_tokens: 1024` can truncate long replies.
- [do] `base_url` ending in `/v1` for Anthropic gives `/v1/v1/messages`.
- [do] AI error text (first 80 chars of a 401 body) is shown to users; show only the status code.
- [do] Live hints run on the untrimmed body; the panel on the trimmed one (`$` at end can differ).
- [do] Table check: rows in indented code blocks flagged, tables in blockquotes missed, continuation rows without `|` missed.
- [do] Rules dir signature (name/size/mtime) can miss a same-size rewrite within mtime resolution.
- [fixed 93959c3] Script timeout kills only the direct child; grandchildren survive (use a process group). Test: `TestScriptTimeoutKillsChildren`.
- [fixed c825cfd] No test for a symlink pointing outside the rules dir. Test: `TestScriptSymlinkOutsideRefused` (new).
- [do] Problems for a rule without an id have an empty rule field.
- [ask] Error-level AI rules can flip between runs (LLM variance, in-memory cache only).
- [ask] Prompt injection in finding text can pass an AI rule.

## M6 Git
- [ask] Old repos still have password hashes in their git history (users.yaml is untracked from now on; rewrite history if that matters).
- [fixed a3ae50f] Credential cache: a removed/re-passworded user keeps fetch access until restart. Test: `TestCacheFollowsAccountChanges`.
- [fixed f67ec57] Credential cache: expired entries are never purged. Test: `TestCredCachePurged`.
- [do] Hook ignores scanner errors / malformed stdin lines (should fail closed).
- [fixed 5f41a90] Intermediate commits of a push aren't path-checked (D9). Tests: `TestPolicyEveryCommit`, `TestPolicyMergeSideBranch`.
- [won't: the server never redirected; git prints the warning only for a clone URL with a user name in it, and YARS shows none] Git prints "warning: redirecting to …/git/yars/" (an extra round trip).
- [fixed c9cf8e2] `TestPushForceRejected` doesn't assert the rejection reason. Test: `TestPushForceRejected` (new assertion).
- [fixed f8eb169] No end-to-end tests for branch delete or tags. Test: `TestPushDeleteAndTagRefused` (new).
- [fixed 08fc593] A dirty server working tree blocks every push ("unstaged changes"): the tree is put back to HEAD with a log line, after a failed push and at start (793a8d9). Tests: `TestReceivePushRestoresEngagementTree`, `TestSetupRestoresDirtyEngagementTree`.
- [fixed a224c76] No rate limit on failed git Basic auth (the D27 lockout). Test: `TestLoginLockout`.

## M7 Retests
- [do] A `retest.source` without "/" renders an empty link and status pill.
- [do] "Result" sorts alphabetically (Not fixed before Partially fixed).
- [do] Retest result form has no optimistic-concurrency base (last writer wins).
- [do] Non-validation errors from creating a retest go to the generic error page, which is a bare "internal error" line; the form and its input are lost.
- [do] Banner links to `/e/` when a hand-made retest engagement has no `source`.
- [do] Attachments aren't copied; section Markdown referencing `attachments/…` breaks in copies.

## M8 Exporters
- [do] Formats with pandoc extensions (`docx+styles`) are rejected rather than supported.
- [do] `#` headings inside finding bodies render at the same level as finding titles (breaks TOC).
- [do] Control characters (ANSI escapes from pasted output) make Confluence storage XML invalid.
- [do] Task-list checkboxes may be rejected by Confluence.
- [do] CLI `yars export`: `--mark/--as` validated after writing.
- [do] CLI `yars export`: marking failures exit 0.
- [do] CLI `yars export`: unknown dirs silently dropped.
- [do] CLI `yars export`: config load errors show as "unknown exporter".
- [do] CLI `yars export`: flags after the engagement are treated as dirs.
- [do] CLI `yars export` with named finding dirs exports drafts; the website exports finished findings only (R10) (found in triage).
- [do] Duplicate `finding=` values duplicate a finding in the report.
- [do] Client disconnect is reported as "pandoc timed out".
- [won't: does not happen; past the cap the pipe is closed and pandoc stops at once] A full stderr cap can stall pandoc until the timeout.
- [fixed 5d21d09] Script exporter JSON has capitalised engagement keys (`ID`, `Name`). Test: `TestScriptExporterKeys`.
- [do] `safePath` rejects a missing file literally named `..foo`.
- [fixed 101b616] Weak path-escape tests (depend on /etc/hostname). Tests: `TestExporterPathEscape`, `TestFullZip` (new: files that exist, outside the folder).
- [do] Content types rely on the system mime table (octet-stream fallback).
- [do] No limit on concurrent exports (100 MB buffers each); PDF has two workers already.
- [ask] Confluence push embeds images as data URIs, which Confluence may not render (needs the attachments API).
- [ask] This pandoc build can't run docx under `--sandbox`; the fallback runs unsandboxed (images/HTML are pre-sanitised).

## M9 MCP
- [fixed c5cd243] `create_finding` doesn't apply `UpdateTitle`'s one-line/200-char check. Test: `TestMCPCreateFindingTitle`.
- [fixed 82dabad] Lookup by ID matches front-matter `id`, not the dir prefix; duplicates pick the first silently (should be "ambiguous"). Tests: `TestIDByFrontMatterToo`, `TestAmbiguousIDRefused`.
- [fixed 8e1dfb6] JSON-RPC: batches get -32700 (should be -32600); `jsonrpc` field unchecked; a stdio line over 8 MB ends the session. Tests: `TestBatchIsInvalidRequest`, `TestRejectsWrongJSONRPC`, `TestStdioLongLineGoesOn`.
- [fixed 8e1dfb6] HTTP: `Bearer` matched case-sensitively. Test: `TestBearerAnyCase`.
- [ask] HTTP: no OAuth protected-resource metadata (Claude Code may show "needs authentication" on a bad token — documented).
- [do] Token CLI: revoking an unknown user succeeds silently.
- [fixed bc9f7c0] Token CLI: no per-token revoke or token ids in `list`. Test: `TestTokenCommandScopes` (new assertion for the ids).
- [do] Token CLI: `.gitignore` migration can duplicate the comment line (a repo with an older comment gets the new one as well).
- [fixed f29d296] Test gap: non-author pentester `set_field reviewers`/`clear` via MCP. Test: `TestMCPPermissions` (new assertions).
- [fixed bc9f7c0] Test gap: revoke on a running server over HTTP end-to-end. Test: `TestMCPRevokeFromAnotherProcess` (new).

## M10 SQLite
- [do] Migration: a token in tokens.yaml for a user missing from users.yaml aborts the migration (should skip with a warning).
- [do] Migration: chat dedupe is by global message id; a finding folder copied with its chat.jsonl loses the second copy's chat (report it).
- [do] CreateRetest commits the copies, then writes their retest links in a separate transaction; if that fails the copies look like plain drafts.
- [do] CreateRetest with no database succeeds silently.
- [do] Saving an unchanged section of a pushed file in non-canonical format rewrites it and voids clearances.
- [do] Hook: a transient database error is reported as "the finding is complete; only a director can change it" (should be "server busy, retry").
- [fixed 790771f] Sessions: expired rows are only deleted when looked up (a daily prune). Test: `TestPruneAuditAndSessions`.
- [fixed d51c4aa] Sessions: the cookie MaxAge (14 days) is set at login only. Test: `TestCookieRefreshedOnPageLoad`.
- [ask] Attachments are not covered by the clearance hash.
- [fixed 43ee24c] Attachments are not covered by the complete-lock (website; the push since 1d3eaac). Tests: `TestAttachments`, `TestPolicyLockedAttachments`.
- [do] Clear binds to the content at click time, not to the version the reviewer viewed (send the viewed hash with Clear and reject on mismatch).
- [ask] A director's push to an approved finding moves the approval in pre-receive; if the push then fails to land, the finding falls back to verification (safe, but surprising).

## M11 Repo per engagement
- [do] `Store.commit` returns before its rollback when the engagement repo can't be opened.
- [do] `Store.commit` routing looks only at the first path (every caller passes one engagement today).
- [fixed e656844] `Store.Version()` runs ~2 git processes per engagement on every index refresh check. Test: `TestVersionStartsNoGit`.
- [do] Two first requests to a new engagement repo can race in `setupRepo` (config.lock → 500).
- [do] The `ready` map of set-up repos is never invalidated.
- [do] Migration import commits (fallback path) sweep in files the main repo's `.gitignore` excluded.
- [fixed 5cb56df] SyncPointers commits in the main repo under the store lock only; a concurrent push to main can hit index/HEAD lock contention. Test: `TestReceivePushMainRepo`.
- [ask] A push to the main repo can be refused as non-fast-forward right after the server moved pointers (pull first — documented).
- [do] Docs: no guidance for pre-M11 clones with unpushed work (they get modify/delete conflicts after the migration).
- [do] Docs: `git pull --recurse-submodules` puts submodules back on a detached HEAD.
