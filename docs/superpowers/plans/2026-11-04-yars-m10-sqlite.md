# M10 — SQLite for accounts, chat and workflow state

**Goal:** everything that is not finding content lives in SQLite (`.yars/yars.db`); `finding.md` keeps content only.

**Design:** `/home/plato/.claude/plans/the-goal-of-this-foamy-sunrise.md` (approved 2026-11-04), Milestone 10 section.

**Stack:** `modernc.org/sqlite` (pure Go, no cgo), `database/sql`.

## Global constraints
- The database file is `.yars/yars.db`, mode 0600, and git-ignored.
- A finding's state is keyed by `(engagement id, finding id)`. No row means a draft with no reviewers.
- A clearance counts only while `cleared_hash == store.BodyHash(current finding.md)`.
- `Meta.Status`, `Reviewers`, `ClearedBy`, `Returned` and `Retest` are never written to the file. They are filled from the database when a finding is loaded.
- Every state write runs in one transaction and bumps `changes.seq`.

## Tasks
1. **`internal/db`: Open, schema v1, change counter.** Tests:
   - creates the file with 0600;
   - schema version 1;
   - reopen is a no-op;
   - `Bump`/`Seq`.
2. **Accounts in `db`:** users (add, get, list, delete, password, role), tokens (add hash, owner, revoke, list) and sessions (create, lookup with a 14-day idle expiry and `last_seen` refresh, delete). Tests for each, including expiry using an injected clock.
3. **`internal/auth` on the database:**
   - `New(*db.DB)`. Users are read per call, so a new or changed account works without a restart.
   - Sessions are persisted and survive a new `Auth` on the same database.
   - `Tokens` is backed by the database.
4. **Workflow state and chat in `db`:**
   - `State`/`States`/`SetState` and reviewers with `cleared_hash`;
   - `Messages`/`AllMessages`/`AddMessage`.

   Tests:
   - a missing row defaults to draft;
   - a reviewer list round-trips;
   - messages come back in time order.
5. **`finding.Meta` state fields become `yaml:"-"`:**
   - `finding.New` stops writing `status`/`reviewers`.
   - `LegacyState(meta)` reports state keys found in `Extra`.

   Tests:
   - a parsed file with `status:` exposes it via `LegacyState`;
   - `Bytes()` never emits state keys.
6. **Store on the database:**
   - `New(repo, cfg, db)`.
   - Loads fill state.
   - `Transition`, `SetReviewers`, `SetRetestResult`, `PostChat` and `Chat` write the database.
   - `CreateRetest` writes state rows.
   - The clearance reset is removed (handled by the hash).

   Tests:
   - adapt the existing store tests;
   - an edit after clearing makes the clearance not count;
   - a transition makes no git commit.
7. **Index:** state comes from the database, and the refresh key is HEAD + seq. Test: a state change without a commit shows up.
8. **Push policy, content only:**
   - reject state keys in front matter and `chat.jsonl` paths;
   - a locked finding is judged on database state.

   Tests: adapted, plus "push adding status: rejected".
9. **Web, MCP and CLI wiring:**
   - `serve` opens the database and refuses legacy data;
   - `useradd`/`token`/`userdel`/`passwd`/`role` use the database;
   - in MCP stdio without a database, state and chat tools say to use the server;
   - `read_finding` gets a `state` object.

   Tests: adapted fixtures, plus the new commands.
10. **`yars migrate`:**
    - users and tokens go into the database;
    - state is stripped from the files;
    - `chat.jsonl` goes into the database and the files are removed, in one commit;
    - the command is idempotent.

    Test: a fixture in the old layout.

## Review focus
- **Concurrent edit and clear:** the hash binding must make a clearance given on old content not count.
- **Hook database access** while the server holds a write transaction: busy_timeout, no "database is locked".
- **Session token storage:** only the hash, and expired sessions rejected.
- **Migration on a repo with a half-migrated state** (run twice, or interrupted).
- **A push that renames a finding directory:** state is keyed by ID, so it must survive.
