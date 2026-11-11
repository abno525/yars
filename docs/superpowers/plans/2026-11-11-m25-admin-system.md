# M25 — Admin › System: Run integrity, Retention, AI usage, Restore

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Read `2026-11-11-yars-roadmap-to-v1.md` first. Steps use checkbox (`- [ ]`) syntax.

**Goal:** the four missing parts of board 6.8 exist: one button that checks everything, retention settings that are enforced, AI calls with their cost, and a restore from an uploaded backup.

**Architecture:** retention is three server settings and one daily worker in `web.Server` (the pattern of the webhook worker). AI usage is recorded by a callback on `rules.Runner` into a new table; the finding and the user travel in the request context. Restore reuses `internal/backup` (M21) and never touches the running data folder: it unpacks beside it and tells the admin how to switch.

**Spec:** `docs/open-decisions-2026-11-07.md` D24 and the note on it: build Retention and AI usage; build Restore; remove "Test destinations" (the app never had it); one "Run integrity" button replaces "Check again".

**Branch:** `pr/19-admin-system` from the branch that holds M21.

**Gate:** none. Board 6.8 is the layout.

## Review focus

1. Retention must never delete the latest check run of a finding: the Require Check gate reads it (task 2 `TestPruneKeepsLatestRun`).
2. A retention value of 0 means keep, not delete everything (task 2 `TestPruneZeroKeepsAll`).
3. A cached AI reply costs nothing and must not be counted (task 3 `TestCachedReplyIsNotUsage`).
4. An uploaded backup from a newer YARS, or a file that is not a backup, must leave no folder behind (task 4).
5. A restore upload larger than the server's 60 s read timeout allows must still arrive (task 4: the route lifts the deadlines).

---

### Task 1: Run integrity

**Files:** modify `internal/web/admin_system.go:62-66,348-374,407-420`, `internal/db/admin.go`, `internal/web/templates/admin.html:249`, `internal/web/admin_system_test.go`

**Interfaces produced:**

```go
package db
// Integrity runs SQLite's full integrity check ("ok" when sound).
func (d *DB) Integrity() (string, error)
```

Rules: the button's label becomes `Run integrity` (same route `POST /admin/system/check`, same slot `w128`). A run adds two rows to the Health table after "Database integrity": the existing row now reports `integrity_check` instead of `quick_check` when run from the button; a new row **Git repositories** runs `gitrepo.Repo.Fsck()` (M21) on the main repo and every engagement repo: `OK · <N> repos` or `Error · <first failing repo>` with the git message as detail. On the plain page load (no button) the git row shows `Not run` (state `off`), as the AI row does.

- [ ] **Step 1: write the failing tests.** `TestRunIntegrityButton` (the System page has a button `Run integrity` and no `Check again`); `TestRunIntegrityRunsFsck` (after the POST the Health table has `Git repositories` with `OK · 2 repos`); `TestRunIntegrityReportsBrokenRepo` (delete a loose object of the engagement repo; the row is `Error` and names `acme`); `TestIntegrity` (`db`): returns `ok`.
- [ ] **Step 2–4:** fail, implement, pass. **Step 5:** commit: `feat(admin): Run integrity checks the database and every repository (D24)`.

### Task 2: Retention

**Files:** create `internal/db/retention.go`, `internal/db/retention_test.go`, `internal/web/retention.go`, `internal/web/retention_test.go`; modify `internal/db/accounts.go:15,523-542` (session idle), `internal/web/notifications.go` (start the worker beside the webhook worker), `internal/web/admin_system.go`, `internal/web/templates/admin.html` (new panel after Backup)

**Interfaces produced:**

```go
package db
// Retention is how long things are kept, in days; 0 keeps them for good.
type Retention struct{ AuditDays, CheckRunDays, SessionDays int }
// Setting keys and defaults.
const (
	RetainAuditKey    = "retention.audit_days"     // default 0
	RetainCheckRunKey = "retention.check_run_days" // default 90
	RetainSessionKey  = "retention.session_days"   // default 14
)
func (d *DB) Retention() (Retention, error)             // settings with the defaults applied
func (d *DB) SetRetention(r Retention) error            // each value 0–3650
type Pruned struct{ Audit, CheckRuns, Sessions int }
// Prune deletes what is older than r allows at now.
func (d *DB) Prune(now time.Time, r Retention) (Pruned, error)
```

Rules for `Prune`:
- Audit: `DELETE FROM audit WHERE ts < cutoff` when `AuditDays > 0`.
- Check runs: when `CheckRunDays > 0`, delete runs with `finished != ''` and `finished < cutoff` whose id is not the highest id of their `(eng, fid)`. Results and steps go with them (the tables cascade).
- Sessions: delete rows with `last_seen < now - SessionDays` when `SessionDays > 0`. `SessionUser` uses the same number of days as the idle limit (read through `d.Retention()`; 0 means the constant `SessionIdle`).

Worker: `func (s *Server) startRetention()` runs `Prune` once at start and then every 24 hours until `s.stop` closes; a run that deleted anything writes the audit entry `retention.prune` by `yars` with the detail `audit <N> · check runs <N> · sessions <N>`. Panel "Retention": three number inputs (`audit_days`, `check_run_days`, `session_days`, each `w96`, `min=0 max=3650`), a Save button (`POST /admin/system/retention`), and the stats `Last prune` (time and detail of the newest `retention.prune` audit entry, `—` when none).

- [ ] **Step 1: write the failing tests.**
  - `TestPruneKeepsLatestRun`: three finished runs of one finding, all older than the cutoff: two are deleted, the newest stays with its results.
  - `TestPruneZeroKeepsAll`: `Retention{}` deletes nothing.
  - `TestPruneAuditAndSessions`: rows older than the cutoff go, newer stay.
  - `TestRetentionDefaults`: an empty database returns `{0, 90, 14}`.
  - `TestRetentionFormSaves` (`web`): the POST stores the values and writes the audit entry `setting.retention`; a value of `-1` or `4000` answers 400 and stores nothing.
  - `TestSessionIdleFollowsRetention` (`db`): with `SessionDays: 1`, a session idle for two days is refused.
- [ ] **Step 2–4:** fail, implement, pass (`go test ./internal/db ./internal/web`). **Step 5:** commit: `feat(admin): retention for the audit log, check runs and sessions (D24)`.

### Task 3: AI usage

**Files:** create `internal/db/aiusage.go`, `internal/db/aiusage_test.go`; modify `internal/db/db.go` (schema v20), `internal/rules/ai.go:78-83,87-104,108-130,176-233`, `internal/rules/slow.go:21-35`, `internal/store/checks.go:503,515,518` (the three places a run calls the linter with `context.Background()`), `internal/web/admin_ai.go` (`wireAI`, the form), `internal/web/admin_system.go`, `internal/web/templates/admin.html`

**Interfaces produced:**

```go
package rules
// Usage is one call to the AI provider.
type Usage struct {
	Purpose         string // "rule", "test", later "fix"
	Provider, Model string
	Rule            string
	User, Eng, Fid  string // from the context (WithCaller); "" when unknown
	In, Out         int    // tokens as the provider reported them
	Took            time.Duration
	OK              bool
}
// OnUsage, when set, is told about every provider call (never a cached reply).
// Runner gains the field:  OnUsage func(Usage)
// Caller names who a run is for and on which finding.
type Caller struct{ User, Eng, Fid string }
func WithCaller(ctx context.Context, c Caller) context.Context

package db
// migration v20:
// CREATE TABLE ai_usage (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, username TEXT NOT NULL DEFAULT '',
//   purpose TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL, eng TEXT NOT NULL DEFAULT '',
//   fid TEXT NOT NULL DEFAULT '', rule TEXT NOT NULL DEFAULT '', tokens_in INTEGER NOT NULL DEFAULT 0,
//   tokens_out INTEGER NOT NULL DEFAULT 0, ms INTEGER NOT NULL DEFAULT 0, ok INTEGER NOT NULL DEFAULT 0);
// CREATE INDEX ai_usage_ts ON ai_usage(ts);
type AIUsage struct{ TS, User, Purpose, Provider, Model, Eng, Fid, Rule string; In, Out, MS int; OK bool }
func (d *DB) AddAIUsage(u AIUsage) error
type AITotal struct{ User string; Calls, In, Out int } // User "" = everyone
// AITotals sums the calls since a time: the total first, then one row per user by calls.
func (d *DB) AITotals(since time.Time) ([]AITotal, error)
const AIPriceInKey, AIPriceOutKey = "ai.price_in", "ai.price_out" // per million tokens, decimal text
```

Rules:
1. `Runner.ask`, `openai` and `anthropic` return `(content string, in, out int, err error)`: OpenAI reads `usage.prompt_tokens` and `usage.completion_tokens`, Anthropic `usage.input_tokens` and `usage.output_tokens`. `ask` measures the time and calls `OnUsage` once per call, successful or not.
2. `Runner.AI` passes purpose `rule` and the rule id; `Ping` passes `test`. A reply served from the cache makes no call and no usage.
3. `store.runCheck` wraps its context: `rules.WithCaller(context.Background(), rules.Caller{User: run.By, Eng: eng, Fid: fid})`.
4. `web.wireAI` sets `rn.OnUsage` to a function that calls `d.AddAIUsage`.
5. Admin › AI form: two inputs "Price in" and "Price out" (per 1M tokens, `w128`, decimal with up to 4 places, empty = no price). Stored with `SetSetting`.
6. Admin › System, new panel **AI usage** after Retention: stats for the last 7 and the last 30 days (Calls, Tokens in, Tokens out, Cost), and a table for the last 30 days: User | Calls | Tokens in | Tokens out | Cost, with the empty row when there are none. Cost is `in/1e6*priceIn + out/1e6*priceOut` with two decimals, `—` when no price is set.
7. The retention worker also deletes `ai_usage` rows older than `AuditDays` when that is above 0.

- [ ] **Step 1: write the failing tests.**
  - `TestUsageRecordedPerCall` (`rules`, with an `httptest` server that answers an OpenAI-style body with `usage`): one `AI` call gives one `Usage{Purpose: "rule", In: 12, Out: 3, OK: true}` with the rule id and the caller from the context.
  - `TestCachedReplyIsNotUsage`: the same text twice gives one usage.
  - `TestFailedCallIsUsage`: a 500 answer gives `OK: false`.
  - `TestAnthropicUsage`: token fields are read from an Anthropic-style body.
  - `TestAITotals` (`db`): three rows by two users; the first total is everyone, then per user by calls.
  - `TestUsagePanelCost` (`web`): with prices `3` and `15` and one row of 1,000,000 in and 100,000 out, the panel shows `4.50`.
  - `TestUsagePanelNoPrice`: cost cells show `—`.
- [ ] **Step 2–4:** fail, implement, pass (`go test ./internal/rules ./internal/db ./internal/store ./internal/web`). **Step 5:** commit: `feat(admin): AI calls, tokens and cost (D24)`.

### Task 4: Restore

**Files:** create `internal/web/admin_restore.go`, `internal/web/admin_restore_test.go`; modify `internal/web/admin_system.go` (route, view), `internal/web/templates/admin.html` (panel after AI usage)

**Interfaces produced:**

```go
// POST /admin/system/restore (multipart, field "backup"); admin only.
func (s *Server) restoreUpload(w http.ResponseWriter, r *http.Request)
// restoreMax caps an uploaded backup.
const restoreMax = 16 << 30
```

Rules:
1. The route is wrapped in `longLived` (no read or write deadline) and `http.MaxBytesReader(w, r.Body, restoreMax)`. The upload is streamed to a temporary file with `r.MultipartReader()` (never `ParseMultipartForm`, which buffers).
2. The target is `<data folder>.restored-<YYYYMMDD-HHMMSS>` beside the data folder. `backup.Restore(tmp, target)` does the rest; the temporary file is removed.
3. On success: audit `restore.upload` with the target; redirect to `/admin/system` with a flash (the existing `s.flash`) that the panel shows: the four report values and the line `yars serve --data <target>` in a copy row (`data-copy`). The running server keeps serving the old folder.
4. On failure: the panel's state slot shows the error (`backup from a newer YARS …`, `… not a plain file inside the data folder`, `not a ZIP file`); nothing is left on disk.
5. Panel **Restore**: a file input and the button `Restore` (`w128`) in the panel head; below, the stats of the last restore (`—` when none).

- [ ] **Step 1: write the failing tests.**
  - `TestRestoreUploadMakesSiblingFolder`: take a backup with `backup.Write`, upload it; a folder `<e.dir>.restored-…` exists and `gitrepo.Open` works on it; the System page shows `yars serve --data` with that path; `e.dir` is unchanged (same HEAD).
  - `TestRestoreUploadRefusesNewerSchema`: no sibling folder exists afterwards; the page shows `newer YARS`.
  - `TestRestoreUploadRefusesNonZip`: uploading text answers with the page and the error; no folder.
  - `TestRestoreUploadAdminOnly`: `alice` gets 403.
- [ ] **Step 2–4:** fail, implement, pass. **Step 5:** commit: `feat(admin): restore an uploaded backup into a new folder (D24)`.
- [ ] **Step 6:** browser check against board 6.8. Push the branch and open PR #19 (title `Admin › System: integrity, retention, AI usage, restore`).
