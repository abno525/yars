# M21 — backup and restore

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Read `2026-11-11-yars-roadmap-to-v1.md` first. Steps use checkbox (`- [ ]`) syntax.

**Goal:** a backup can be made from the command line (for cron) and from the website with the same code, and any backup can be turned back into a working data folder.

**Architecture:** a new package `internal/backup` owns the ZIP format. The website's download handler, `yars backup` and `yars restore` all call it. A restore never writes into an existing data folder: it unpacks into a new folder and verifies it (database opens, `quick_check`, `git fsck` per repo). The command line takes no locks; it verifies what it wrote and retries, so a backup taken while a commit lands is either consistent or redone.

**Spec:** `docs/open-decisions-2026-11-07.md` D24 (Restore); the analysis finding that a git clone is no longer a backup since M10.

**Branch:** `pr/15-backup-restore` from `pr/14-hygiene-ci`.

## Review focus

1. A backup from a newer YARS restored with an older binary must refuse before writing anything (task 3, `TestRestoreRefusesNewerSchema`).
2. A ZIP entry that escapes the target folder or is a symlink must refuse the whole restore (task 3, `TestRestoreRefusesZipSlip`).
3. A backup taken while a commit lands must not be kept if it is inconsistent (task 4, `TestBackupRetriesInconsistent`).
4. A restore into a folder that already holds data must change nothing (task 3, `TestRestoreRefusesNonEmpty`).
5. Migration snapshots must not pile up or leak into backups (task 1 and task 5).

## File structure

| File | Responsibility |
|---|---|
| `internal/backup/backup.go` (new) | `Write`: stream a ZIP of a data folder |
| `internal/backup/restore.go` (new) | `Restore`, `Verify`, `Report`: unpack and check |
| `internal/backup/backup_test.go` (new) | tests for both |
| `internal/store/locks.go` (new) | `LockMain`, `LockEngagement` (exported lock access) |
| `internal/gitrepo/gitrepo.go` | `Fsck` |
| `internal/db/db.go` | `SchemaOf`, snapshot before a migration |
| `internal/web/admin_system.go` | the download handler calls `backup.Write` |
| `cmd/yars/backup.go` (new) | `cmdBackup`, `cmdRestore` |
| `cmd/yars/main.go` | the two commands in `main` and `usage` |
| `README.md`, `docs/superpowers/specs/2026-11-03-yars-design.md` | what to back up; what the database holds |

---

### Task 1: `backup.Write`

**Files:** create `internal/backup/backup.go`, `internal/backup/backup_test.go`, `internal/store/locks.go`

**Interfaces produced:**

```go
package store
// LockMain takes the main repo's lock; call the result to release it.
func (s *Store) LockMain() (unlock func())
// LockEngagement takes an engagement repo's lock.
func (s *Store) LockEngagement(id string) (unlock func())

package backup
type Options struct{ WithKey bool }
// Locker is what Write holds while it copies a repository; nil copies without locks.
type Locker interface {
	LockMain() (unlock func())
	LockEngagement(id string) (unlock func())
}
// Write streams a ZIP of dataDir to w and returns the bytes written.
func Write(w io.Writer, dataDir string, d *db.DB, l Locker, o Options) (int64, error)
// Skip reports files a backup leaves out.
func Skip(rel string, withKey bool) bool
```

Rules `Write` follows:
1. Snapshot the database first with `d.Snapshot(tmp)` into a temporary folder; add it as `.yars/yars.db` last.
2. Copy every regular file of the main repo except the `engagements/` folder while holding `LockMain`.
3. Copy each `engagements/<id>` folder while holding `LockEngagement(id)`, one engagement at a time.
4. `Skip` is true for `.yars/yars.db`, any path starting `.yars/yars.db-` or `.yars/yars.db.before-`, and `.yars/secret.key` unless `withKey`.
5. Entries that are not regular files (symlinks, devices) are left out. File modes are kept (`zip.FileInfoHeader`), so hooks and rule scripts stay executable.

- [x] **Step 1: write the failing tests** in `internal/backup/backup_test.go`. Build the data folder with `gitrepo.Init`, `db.Open`, `store.New` and `CreateEngagement` + `CreateFinding`, as `internal/web/server_test.go` `newEnv` does.
  - `TestWriteHasSnapshotNotLiveDB`: the ZIP has `.yars/yars.db`; it has no entry ending `-wal` or `-shm`.
  - `TestWriteKeyOnlyWhenAsked`: with `WithKey: false` there is no `.yars/secret.key`; with `true` there is.
  - `TestWriteSkipsSymlinksAndSnapshots`: a symlink in the data folder and a file `.yars/yars.db.before-v18` are not in the ZIP.
  - `TestWriteKeepsExecBit`: a file with mode `0755` under `.yars/rules/` has `0o111` bits set in its ZIP header.
  - `TestWriteHoldsLocks`: a fake `Locker` that appends to a slice records `main`, then one entry per engagement, each released (the unlock func ran) before the next is taken.
- [x] **Step 2:** run `go test ./internal/backup`. Expected: FAIL, package does not compile.
- [x] **Step 3:** implement `store.LockMain` and `LockEngagement` (wrappers over `mainMu` and `engLock`), then `backup.Write` and `Skip`. Move the walking and ZIP code out of `web.Server.backup` (`internal/web/admin_system.go:229`); `backupSkip` there is deleted.
- [x] **Step 4:** run `go test ./internal/backup ./internal/store`. Expected: PASS.
- [x] **Step 5:** commit: `feat(backup): one ZIP writer for the website and the command line`.

### Task 2: the website uses it

**Files:** modify `internal/web/admin_system.go` (the `backup` handler), `internal/web/admin_system_test.go`

- [ ] **Step 1:** change the existing backup tests only where they call `backupSkip` (use `backup.Skip`). Add `TestBackupDownloadUsesStoreLocks`: start the download with `e.do`, and assert the response is a ZIP that `backup.Verify` (task 3) accepts. Until task 3 exists, assert `zip.NewReader` opens it and it holds `.yars/yars.db`.
- [ ] **Step 2:** the handler body becomes: set the headers as now, `n, err := backup.Write(cw, dir, s.Store.DB(), s.Store, backup.Options{WithKey: withKey})`, the same `panic(http.ErrAbortHandler)` on error, the same audit line.
- [ ] **Step 3:** run `go test ./internal/web -run Backup`. Expected: PASS. Commit: `refactor(admin): the backup download uses internal/backup`.

### Task 3: `backup.Restore` and `backup.Verify`

**Files:** create `internal/backup/restore.go`; modify `internal/gitrepo/gitrepo.go`, `internal/db/db.go`

**Interfaces produced:**

```go
package gitrepo
// Fsck checks the repository's objects and refs (git fsck --no-dangling).
func (r *Repo) Fsck() error

package db
// SchemaOf reads the schema version of the database file at path without migrating it.
func SchemaOf(path string) (int, error)

package backup
type Report struct {
	Schema      int  // of the database in the backup
	Engagements int  // engagements/<id> that are repositories
	Findings    int  // findings/<dir>/finding.md files
	HasKey      bool // .yars/secret.key is in the backup
}
// Restore unpacks zipPath into destDir (missing or empty) and verifies it.
func Restore(zipPath, destDir string) (Report, error)
// Verify unpacks zipPath into a temporary folder, verifies it and removes it.
func Verify(zipPath string) (Report, error)
var ErrNewer = errors.New("backup from a newer YARS")
```

Rules:
1. `Restore` refuses when `destDir` exists and has any entry: `"<dir> is not empty; restore into a new folder"`.
2. Before writing anything it reads every ZIP header: an entry whose name is absolute, contains a `..` segment or a backslash, or whose mode is not a regular file or a directory, refuses the restore: `"<name>: not a plain file inside the data folder"`.
3. It extracts `.yars/yars.db` first into a temporary file and calls `db.SchemaOf`. Above `db.SchemaVersion`: return `fmt.Errorf("%w (schema %d, this yars writes %d); upgrade yars first", ErrNewer, got, db.SchemaVersion)` and write nothing to `destDir`.
4. It unpacks every entry, keeping the executable bits.
5. Checks, in order, each a wrapped error naming what failed: `db.Open` (migrates), `d.Check()` returns `ok`, `gitrepo.Open(destDir).Fsck()`, then `Fsck` of every `engagements/<id>` that has a `.git`.
6. On any failure after unpacking, `destDir` is removed again (it did not exist or was empty before).
7. `Verify` is `Restore` into `os.MkdirTemp` followed by `os.RemoveAll`.

- [ ] **Step 1: write the failing tests.**
  - `TestRestoreRoundTrip`: seed a folder (two engagements, three findings, one chat message), `Write` it, `Restore` it; `store.New` on the result lists the same finding ids and titles; the chat count is equal; `Report` is `{Schema: db.SchemaVersion, Engagements: 2, Findings: 3, HasKey: false}`.
  - `TestRestoreRefusesNonEmpty`: `destDir` holds one file; the error contains `not empty`; the file is still the only entry.
  - `TestRestoreRefusesZipSlip`: three hand-made ZIPs (entry `../x`, entry `/abs`, a symlink entry); each is refused and `destDir` does not exist afterwards.
  - `TestRestoreRefusesNewerSchema`: a ZIP whose `.yars/yars.db` has `PRAGMA user_version` set to `db.SchemaVersion + 1`; `errors.Is(err, ErrNewer)`; `destDir` does not exist.
  - `TestRestoreRemovesBrokenResult`: a ZIP whose engagement repo lacks an object (delete one file under `.git/objects` before `Write`); the error names the engagement; `destDir` does not exist.
  - `TestFsck` in `internal/gitrepo`: a fresh repo passes; after deleting a loose object it fails.
- [ ] **Step 2:** run `go test ./internal/backup ./internal/gitrepo ./internal/db`. Expected: FAIL.
- [ ] **Step 3:** implement `Fsck` (`r.run(nil, "fsck", "--no-dangling")`), `SchemaOf` (open `file:<path>?mode=ro` with the sqlite driver, `PRAGMA user_version`), `Restore`, `Verify`.
- [ ] **Step 4:** run the three packages. Expected: PASS. Switch `TestBackupDownloadUsesStoreLocks` (task 2) to `backup.Verify`.
- [ ] **Step 5:** commit: `feat(backup): restore into a new folder, verified`.

### Task 4: `yars backup` and `yars restore`

**Files:** create `cmd/yars/backup.go`, `cmd/yars/backup_test.go`; modify `cmd/yars/main.go` (`main` switch, `usage`, the package comment)

**Interfaces produced:**

```go
// yars backup [--data dir] [--key] --out file.zip
func cmdBackup(args []string, out io.Writer) error
// yars restore --from file.zip --data newdir
func cmdRestore(args []string, out io.Writer) error
// backupTries is how often cmdBackup takes the backup again when Verify refuses it.
const backupTries = 3
```

Behaviour of `cmdBackup`: `--out` is required and must not exist (`"<file> exists already"`). It writes to `<out>.part`, calls `backup.Verify` on it, renames it to `<out>` on success, and on a verify failure removes it and tries again, up to `backupTries` times; then `"could not take a consistent backup while the server is writing; try again"`. It writes the audit entry `d.Audit("cli", "backup", "", "<with|without> key · <size>")` and prints `wrote <out> (<size>, <N> engagements, <M> findings)`.

Behaviour of `cmdRestore`: both flags are required; `--data` here is never defaulted from `YARS_DATA` or `yars use`. It prints the report as four lines (`schema v18`, `2 engagements`, `3 findings`, `secret key: yes|no`), then, without a key, `stored AI and personal keys must be entered again`, then `next: yars serve --data <newdir>`.

- [ ] **Step 1: write the failing tests.**
  - `TestBackupWritesVerifiedZip`: after `initData` and one finding, `cmdBackup` writes the file; `backup.Verify` accepts it; no `.part` file remains.
  - `TestBackupRefusesExistingOut`.
  - `TestBackupRetriesInconsistent`: replace the package variable `verifyBackup` (set to `backup.Verify` by default) with a fake that fails twice, then passes; the command succeeds and the fake ran three times. With a fake that always fails, the command returns the "could not take" error and no file remains.
  - `TestRestoreCommandRoundTrip`: backup, then restore into a new folder; `gitrepo.Open` and `openDB` work on it; the output has `next: yars serve --data`.
  - `TestRestoreNeedsBothFlags`.
- [ ] **Step 2:** run `go test ./cmd/yars -run "Backup|Restore"`. Expected: FAIL.
- [ ] **Step 3:** implement the two commands; add `case "backup"` and `case "restore"` to `main`; add both to `usage` and the package comment.
- [ ] **Step 4:** run the tests. Expected: PASS. Commit: `feat(cli): yars backup and yars restore`.

### Task 5: a snapshot before a migration

**Files:** modify `internal/db/db.go` (`Open`, `migrate`), `internal/db/db_test.go`

Behaviour: in `migrate`, when the stored version is above 0 and below `schemaVersion`, before the first migration run `VACUUM INTO '<path>.before-v<stored>'` (remove a file of that name first). After the migrations succeed, keep the two snapshots with the highest version numbers and delete the others. Snapshots get mode `0600`. `migrate` takes the database path as a parameter.

- [ ] **Step 1: write the failing tests.** Add the helper `openAtVersion(t *testing.T, v int) string` to `db_test.go`: it creates a database file, runs `migrations[0:v]` (and their `goMigrations`) in order, sets `PRAGMA user_version = v`, closes it and returns the path.
  - `TestMigrateKeepsSnapshot`: `openAtVersion(t, schemaVersion-1)`, then `Open`; the file `<path>.before-v<schemaVersion-1>` exists, has mode `0600`, and `SchemaOf` on it returns `schemaVersion-1`.
  - `TestMigrateKeepsTwoSnapshots`: pre-create `.before-v3`, `.before-v7`, `.before-v9`; after the `Open` above only the two highest version numbers remain (the new one and `.before-v9`).
  - `TestFreshDatabaseHasNoSnapshot`: `Open` on a new path leaves no `.before-` file.
- [ ] **Step 2:** run `go test ./internal/db -run Migrate`. Expected: FAIL.
- [ ] **Step 3:** implement. Run `go test ./internal/db ./cmd/yars`. Expected: PASS.
- [ ] **Step 4:** commit: `feat(db): keep a snapshot of the database before a migration`.

### Task 6: documents

**Files:** modify `README.md`, `docs/superpowers/specs/2026-11-03-yars-design.md`

- [ ] **Step 1:** README, new section after "Default data folder":

```markdown
## Backup and restore

A git clone holds the findings only. Accounts, workflow state, reviewers,
chat and check results are in the server's database, so back up with:

    ./yars backup --out /backups/yars-$(date +%F).zip

Add `--key` to include the key that decrypts stored AI and personal keys.
Run it from cron; it works while the server runs.

    ./yars restore --from /backups/yars-2026-11-11.zip --data /srv/yars-restored
    ./yars serve --data /srv/yars-restored

A restore always goes into a new folder and checks it before it reports success.
```

- [ ] **Step 2:** in the spec, replace the goal phrase "Markdown-in-git as the single source of truth" with "finding content as Markdown in git; accounts, workflow state and chat in the server's database (since M10)", and add under "Anti-goals" the sentence: "A git clone is not a backup; `yars backup` is."
- [ ] **Step 3:** commit: `docs: backup and restore; what the database holds`. Push the branch and open PR #15 (title `Backup and restore`).
