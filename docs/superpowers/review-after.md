# Review after the unattended run

Choices the plans did not make, and places the result differs from a plan. One entry per item: milestone, task, what, why.

| Milestone | Task | What | Why |
|---|---|---|---|
| all | all | Commit trailers name `Claude Opus 5.5`, not `Claude Fable 5.2` as RUN.md rule 11 writes. | The run was done by Opus 5.5; the trailer names the model that wrote the commit. |
| all | all | PROGRESS.md gets a task's commit hash in the commit that follows it. | A commit cannot hold its own hash. |
| M20 | 1 | The commit is `aa655ef docs: decisions, keyboard inventory, and the plans from M19 to v1.0`, not the plan's subject. | It was made before this run (RUN.md lists it as done). |
| M20 | 4 | The "no pandoc" proof ran with a PATH of every tool except `pandoc*` and `xelatex*`, cgo off, not a PATH of only `git` and `go`. Result: `internal/export`, `internal/web`, `cmd/yars` pass. No skip guard was added. | With only `git` and `go`, the fake `pandoc` and rule scripts the tests write fail on `cat`, `dirname`, `sleep`, `grep` and `wc`, which every CI runner has; cgo needs `gcc`. |
| M20 | 4 | `gofmt -l .` lists `.claude/worktrees/…/internal/db/leads.go` locally. | It is in an ignored, untracked worktree (kept, see task 5) that a CI checkout does not have. |
| M20 | 5 | The worktree `.claude/worktrees/wf_32da3db5-75c-4` and its branch `worktree-wf_32da3db5-75c-4` are left in place. | The worktree holds uncommitted work: `internal/db/db.go` modified, `internal/db/leads.go` and `internal/db/leads_test.go` new. `git worktree remove` refuses it; forcing would destroy it. Decide whether to keep it, then `git worktree remove --force` it and `git branch -d` the branch. |
| M20 | 5 | `feat/push-checks` is left in place. | `git cherry feat/redesign feat/push-checks` shows two commits not on `feat/redesign`: `5886e4b fix(accounts): no two accounts commit as the same email` and `e9b9465 feat(push): a push is refused for what the website refuses, in every commit`. |
| M20 | PR | `pr/15-backup-restore` was cut locally a few minutes before PR #14 was opened; nothing of M21 was pushed before it. `feat/redesign` is fast-forwarded to `pr/14-hygiene-ci` after the PR opened. | Order slip, no effect on the branches' content. |
| M21 | 1 | The handler in `internal/web/admin_system.go` and `backupSkip` are changed in task 2, not task 1. | Task 2 rewrites the same handler; keeping web out of task 1 leaves each commit building and passing. |
| M21 | 1 | `backup.Write` also writes a ZIP entry for every folder, and files directly under `engagements/` go in with the main repo. | Without folder entries an empty `.git/refs` (all refs packed) is lost and git no longer sees a repository; restore rule 2 already allows folder entries. |
| M21 | 1 | Added `TestSkip` beside the five named tests. | `Skip` is an interface of the task; the rules list its cases. |
