# Review after the unattended run

Choices the plans did not make, and places the result differs from a plan. One entry per item: milestone, task, what, why.

| Milestone | Task | What | Why |
|---|---|---|---|
| all | all | Commit trailers name `Claude Opus 5.5`, not `Claude Fable 5.2` as RUN.md rule 11 writes. | The run was done by Opus 5.5; the trailer names the model that wrote the commit. |
| all | all | PROGRESS.md gets a task's commit hash in the commit that follows it. | A commit cannot hold its own hash. |
| M20 | 4 | The "no pandoc" proof ran with a PATH of every tool except `pandoc*` and `xelatex*`, cgo off, not a PATH of only `git` and `go`. Result: `internal/export`, `internal/web`, `cmd/yars` pass. No skip guard was added. | With only `git` and `go`, the fake `pandoc` and rule scripts the tests write fail on `cat`, `dirname`, `sleep`, `grep` and `wc`, which every CI runner has; cgo needs `gcc`. |
| M20 | 5 | The worktree `.claude/worktrees/wf_32da3db5-75c-4` and its branch `worktree-wf_32da3db5-75c-4` are left in place. | The worktree holds uncommitted work: `internal/db/db.go` modified, `internal/db/leads.go` and `internal/db/leads_test.go` new. `git worktree remove` refuses it; forcing would destroy it. Decide whether to keep it, then `git worktree remove --force` it and `git branch -d` the branch. |
| M20 | 5 | `feat/push-checks` is left in place. | `git cherry feat/redesign feat/push-checks` shows two commits not on `feat/redesign`: `5886e4b fix(accounts): no two accounts commit as the same email` and `e9b9465 feat(push): a push is refused for what the website refuses, in every commit`. |
| M20 | 4 | `gofmt -l .` lists `.claude/worktrees/…/internal/db/leads.go` locally. | It is in an ignored, untracked worktree that a CI checkout does not have; task 5 removes it. |
