# Review after the unattended run

Choices the plans did not make, and places the result differs from a plan. One entry per item: milestone, task, what, why.

| Milestone | Task | What | Why |
|---|---|---|---|
| all | all | Commit trailers name `Claude Opus 5.5`, not `Claude Fable 5.2` as RUN.md rule 11 writes. | The run was done by Opus 5.5; the trailer names the model that wrote the commit. |
| all | all | PROGRESS.md gets a task's commit hash in the commit that follows it. | A commit cannot hold its own hash. |
| M20 | 4 | The "no pandoc" proof ran with a PATH of every tool except `pandoc*` and `xelatex*`, cgo off, not a PATH of only `git` and `go`. Result: `internal/export`, `internal/web`, `cmd/yars` pass. No skip guard was added. | With only `git` and `go`, the fake `pandoc` and rule scripts the tests write fail on `cat`, `dirname`, `sleep`, `grep` and `wc`, which every CI runner has; cgo needs `gcc`. |
| M20 | 4 | `gofmt -l .` lists `.claude/worktrees/…/internal/db/leads.go` locally. | It is in an ignored, untracked worktree that a CI checkout does not have; task 5 removes it. |
