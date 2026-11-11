# Progress

A task's commit hash is written by the commit that follows it.

```
M19         done     PRs #8–#13 opened
M20 task 1  done     aa655ef
M20 task 2  done     183ee6e
M20 task 3  done     31e76aa
M20 task 4  done     c414864
M20 task 5  done     8c32bb3 (worktree pruned; old worktree and feat/push-checks kept, see review-after.md)
M20 PR      opened   #14
M21 task 1  done     f1570df, review fixes 069a0e2
M21 task 2  done     809558c
M21 task 3  done     cb749f9
M21 task 4  done     6b8e814
M21 task 5  done     2f603f0
M21 review  fixed    db2fd5e (task 2), 3214bb9 (tasks 1, 3, 4), 3c017bf (task 5)
M21 task 6  done     358c07a
M21 branch  reviewed fixes ba507ff
M21 PR      opened   #15
M21 tests   b8d4226 (from the review of ba507ff)
M22 task 1  done     aa387bd
M22 task 2  done     321ce25 (browser check passed: no policy refusals; list holds off while ticked)
M22 task 2  review   test fixed 071b67b
M22 task 3  done     3fd25ee
M22 task 4  done     83c4dad (manual: SIGINT with an open page stops in under a second, exit 0)
M22 task 5  done     105e29b, review fix fafb8c8 (fsck limit)
M22 task 4  review   6bf15fb (second signal)
M22 task 6  done     f67ec57 (cache), d957c1b (hook env), 93959c3 (script group), d51c4aa (cookie refresh)
M22 branch  reviewed notes b558ccc
M22 PR      opened   #16
M23 task 1  done     61c7947, review fix 29d76e3
M23 task 2  done     2f1d108 (browser check passed: caret and focus kept, q= in the URL, Back restores)
M23 task 3  done     (browser check passed: two tile panels and two bars only)
```
