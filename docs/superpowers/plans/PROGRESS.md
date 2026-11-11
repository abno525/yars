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
M23 task 3  done     4861cb3 (browser check passed: two tile panels and two bars only)
M23 task 4  done     a1f5f09, review fix 41086fd
M23 task 2  review   fix cafc51c
M23 task 3  review   fix 4643d30
M23 task 5  done     6903760
M23 task 6  done     b600394
M23 task 7  done     6a8f1db
M23 task 6  review   fix 48bbb32
M23 task 5  review   fix 220c4bd (running run, repeated heading)
M23 task 7  review   fix cda90e2 (retry after a rule change, empty rules folder)
M23 branch  reviewed fixes 6961084 (rename conflict before the save, inbox drafts, decisions table; its review passed)
M23 PR      opened   #17
M24 task 1  done     ab55673 (browser check passed: stays closed and stays open across a second session's edit; opens while Check runs and closes after; a typed Dismiss reason survives a refresh)
M24 task 2  done     1eb3b22
M24 task 1  review   fix 5a1a821 (open strip scrolls; strip choice kept on out-of-band swaps and dismissals)
M24 task 3  done     5fc1c72
M24 task 4  done     245b0ea (review passed)
M24 task 2  review   fix 8976f09 (strip on workflow events; stale run lists rules now; run errors hold Submit; CVSS row; errors open count)
M24 task 3  review   fix aa97cf0 (duplicates: title room, three rows high)
M24 task 2  review   fix 2 0172169 (the strip reads the store's open-check source: stale by rules, cut-off run, run again, broken rule file)
M24 task 5  done     1eae352 (browser check of the whole page passed: strip closed 48 px under the text and Attachments; bar two rows, no list; Return event red in the chat; side column duplicates then chat; retest Original closed 50 px; no sideways scroll)
M24 task 5  review   passed; nits a60012f (liveTrigger, access pin, Original test bound)
M24 branch  reviewed fixes f1cace6 (closed strip keeps refreshing; Original state kept; withdrawn strip place)
M24 PR      opened   #18
M25 task 1  done     8e8429c
M25 task 2  done     790771f
M25 task 1  review   fix 077937c (fsck's message in the row; deadlines lifted for admins only)
M25 task 3  done     78af795 (schema v20)
M25 task 4  done     e125a18
M25 task 2  review   fix 2d033af (runs on the newest run's content kept; field labels in the error)
M25 task 4  review   passed; fix (read-only parent named in the panel; one restore at a time)
M25 browser check    passed (System at 1440: Health, Backup, Retention, AI usage, Restore, Operations, Server, full width, no overflow; Run integrity 4 repos and integrity_check; a backup restored into data24.restored-… with the serve command; Retention saved)
```
