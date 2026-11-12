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
M25 task 4  review   passed; fix ff9c75f (read-only parent named in the panel; one restore at a time)
M25 task 3  review   passed; fixes dde76c4 (Submit, MCP and bench AI calls attributed; usage columns; prices audited)
M25 branch  reviewed fixes 7fc59b7 (refused panels scroll into view; upload's own name; copy row; slow-upload test)
M25 browser check    passed (System at 1440: Health, Backup, Retention, AI usage, Restore, Operations, Server, full width, no overflow; Run integrity 4 repos and integrity_check; a backup restored into data24.restored-… with the serve command; Retention saved; a refused upload scrolls its error into view)
M25 PR      opened   #19
M26 task 1  done     385f462 (schema v21)
M26 task 2  done     050c6a5
M26 task 3  done     e111aec
M26 task 1  review   fix 6a4a662 (purge clears the marks; noted under the lock; one lister; long names)
M26 task 4  done     bfacfff
M26 task 2  review   fix 6aff44f (HEAD's version kept; merged versions; copy elsewhere refused; gc past the point of no return; dirty tree; lock test)
M26 task 3  review   fix 6aff44f (bytes the server holds; merge repeat; quoted name)
M26 task 4  browser  fix a7ecacc (confirm table fits; a refusal names the copy)
M26 task 4  review   fix be5e0af (deadlines lifted; header row; archived named; ids kept before the rewrite; unfinished purge; marked files only)
M26 task 2  review 2 fix 6e49d5e (old versions out at every path; copy in the current files redacted first; gc retried; reflogs kept on refusal)
M26 browser check 2  fix cc7ecf4 (confirm table's value column)
M26 branch  reviewed fixes 1a691dd (renames followed; an interrupted purge finished; history-only paths a server error)
M26 branch  fix check    fix 6edc7fc (versions history holds again; exact earlier folder names); its check passed; nits c8218ad
M26 browser check    passed (1440: marks and the Purge slot, clipped long name, confirm page within its panel, purge removes the original from git and the mark, a copy refuses with 409, a redacted copy lets both purges through)
M26 PR      opened   #20
M27 task 1  done     17592fc
M27 task 2  done     397a37c
M27 task 3  done     8be4e77
M27 task 4  done     510d5a8
M27 browser check    passed (1440: Complete shows Revert, Mark reported, Withdraw at 136 px; the panel "Revert to verification" with a secondary Revert; Reported shows Revert then Withdraw at the same right edge; a revert with a reason lands in the chat with the accent marker; bulk Set state offers only "Complete · revert" for a reported row, its dialog reads "Revert 1 finding", and it moves the row)
M27 task 1  review   passed; nits 0cb1efe
M27 task 2  review   passed; test nits 9e94ffe
M27 task 3  review   passed; fix fcf238a (inbox row kept after a revert; bulk dialog's Revert button secondary)
M27 task 4  review   passed; nits 51798da
M27 branch  reviewed fixes 0a3c0a5 (the author's revert over MCP; inbox row in its sorted place; Revert titles); its check passed; nit 2e48ccc
M27 PR      opened   #21
M28 task 1  done     bdac2ae to 0ce9144 (nine moves; store.go 268 lines; the 1190 test names unchanged)
M28 task 2  done     914487f to 01aa7d1 (three moves; checks.go 61 lines; test names unchanged)
M28 task 3  done     874ca24 to d8e8d03 (one commit per package: web, store, mcp, export, rules, yars; the fifteen files gone; the 1190 test names unchanged)
M28 tasks   review   passed (1, 2, 3: byte-for-byte moves checked; placements as recorded); wording nits 9da5d61
M28 branch  reviewed passed but for size: split into pr/22a-store-split (to a2160ff) and pr/22b-test-names 44885ee
M28 PRs     opened   #22 (pr/22a-store-split), #23 (pr/22b-test-names)
M29 task 1  done     782b2c2 (browser check 1 passed: "ecinjk?/" typed into a Details textarea, an Assets input, the CVSS paste and reason, a section body, a chat reply, the composer; a CVSS radio and the section select unchanged; the page, its five open editors and its panels unchanged; Ctrl+K and Esc work from the composer)
M29 task 2  done     38b80c4 (browser check passed: j through the eleven main panels of a finding in order, k back, l to the chat, h back; every box the same at the same scroll, the chat's sticky column aside; Esc closed the More popover, then the Withdraw form, then the Details editor, then cleared the selection)
M29 task 3  done     d44cf68 (browser check passed: j j e opened Details with focus in Location, typed, Ctrl+S saved it and put focus on its Edit button, page unchanged; Ctrl+S in Settings › Account posted /settings/account only; Ctrl+S on the login page posted nothing; in the CVSS editor Ctrl+S from a reason field posted Save and the vector stayed; the seed config never disables Save for a missing reason)
M29 task 4  done     9e37132 (browser check passed: disabled Submit, Approve and Sign off keys send nothing; Shift+R opens Return with focus in the reason, Ctrl+Enter sends; focus stays on Submit across a live refresh; Shift+S submits at once; bulk Shift+S posts only with a ticked row, from its checkbox)
M29 task 5  done     e48fdbb (browser check passed: j j Enter opens the second finding; j x j j Shift+Space ticks three rows; Shift+click ranges; / focuses Search, or opens Go to on the inbox; i opens the inbox; a filter keeps focus after its swap)
M29 task 6  done     35c37dd (schema v22; browser check passed: with shortcuts off j e ? i do nothing, Ctrl+K, Esc, Ctrl+S and Ctrl+Enter work; ? opens the list within the window, Esc closes it, the Finding page group hidden without panels)
M29 tasks 1–3 review fix 4c9a535 (Ctrl+Enter presses its forms' marked button only; Ctrl+S needs a field and the form's own button; a click never scrolls; outlines; h/← and arrows; Esc closes CVSS and returns focus)
M29 task 4  review   passed; nits in the same fix (row checkboxes only; no Shift+T in the list; no id on the running Check)
M29 task 5  review   fix c80f9a9 (Enter on a list checkbox never submits, opens the row; j/k skip disabled rows; x in lists only; Load more focus only from its button)
M29 task 6  review   passed; nits c80f9a9 (no selection with shortcuts off; Chat group only with a chat; Redact Ctrl+Z noted) and 6d82ab5 (a form without theme keeps it; AddUser stores KeysOff; v21 upgrade test)
M29 branch  review   fixes 513cfda (keys move focus off the old panel; picker Enter; row ids; focus rides on the key's request), nits 7515b28 (held Esc; Esc order; focus back to a reason toggle; the ? list shows what works on the page)
M29 branch  fix check one regression (picker Ctrl+Enter), fixed 938c6c7 with the check's optional leftovers
M29 PR      opened   #24
M30 task 1  done     a4a4851 (POST /git/e/<id>/lint: every rule, nothing stored, team and token checks as a clone)
M30 task 2  done     025dc8b (yars lint --staged: the index, git's saved login, one line and exit 0 when the server cannot be asked)
M30 task 3  done     1f80bde (yars hook install: every engagement of a clone, a hand-written hook kept; end to end, a commit breaking a rule goes in with the server's lines, and with the server down)
M30 task 4  done     f3b7ec0 (docs/git.md "Check before you commit", README line)
M30 task 1  review   passed; nits 1fd86af (a read deadline on the posted body; 404 for any method without the endpoint; only a finding id recorded with AI usage; three tests)
M30 task 2  review   fix 09a3c1b (a waiting credential helper bounded by the run's time; moved findings checked; 4 asked at a time; git's TLS and proxy settings)
M30 task 3  review   fix e4ed169 (core.hooksPath left alone; a hook that never stops a commit and says when its binary is gone; the PATH name; tests isolated from the user's git config)
M30 branch  review   fixes d6d308e (one failed login per commit, a refused helper login forgotten; the workflow state applied as Check does; how to save a login; could-not-run rules not counted; docs)
M30 branch  fix check one regression (the first finding asked alone took two rounds), fixed 63117c1: the login checked first with a GET, then all findings at once
M30 PR      opened   #25
M31 task 1  done     59b9d8b (Runner.Fix and Engine.Fix: the whole section back, purpose fix, never cached)
M31 task 2  done     7c1bf33 (StartFix: each open check result fixed only when nothing else changed and the rule no longer fires, committed as AI for <user>, answered in its thread; a check run follows)
M31 task 3  done     aefc4bc (Fix with AI in the Checks strip's head; Fixing while it runs, the strip open, Check disabled; 409 while busy)
M31 task 4  done     1af3cac (the AI tag after the user's name on an AI reply and on an AI commit in History)
M31 browser done     ace396c (fake provider; four fixes: the strip head fits, Fixing's spinner, the AI mark's size, live refreshes keep the last event)
M31 task 1  review   fix ee565ee (the prompt names the problem and quote as data too; 3x time limit; empty body refused; first JSON value read)
M31 task 3  review   fix ee565ee (Enter skips Fix with AI; no Retry while fixing; the progress moves; one status read)
M31 task 4  review   fix ee565ee (an "AI for" author name refused on push; AI replies out of the inbox; the conflict head marked)
M31 task 2  review   fix 76a894b (the quote as words in one paragraph; no blocks reaching other paragraphs; a rule that could not run or finds a new problem refuses; open findings only; cut quotes found)
M31 task 3  review 2 fix 76a894b (missed live events fired at settle; refusals are toasts, 422)
M31 branch  review   fixes 08ea0ab (the rest of the section must render the same; archived engagements; a 15-minute bound and a stop)
M31 branch  fix check three low findings, fixed cf87bf2 (list items keep their place; indented code and HTML blocks fixable; a stop in flight says so)
M31 PR      opened   #26
M32 task 1  done     8e1dfb6 (strict JSON-RPC: no batches, jsonrpc 2.0, no null id; bearer in any case; two protocol versions; long stdio lines go on)
M32 task 2  done     82dabad (f-7, F-7, F-007 and 7 name one finding; an ID two folders share is refused; unknown status or severity lists the valid ones)
M32 task 3  done     b7eb678 (every answer one JSON object with ok; lists items and next; refusals with a code)
M32 task 4  done     a5cf93c (limit and cursor on the list tools; q in list_findings)
M32 task 1  review   fix f14881b (ids string or number; non-requests -32600; exact member names; 400 for input it cannot accept; the version header; stdio limits)
M32 task 2  review   fix f14881b (candidates from the folder listing and the index; exact folder first; a broken finding says why)
M32 task 5  done     6918a57 (whoami, get_config, list_team, read_chat, list_history, list_attachments, read_template; read_finding bodies and allowed_actions)
M32 task 3  review   fix 4408985 (gate codes tested; revert and missing reason codes; the checks race is a conflict; docs code column)
M32 task 4  review   fix 4408985 (notifications paged by id in the query, token engagements filtered there; no 5,000 cut)
M32 task 6  done     51b6489 (mark_notifications_read, fix_checks; instructions; docs Answers and Paging)
M32 task 5  review   fix 94b893b (allowed_actions checks the token; six modes tested; history cached; clone answers)
M32 task 6  review   fix d40a67d (fix_checks needs edit too; ids once each, at most 200, one statement; plain store words; docs rows checked)
M32 manual  done     (an MCP session over HTTP: list drafts, read, edit with base, submit; every answer parsed)
M32 branch  review   fixes 4990b7c (can_edit follows the token; template not_found; real refusal before a missing reason; docs table; clone history)
M32 branch  fix check passed
M32 PR      opened   #27
M33 task 1  done     6b13c77 (every colour a token; the scattered token blocks merged; 21 pages' computed colours the same in both themes)
M33 task 2  done     43bab42 (the preview's paper takes the light tokens; in dark only the paper's subtree changed, light unchanged)
M33 task 1  review   fix c171964 (the colour checks: media block alone, blocks once, no token set again, any-case and newer colour functions, system colours, %23, strings and url(), nesting)
M33 task 2  review   fix 052bafd (the preview's text colour and selector placement tested; report severity colours tied to the preview's)
M33 branch  review   fixes f5d1fc0 (one scanner for strings, escapes, comments and url(); theme-only rules refused; nested rules and data: URLs refused; fewer false positives; cover bar, head bar and PDF palette tied)
M33 branch  fix check passed bb7f48d (eight fixed; then data: URLs in any string and more made-up-name properties)
M33 PR      opened   #28
M34 task 1  done     add547c (every backlog line marked: 37 fixed, 11 of them by a new test; 6 won't; 63 do; 12 ask)
M34 task 2  done     ce24307..49df5a9 (the 63 do lines, one commit each with its test)
M34 task 1  review   fix 08b3cb4..4fa33ea (two tests that missed their line; three won't lines closed by rule 1; revoke --id with two tokens)
M34 task 2  review   fixes 15292a7..40ef1dd (four reviewers, one per part: lint's hidden script failures, the one blocker; live counts; the migration import; Jira headings; a hand-written pandoc format; PDF worker order; sandboxed downloads; export --as and statuses)
M34 known   done     docs/known-limits.md (3 won't, 22 needing a decision); the backlog file removed
M34 branch  review   fixes e301b0e..356f174 (the inbox fails rather than show empty queues; exporter statuses finished only, R10 in the CLI; timing-free worker tests; MCP sign-off base in known limits)
M34 branch  fix check passed (all five fixed; two wording points taken)
M34 PR      opened   #29
M35 task 1  done     ab6e7d7 (yars version: build version, schema, Go release; Admin › System's Version)
M35 task 2  done     39764d9 (data from M11 opens with this version; no migration bug)
M35 task 3  done     cd3b982 (docs/deploy.md: requirements, install, service, HTTPS, backup and drill, upgrade, health)
M35 task 4  done     da92b59 (the v1.0 walkthrough: nine lines pass; line 3 failed and was fixed in 54cac0f)
M35 task 1  review   fix 8804d8b (the tests check the second call and a short revision; the plan's buildVersion kept)
M35 task 2  review   fix c509878 (prepareData shared with yars serve; an M11 pentester on the team; snapshot of schema 1; builder kept)
M35 task 3  review   fix efb60d2 (the folders yars writes; unbuffered bodies; base_url; LaTeX packages; going back only when the schema changed)
M35 task 4  review   fix 0843814, 40f167b (every CVSS parse error says how to fix it; the record as the run was)
M35 branch  review   fixes 775331c (base_url by push; a copy of the old binary; --user-group; the fixture's output path; these PROGRESS lines)
M35 branch  fix check passed (all six fixed; base_url is an admin's, in deploy.md and config.md)
M35 PR      opened   #30
M35 after   done     c89fcee (asked after the run: Developers opens from the user name only; the header runs Go to, theme, bell, user name)
M35 after   done     c7abff7 (asked after the run: Token expiring is sent, once per token, under 7 days left; schema v23)
M35 after   review   fix b0f1591 (the claim and the notice in one transaction; a re-enabled owner is still told)
M35 after   done     d286a10 (asked after the run: long user names end in "…" in the header, Reviewers, the reviewer tag, a lead's head)
M35 after   review   fix 4dfc60a (who is editing, the new-password page, a lead's strips; a short reviewer keeps a letter)
```
