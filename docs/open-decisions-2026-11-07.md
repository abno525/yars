# YARS — decisions waiting for you

Written 2026-11-07, at commit `a9fa9c5` on `feat/redesign`.

**How to answer.** Write under each **Your answer:** line. You can write:
- "yes"
- "no"
- "go with the recommendation"
- your own choice, in a few words

At the top you can also write "go with all recommendations except …".

Anything you leave blank, I'll ask about again before building it.

**Overall answer:**

> 

---
---

# Part 1 — Finding page

These change the canvas first. I'll draw boards for you to sign off before any code is written.

---

## D2. Where should the Checks panel go, and when should it be open?

Today it is the first thing on the finding page, and it pushes the finding text far down.

**Recommendation:**
- Make it a thin 48 px strip at the bottom of the main column, closed by default.
- It opens by itself only while a check is running, or when the author's draft has errors.
- Hide it when there are no rules, and on withdrawn findings.

Bugs: P4-01, P4-04, P4-05, P4-06, P4-07, P4-08, P4-20, P4-64

**Your answer:**

> yes

---

## D3. Remove the error list under the workflow bar?

Today the same problem shows 3–4 times on the page, and the counts disagree. Each CVSS problem is also listed twice.

**Recommendation:** yes.
- Keep one "N errors to fix" count that opens the Checks strip.
- Stop opening a chat thread for every check hit.

Bugs: P4-02, P4-03, P4-60

**Your answer:** 

> yes

---

## D4. Tidy the finding page's side column and title row?

**Recommendation:** yes to all five:
1. Move "Possible duplicates" to the side column.
2. Rename the side "Status" panel to "Activity".
3. Combine "Merge into" and "Save as template" into one "More" button.
4. Collapse the retest "Original" sections.
5. List the finding's attachments on the page. Today they show only inside a section editor.

Answer per item if you like, e.g. "1 yes, 2 no, …".

Bugs: P3-03, P4-11, P4-12, P4-13, P4-15

**Your answer:**

> yes

---

## D21. Fold the side status panel into the chat?

Status changes (submitted, returned, signed off, approved) would show as events in the chat timeline, instead of in a separate panel. If yes, item 2 of D4 no longer applies.

**Recommendation:** yes.

**Your answer:**

> yes

---

## D22. Workflow bar: one row or two?

Board 3.5 shows the steps, reviewers and actions in one 56 px row. The app uses two rows, because the steps (520 px) and the action buttons (496 px) don't fit side by side together with the check slot.

**Options:**
- **(a)** Keep two rows.
- **(b)** One row, with a shorter step bar.
- **(c)** One row, with the check slot moved to the Checks strip (D2).

**Recommendation:** (c), if you say yes to D2.

**Your answer:**

> a

---
---

# Part 2 — Look and layout

---

## D5. Engagement pages: which repeated numbers and items to drop?

**Recommendation:**
- On Overview, keep the tiles and the charts, and drop the bar legends and chart tables.
- Show the git clone command only under Developers › Git. Today it also sits under the findings table.
- Drop the Preferences panel in Settings, since the top-bar toggle already sets the theme.

Bugs: P4-21, P4-22, P4-23, P4-46

**Your answer:**

> i have no idea what you mean, has to be explained better. 

---

## D6. In dark mode, should "0" badges be black or stay dark grey?

**Recommendation:** black, to match the "0 is black" rule.

Bug: P4-53

**Your answer:**

> Dark mode should be skipped for now, its not so easy to do it correctly right now. it will be remade in the future. 

---

## D16. Do two-column "label: value" tables need a header row?

These are the finding Details table, the retest Original and the report preview.

**Recommendation:** yes. Follow "every table has a header row" and add a plain "Field | Value" header.

Bug: P4-56

**Your answer:**

> yes

---

## D17. What should an empty table look like?

Today there are three styles: a big centred dash, a small left dash, or only the header row.

**Recommendation:** one style everywhere: the header row, plus one normal-height row with a left-aligned dash.

Bugs: P4-06, P4-35, P4-42, P4-47, P4-55

**Your answer:**

> recommendation

---

## D20. A finding with no CVSS vector: show "0.0" or a dash?

The board, the templates list, the new-finding duplicates and the template page show "0.0", which reads like a real score of 0.0.

**Recommendation:** a dash ("—"), in all four places.

Bug: P1-12

**Your answer:**

> dash

---

## D23. Findings list: Search box and the Withdrawn filter

Board 2.4 has a Search box and no Withdrawn segment. The app has no Search box, and it does have a Withdrawn segment.

- **Search box:** add it? It searches title, ID and assets, and needs a small backend query.
- **Withdrawn segment:** keep it or drop it? If you drop it, withdrawn findings show only under "All".

**Recommendation:** add Search. Keep Withdrawn, since it is otherwise hard to find withdrawn findings.

**Your answer:**

> Recommendation

---

## D24. Admin › System: build the missing panels?

Board 6.8 also shows these, which the app doesn't have yet:
- **Restore** (from a backup)
- **AI usage** (calls and cost)
- **Retention** (how long to keep the audit log, sessions and old check runs)
- the **Test destinations** and **Run integrity** buttons

**Recommendation:**
- Build Retention and the two buttons now.
- Leave Restore for later: it is risky and needs its own design.
- Build AI usage only if you want cost tracking.

**Your answer:**

> I want all of these to exist, if you think that adding a restore is a big task, just add it to be done, but just add the ui now. Test destinations button could be removed. I dont know whats the difference between run integrity and check again, so you can just have one run integrty button, that verifies that all is ok.

---
---

# Part 3 — Behaviour

---

## D14. An AI assistant editing several Details rows one after another

Should each edit after the first be refused because "the finding changed"?

Today the second edit fails even though nobody else touched the finding, and the message wrongly says someone else edited it. DeepSeek hit this 15 times in testing.

**Recommendation:** no.
- Check each row on its own.
- Return the new version after each edit.
- Change the message to "the finding changed since you read it".

Bug: P1-03

**Your answer:**

> Recommendation

---

## D15. When a finding changes through an AI assistant or a git push, should the open page update by itself?

Today the text stays old until you reload. Saving over it is still caught as a conflict.

**Recommendation:** yes.
- Refresh the sections that are not being edited.
- For a section being edited, keep today's conflict view.

Bug: P1-09

**Your answer:**

> Recommendation

---

## D18. Dismissing one check result: only that row, or the same wording in every section?

Today one Dismiss clears the same word in all six sections.

**Recommendation:** only that row.

Bug: P4-10

**Your answer:**

> only that row

---

## D19. How should a finding with no severity count in the severity totals?

Today the report says "9 findings", but the severity rows add up to 8.

**Recommendation:** add a "No severity" row, so the rows always add up to the total.

Bug: P4-24

**Your answer:**

> no severity is still a draft usualy with a - , any finished finding has a score, if its info its 0.0.

---

## D25. Ready to approve: list findings whose checks still block approval?

Today the director's "Ready to approve" queue includes findings that have check errors. The Approve button there then fails. On the finding page, Approve is disabled for them.

**Options:**
- **(a)** Leave them out of the queue.
- **(b)** Keep them, with a disabled Approve and an error count.

**Recommendation:** (b), so the director can see what is waiting and why.

**Your answer:**

> things should not get passed to directos, if these have errors or warnings. Director should always just get clean things, reviewers  have to dismiss the errors first. 

---

## D26. "Set a new password" for users with a temporary password

Board 1.3 has this screen, but the app doesn't. A user an admin creates with a temporary password logs straight in, and is never asked to change it.

**Recommendation:** yes, build it. On first login with a temporary password, the user must set a new one before anything else.

**Your answer:**

> yes, build it.

---

## D27. Login lockout after failed attempts?

The login page has room for a "Too many attempts" box with a countdown, but the app has no lockout. Failed logins are only written to the activity log.

If yes, also answer: how many failed attempts, and how long is the lockout?

**Recommendation:** yes, 5 attempts per user, then 15 minutes, counted per username (not per IP), and shown with a countdown.

**Your answer:**

> Recommendation

---
---

# Part 4 — AI assistant connection (MCP)

---

## D7. Which missing AI-assistant features should be built now?

**Recommendation:**
- **Build now:**
  - section text in read_finding
  - a list of the actions allowed right now
  - who-am-I, team and config lookups
  - mark notifications read
  - the same JSON answer shape everywhere
- **Note only, for later:**
  - paging
  - error codes
  - full chat history
  - tools for engagements, history, attachments, export and templates
  - a REST API (MCP stays the documented API)

Bugs: P2-09 to P2-18, P2-21

**Your answer:**

> leave it for now, till everything else is implemented and then do it all at once. it has to be replanned and discussed in detail first.

---

## D8. How strict should the AI connection be about malformed requests?

**Recommendation:**
- Accept "bearer" in any letter case.
- Stop advertising the old 2025-03-26 protocol version, instead of building request batches.
- Refuse requests with a null id or a wrong "jsonrpc" version.
- Answer an unknown status or severity filter with an error that lists the valid values.
- Accept finding IDs and row names in any case (F-7, f-007).

Bugs: P2-03, P2-05, P2-06, P2-20, P1-02

**Your answer:**

> i have no idea what any of this means.

---
---

# Part 5 — Git pushes

---

## D9. Should a git push be refused for the same things the website refuses?

Today a push can add any of these:
- a broken CVSS, bad assets, or an empty title
- a severity that contradicts the CVSS
- files over 10 MB, or programs as attachments
- broken in-between commits
- an `engagement.yaml` with an empty name, bad dates, or a changed type or source (a pentest can be turned into a retest of another engagement)

This makes pushes stricter for people who already use git.

**Recommendation:** yes to all.
- Use one shared check for the website and the push.
- Check every commit in a push, not only the end result.

Bugs: P3-05, P3-06, P3-08, P3-11, P3-20

**Your answer:**

> sure, but make sure it gives a proper reason for the refusal so its easy to debug.

---

## D10. Must a commit's author match the pusher by both name and email?

Today either one is enough, so someone can commit as "dir1" and the history credits dir1.

**Recommendation:** yes, both.

Bug: P3-12

**Your answer:**

> match by email, as this one doesnt change usualy.

---

## D11. The git help page promises checks that don't exist (rules on push, a verification lock)

Change the page or the code?

**Recommendation:** change the page to describe what really happens now. Add rules on push later, only if you say yes to D9.

Bug: P3-10

**Your answer:**

> add the rules, fulfill those promisses.

---

## D12. Should settings pushed over git take effect on the website at once?

Today the website needs a restart.

**Recommendation:** yes. Reload the settings after every push to the main repo, and check the values (not only the file format) before accepting the push.

Bug: P3-15

**Your answer:**

> yes, using git should be equivalent to using the site.

---

## D28. Redacted images: what about the unredacted original in git history?

When an image is redacted in the browser, the server stores only the redacted copy. But if the original was ever committed, for example pushed over git or added before redaction, it stays in the engagement's git history.

**Options:**
- **(a)** Rewrite the engagement's history to remove the original. This is thorough, but it breaks everyone's existing clones, which must be cloned again.
- **(b)** Keep the history, and show a warning on the image that an unredacted original exists in history, with a director-only "Purge from history" action.

**Recommendation:** (b).

**Your answer:**

> b, but this warning should be really subtle.

---

## D13. The test terminal app (yarstui): keep it in the scratch area or add it to the repo?

**Recommendation:** keep it in the scratch area.

**Your answer:**

> keep it in the scratch area

---
---

# Part 6 — Keyboard shortcuts

Questions from `docs/superpowers/plans/2026-11-05-keyboard-shortcuts.md`, section 10. No shortcut code is written until these are answered.

---

## K1. Workflow and bulk shortcuts (Shift+S / A / O / P): focus the button or fire at once?

Approve and Mark reported can't be undone from the UI.

**Recommendation:** focus only; Enter confirms.

**Your answer:**

> there should be an undo button for these actions. all actions should be reversible by design. fire at once.

---

## K2. E (edit) with the mouse hovering: should the hovered section count?

It's convenient, but it can surprise you when the mouse happens to rest somewhere.

**Recommendation:** no.

**Your answer:** OK, i got how i want it to work. when a section is clicked it should be selected. the selection should be visible by a slightly visible change to the boarder of the section. pressing arrows or jkhl should move the user between sections. pressing e should open section in edit mode. pressing ctrl s just saves it. having nothing selected should do nothing. pressing enter in this nonedit state should change the state of the buttons if those are in section, i.e. approve, check etc.

> 

---

## K3. E with nothing selected: which panel opens?

**Options:**
- **(a)** The first editable panel (Details).
- **(b)** The first text section (usually Description).

**Recommendation:** (b).

**Your answer:** as above.

> 

---

## K4. Ctrl+S during a save conflict

**Options:**
- **(a)** Do nothing, and move focus to "Keep mine".
- **(b)** Act as "Keep mine".

**Recommendation:** (a).

**Your answer:** a

> 

---

## K5. Which plain forms should Ctrl+S save?

**Proposed:** template meta, rule, destination, engagement General, Settings Account / Preferences / Notifications, webhook and AI.
**Left out:** Password, Add user, New engagement and Connections.

**Recommendation:** as proposed.

**Your answer:** all fields if selected.

> 

---

## K6. Where do shortcuts show?

**Options:**
- **(a)** Only in the `?` overlay.
- **(b)** Also in button tooltips, e.g. "Approve · Shift+A".

**Recommendation:** (a), per the no-helper-text rule.

**Your answer:** a

> 

---

## K7. In the Redact dialog: Ctrl+S to save and Ctrl+Z to undo?

Drawing the boxes stays mouse-only.

**Recommendation:** yes.

**Your answer:** 

> yes

---

## K8. Key names

The proposal uses `g` sequences (g i = inbox, …), `[ ]` to switch tabs, and `h` for History.
- Is that too many?
- Which keys would you change?
- Should "new" be `n` or `c`? (`c` is Comment.)

**Recommendation:** keep them as proposed, with `n` for new.

**Your answer:** 

> there should be no sequences, c for comment, i for inbox, history has to use other key.

---

## K9. An on/off switch for keyboard shortcuts?

It would be a "Keyboard shortcuts On/Off" setting in Preferences. The accessibility guideline WCAG 2.1.4 recommends one.

**Recommendation:** yes.

**Your answer:**

> yes

---

## K10. Bugs found while planning shortcuts

The engagement picker and the CVSS severity select act as soon as the value changes. Fix them in the shortcuts work, or separately?

**Recommendation:** separately, now, as bugs.

**Your answer:**

> Recommendation

---

## K11. Inbox: Shift+x to select a range from the last ticked row?

**Recommendation:** yes.

**Your answer:**

> what?

---
---

# Anything else

Other notes, changes of mind, or things to add:

> there should be also a button that makes the AI agent deployed and attempt at fixing all of the issues. there should be also a github precommit hook, that runs the check for the finding and marks if there are issues with it according to the scripts.

---
---

# Round 2 — follow-up questions (added after your answers)

Everything else you answered is being built now. These are the ones that were unclear, or where your answer raises a new question.

---

## R1 (was D5). Engagement pages: three duplicated things

Plainer version. An engagement has tabs: Overview, Findings, Report and Settings. Three things on them repeat something shown elsewhere:

1. **Overview tab.** At the top are number tiles, e.g. "12 findings · 3 critical". Below are bar charts, and under each bar chart there is a legend that repeats the same numbers again, plus a small table that repeats them a third time. **Proposal:** keep the tiles and the charts; remove the repeated legends and tables.
2. **Findings tab.** Under the findings table there is a box with the `git clone …` command for this engagement. **Proposal:** show the clone command only on the Developers › Git page, not under every findings list.
3. **Settings tab.** It has a "Preferences" panel with a light/dark theme choice, the same as the toggle in the top bar. **Proposal:** remove that panel. (You said to skip dark mode for now; see R9.)

Answer per item, e.g. "1 yes, 2 no, 3 yes".

**Your answer:**

> 

---

## R2 (was D8). Strictness of the AI connection

Plainer version. When an AI tool talks to YARS and sends a slightly wrong request:

1. It writes its key as "bearer abc…" instead of "Bearer abc…". Today that is refused. **Proposal:** accept it.
2. It sends a few technical details (protocol version, request number) in a way the MCP standard doesn't allow. Today YARS ignores the mistakes. **Proposal:** follow the standard strictly. Real AI tools are not affected.
3. It asks for findings with a status that doesn't exist, e.g. "Verified". Today it silently gets an empty list, so the AI thinks there are none. **Proposal:** answer with an error that lists the real statuses.
4. It asks for "f-7" instead of "F-007". Today that is not found. **Proposal:** accept both.

You also said to leave the AI connection until everything else is done (D7). **Recommendation:** fold this into that later MCP plan too.

**Your answer:**

> 

---

## R3 (was K11). Selecting a range of rows in the inbox

Plainer version. In the inbox and the findings list you tick rows with checkboxes before using the bulk bar. "Range select" means: tick row 3, then shift-click row 9, and rows 3–9 all get ticked, as in Gmail. The question was whether to have this, and which key or click does it.

**Recommendation:** yes, as Shift+click on a checkbox. With your keyboard model, also Shift+Space on the selected row.

**Your answer:**

> 

---

## R4 (from K1). "All actions should be reversible": how should undo work?

Today Approve (to Complete) and Mark reported can't be undone from the web page.

**Options:**
- **(a)** After an action, its button turns into "Undo" in the same place for 10 seconds.
- **(b)** Permanent reverse actions: a director can always "Reopen" a Complete finding (back to Verification) and "Unmark reported" (back to Complete). They are shown in the workflow bar, with a reason, and written to the history.
- **(c)** Both.

**Recommendation:** (b). A 10-second Undo is easy to miss, and a button that changes into another one breaks "nothing moves".

**Your answer:**

> 

---

## R5 (from K2). Keyboard: Enter on a selected panel

You described it: click a panel to select it, a subtle border shows the selection, arrows or `j k h l` move between panels, `e` edits, Ctrl+S saves, nothing selected does nothing, and Enter presses the panel's buttons.

When a selected panel has several buttons (the workflow bar can have Return, Sign off and Approve), what does Enter do?

- **(a)** Inside the selected panel, Tab or left/right moves between its buttons, and Enter presses the highlighted one.
- **(b)** Enter presses the panel's main (orange) button.

**Recommendation:** (a). Also, since `h` and `l` move left and right between panels, they can't be used for anything else.

**Your answer:**

> 

---

## R6 (from K8). Which key for History?

You said no sequences, `c` = comment, `i` = inbox, and History needs a key other than `h`.

**Recommendation:** `y`, which is free; or `v` for "versions".

Also, do these single keys sound right?
- `n` new finding
- `b` team board
- `f` findings list
- `/` search
- `?` shortcut list

**Your answer:**

> 

---

## R7 (from Anything else). The "AI fixes all issues" button

Questions:
1. **Where:** on a finding (it fixes that finding's check results), or also on the findings list (all findings at once)?
2. **What it may do:**
   - **Recommendation:** edit section text, CVSS and Details only.
   - It never changes a finding's state, never dismisses checks, and never edits other people's findings.
   - Each change shows as a normal edit in History, signed by "AI for <you>".
3. **Which AI:** the provider set in Admin › AI.

**Your answer:**

> 

---

## R8 (from Anything else). A git pre-commit hook for findings

A small hook you install in your clone (`yars hook install`). Before each commit, it runs the same checks as the Check button on every finding you changed.

What should it do when it finds problems?
- **(a)** Warn only, and still commit.
- **(b)** Block the commit on errors, and warn on warnings. You can bypass it with `git commit --no-verify`.

**Recommendation:** (b).

Note: you said "github" pre-commit hook. I take that to mean git (the hook runs on your machine), not a GitHub action. Correct me if you meant GitHub.

**Your answer:**

> 

---

## R9 (from D6). Dark mode "skipped for now"

Does this mean:
- **(a)** Keep the dark toggle as it is, but stop all dark-mode work and checks until it is remade.
- **(b)** Hide the dark toggle until it is remade, so nobody sees half-finished dark pages.

**Recommendation:** (b).

**Your answer:**

> 

---

## R10 (from D19). Findings with no severity in the totals

You said a finding without a severity is a draft, shown with "—", and every finished finding has a score (Info is 0.0).

So, to check I read you right:
- **Reports and exports** include only finished findings, so their totals always add up.
- **The Overview chart** shows unscored drafts as a "—" row.

**Your answer:**

> 

---

## Notes on how I read your other answers (correct me here if wrong)

- **D22:** the workflow bar stays two rows.
- **D24:**
  - Build Retention and AI usage.
  - Build Restore too, all at once if feasible; otherwise its screen now and the rest as a recorded task.
  - Remove "Test destinations".
  - One "Run integrity" button replaces both "Check again" and "Run integrity". It checks everything.
- **D25:** a finding reaches a director only when it has no open errors **or warnings**. Reviewers must dismiss them first, so Sign off stays disabled while any are open.
- **D10:** a commit's author must match the pusher by email; the name may differ.
- **D11:** build what the git page promises:
  - rules run on every push;
  - a finding in Verification is locked against pushes, except by its reviewers and directors.
- **D9:** every refusal names the file, the commit and the exact rule, so it's easy to fix.
- **D28:** a very subtle mark on the image (a small dot in the corner, with the detail on hover); purge is director only.
- **K5:** Ctrl+S saves any form while one of its fields is focused, except the login page.

**Corrections:**

> 

---
---

# Round 2 answers (given in chat, 2026-11-07)

- **R1:**
  1. Yes, keep only the tiles and the charts on Overview.
  2. No: keep the git clone box at the bottom of the findings list, as a reminder.
  3. Yes, remove the Preferences theme panel from engagement Settings.
- **R2:** fold it into the later MCP plan.
  1. Accept "bearer" in any letter case.
  2. Follow the MCP standard strictly.
  3. Refuse an unknown status with an error that lists the valid ones, and tell the AI the valid statuses up front (in the tool descriptions and the server instructions).
  4. Accept "f-7" as "F-007".
- **R3:** yes, Shift+click (and Shift+Space) ticks a range of rows.
- **R4:** every action can be reverted to the previous state. A "Revert" action takes Complete back to Verification and Reported back to Complete, with a reason, written to the history.
- **R5:** Enter does nothing when the selected panel has several buttons.
- **R6:** Shift+H opens History.
- **R7:** the AI answers only YARS's automatically generated comments (check results). It makes the fix in the finding automatically and replies in the thread, and both the edit and the reply are marked as done by AI.
- **R8:** the pre-commit hook only warns; it never blocks a commit.
- **R9:** keep the dark toggle; the dark mode remake goes on the to-do list.
- **R10:** correct. Reports and exports count finished findings only, and the Overview shows unscored drafts as a "—" row.

---

# Round 3 — questions from the build (added 2026-11-08)

These came up while building your answers. Everything else is built and working. Leave any blank, and I'll go with the recommendation once you say so.

---

## Q1. Must someone press Check before Sign off or Approve?

Some rules (scripts and AI) run only when someone presses Check, and on Submit and Approve. A reviewer could change the text and sign off without pressing Check. The finding then shows as clean in the director's queue, and the director's Approve fails on an error nobody saw.

**Options:**
- **(a)** Keep it as it is now.
- **(b)** Sign off and Approve need a finished Check on the current text. Until then, both buttons are disabled and the finding is not in Ready to approve. Page, queue and buttons always agree.

**Recommendation:** (b). It fits your answer that directors only get clean findings.

**Your answer:**

> b, but there has to be a toggle in admin panel that allows for it to be a disabled setting. 

---

## Q2. Should an admin's "Reset password" also cancel that user's AI and git tokens?

A reset usually means the password leaked. Today the user's tokens stop working until the new password is set, then work again.

**Recommendation:** yes. Cancel them for good on a reset, and show "tokens revoked: 2" on the confirmation.

**Your answer:**

> no, reset password assumes someone lost the password / forgot. 

---

## Q3. A way out when every admin is locked out

Anyone who knows an admin's username can keep that account locked by typing 5 wrong passwords every 15 minutes. If every admin is locked out, nobody can unlock from the website.

**Recommendation:** add a command-line `yars unlock <user>` for the server owner.

**Your answer:**

> sure, you can add that command, but thats not really an issue as this is supposed to be an internalt tool. Also, btw, add to settings default project for yars, so it does not have to be specified each time a command is being run.

---

## Q4. The retest result buttons (Fixed / Partially fixed / Not fixed) save as soon as you move between them with the arrow keys

This is the same problem as the two dropdowns that were just fixed.

**Recommendation:** save only on click, Space or Enter, like the dropdowns.

**Your answer:**

> Recommendation

---

## Q5. Should AI rules run on every git push?

Each AI rule can take up to 90 seconds per finding, and costs a call per section. Meanwhile the engagement is locked against other changes. Today a push runs every other rule, lists the AI rules as "could not run", and Check on the website runs them.

**Recommendation:** keep AI rules off on push.

**Your answer:**

> I assumed those were run on commits, and then push is done on clean fidings. you can keep rules off on push this way.

---

## Q6. A finding in Verification is locked for its author over git. Lock it on the website too?

On the website, the author can still edit a finding in Verification. That lets them fix what a reviewer asked without a Return. Over git, it is locked, as the git page promised.

**Recommendation:** keep the website as it is, and git stricter.

**Your answer:**

> Recommendation

---

## Q7. A draft with a rule error: refuse the push?

Today a push accepts a draft with errors and lists them as "blocks Submit", just as the website saves drafts with errors. Findings in Verification or later are refused.

**Recommendation:** keep it as it is.

**Your answer:**

> Recommendation

---

## Q8. Renaming a section, severity or details row in a pushed config.yaml

Admin › Structure renames the name inside every finding too. A push can't tell a rename from a removal plus an addition, so findings would keep the old name, and the website would no longer show it.

**Recommendation:** refuse a pushed config.yaml that drops a name findings still use, list those findings, and point to Admin › Structure for renames.

**Your answer:**

> Recommendation

---

## Q9. Field | Value header in the exported documents (PDF, Word, Confluence) too?

It is in the web pages and the report preview now.

**Recommendation:** no. Keep the documents as the Report-PDF board shows them.

**Your answer:**

> Recommendation

---

# Round 4 — questions from the build (added 2026-11-08)

Everything from Round 3 is built and working. Leave any blank, and I'll go with the recommendation once you say so.

---

## Q10. Should Admin › Structure rename a section, severity or details row inside every finding?

Correction to what I wrote in Q8: Admin › Structure only renames report sections inside findings. For finding sections, severities and details rows, a rename there leaves the findings on the old name, and the website then no longer shows it. The page also lets an admin remove a name that findings still use, without warning. A git push of the same change is now refused: "<name> is still used by: <findings>. Change those findings first, then remove the name."

**Recommendation:** yes, as a later task. Admin › Structure renames the name in every finding, and refuses to remove a name findings still use, as the push does.

**Your answer:**

> 

---

## Q11. With "Require Check" on, should an AI rule that couldn't run block Sign off and Approve?

When an AI rule can't run (the AI service is down or times out), the Check still ends as "Done" with "AI checks failed", and Sign off and Approve work, though the AI never read the text. A script rule that fails blocks.

**Recommendation:** block when an AI service is set up but the call failed (Retry is on the row). Don't block when no AI service is set up at all, since the AI rules can never run then.

**Your answer:**

> 

---

## Q12. Should the engagement board also hide bulk Approve for a finding without a current Check?

Ready to approve in the inbox already leaves such findings out. The engagement board still offers Approve in its bulk actions for them; the server then skips them with "run check first", and the board's "Signed off" count includes them.

**Recommendation:** yes. The board offers Approve only when it would work, the same as the inbox.

**Your answer:**

> 

---

## Q13. Should a rule change make the last Check out of date?

Today a Check counts as current while the finding's text is unchanged. If an admin adds or changes a rule afterwards, the old Check still lets Sign off and Approve through.

**Recommendation:** yes. A Check run before the rules last changed counts as out of date, and the page shows "Run Check first".

**Your answer:**

> 

---

# To do later (agreed, not started)

- **Dark mode:** a full remake. Until then, no dark-mode tuning or checks.
- **MCP / AI connection:** replan in detail with the user once everything else is done. It covers D7 and R2.
- **AI fixes check comments (R7):** design on the canvas first.
- **Git pre-commit hook (R8):** warns only; runs the finding checks locally.
- **Keyboard shortcuts:** the selection model from K2, plus K4–K9, R3, R5 and R6. Design on the canvas first.
- **Revert to the previous state (R4).**
- **Admin › System Restore:** the screen now; the backend as its own task if it is too large.

---

# Status (checked 2026-11-11)

One row per decision. "Built" names the test that pins it; "Not built → M<n>" names the milestone of the roadmap to v1.0 (`docs/superpowers/plans/2026-11-11-yars-roadmap-to-v1.md`).

| Id | Subject | Status | Pinned by |
|---|---|---|---|
| D2 | Checks panel as a closed strip | Not built → M24 | |
| D3 | No error list under the workflow bar | Not built → M24 | |
| D4 | Side column and title row tidied | Not built → M24 | |
| D5 | Repeated numbers on engagement pages | Replaced by R1 | |
| D6 | Dark "0" badges | Replaced by R9; colour tokens → M33, new dark colours after v1.0 | |
| D7 | Missing AI-assistant features | Not built → M32 | |
| D8 | Strictness of the AI connection | Replaced by R2 | |
| D9 | A push refused for what the website refuses | Built | `cmd/yars` `TestPushRefusesWhatWebRefuses` |
| D10 | Commit author matched by email | Built | `cmd/yars` `TestPushAuthorEmail` |
| D11 | Rules on push; verification locked over git | Built | `cmd/yars` `TestPushRunsCheckRules`, `TestPushLockedByDatabaseState` |
| D12 | Pushed settings apply at once | Built | `cmd/yars` `TestPushedConfigApplies`; `store` `TestSetConfigInOrder` |
| D13 | yarstui stays outside the repo | Dropped (nothing to build) | |
| D14 | AI edits of several Details rows | Built | `store` `TestDetailsRowsCheckedPerRow`; `mcp` `TestMCPRowEditsOneAfterAnother` |
| D15 | Open pages update by themselves | Built | `web` `TestFindingPanelsRefreshLive` |
| D16 | Field / Value header row | Built | `web` `TestLabelValueTablesHaveHeader` |
| D17 | One empty-table style | Built | `web` `TestOneEmptyTableStyle` |
| D18 | Dismiss one row only | Built | `store` `TestDismissOneRowOnly` |
| D19 | No severity in the totals | Replaced by R10 | |
| D20 | No CVSS vector shows "—" | Built | `web` `TestNoScoreIsADash` |
| D21 | Status panel folded into the chat | Not built → M24 | |
| D22 | Workflow bar keeps two rows | Built | `web` `TestD22TwoRowBar` |
| D23 | Findings search; Withdrawn kept | Not built → M23 | |
| D24 | Admin › System panels | Not built → M25 | |
| D25 | Directors get clean findings only | Built | `store` `TestOpenWarningBlocksSignOffAndApprove`; `web` `TestReadyToApproveSkipsOpenChecks` |
| D26 | Set a new password after a temporary one | Built | `web` `TestTemporaryPasswordMustBeChanged` |
| D27 | Login lockout | Built | `db` and `web` `TestLoginLockout` |
| D28 | Redaction mark and purge | Not built → M26 | |
| K1 | Workflow shortcuts fire at once; undo | Shortcuts → M29; undo replaced by R4 | |
| K2 | Panel selection model | Not built → M29 | |
| K3 | E with nothing selected | Not built → M29 (as K2) | |
| K4 | Ctrl+S during a conflict | Not built → M29 | |
| K5 | Ctrl+S on every form | Not built → M29 | |
| K6 | Shortcuts only in the `?` list | Not built → M29 | |
| K7 | Ctrl+S and Ctrl+Z in Redact | Not built → M29 | |
| K8 | Key names, no sequences | Not built → M29 | |
| K9 | Shortcuts on/off | Not built → M29 | |
| K10 | Selects act on a choice only | Built | `web` `TestSelectsActOnChoiceOnly` |
| K11 | Range select in the inbox | Replaced by R3 | |
| R1 | Engagement pages: 1 overview legends and tables; 2 clone box; 3 theme panel | 1 Not built → M23; 2 Built (kept); 3 Built (none) | 2 `web` `TestCloneHint`; 3 `web` `TestR1NoThemeOnEngagementSettings` |
| R2 | Strictness of the AI connection | Not built → M32 | |
| R3 | Shift+click range select | Not built → M29 | |
| R4 | Revert to the previous state | Not built → M27 | |
| R5 | Enter on a panel with several buttons | Not built → M29 | |
| R6 | Shift+H for History; single keys | Not built → M29 | |
| R7 | AI fixes check comments | Not built → M31 | |
| R8 | Pre-commit hook that warns | Not built → M30 | |
| R9 | Dark toggle kept | Built | `web` `TestShellHeader` |
| R10 | Unscored drafts in totals | Not built → M23 | |
| Q1 | Require Check, with an admin toggle | Built | `store` `TestRequireCheckGate`, `TestRequireCheckOff` |
| Q2 | A reset keeps the user's tokens | Built | `auth` `TestMustChangeRefusesTokensAndCheck` |
| Q3 | `yars unlock`; a default data folder | Built | `cmd/yars` `TestUnlockCommand`, `TestUseCommand` |
| Q4 | Retest results save on a choice only | Built | `web` `TestRetestRadiosActOnChoiceOnly` |
| Q5 | AI rules off on push | Built | `cmd/yars` `TestPushRunsCheckRules` |
| Q6 | Author edits in Verification on the website | Built | `web` `TestAuthorEditsInVerificationOnWebsite` |
| Q7 | A draft with a rule error is pushed | Built | `cmd/yars` `TestPushRunsCheckRules` |
| Q8 | A pushed config dropping a used name is refused | Built | `policy` `TestPolicyConfigDropsUsedName` |
| Q9 | Field / Value header not in documents | Built | `export` `TestReportKVHeaderOnlyInPreview` |
| Q10 | Structure renames inside findings | Not built → M23 | |
| Q11 | A failed AI check blocks while AI is set up | Not built → M23 | |
| Q12 | Board bulk Approve only where it works | Not built → M23 | |
| Q13 | A rule change makes the last check out of date | Not built → M23 | |

Rows with no test: none.
