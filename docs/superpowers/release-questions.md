# Open questions before v1.0

Answer under each question, or reply in the chat with the numbers ("all recommended", or e.g. "all recommended except 4 no, 25 c").

## A. Open limits to fix (from docs/known-limits.md)

1. AI rules can give different answers on the same text. Fix: temperature 0, and reuse the stored result while the text is unchanged.
   Recommended: yes
   Answer: store check if text was verified with ai in unchanged form, dont set temp 0. output is already in comments.

2. A finding's text can talk an AI rule into passing it (prompt injection). Fix: mark the finding's text as data in the prompt; the docs advise keeping AI rules at warning level rather than error.
   Recommended: yes
   Answer: y

3. Check runs have no server-wide limit. Fix: a configurable limit; runs over it wait in a queue instead of being refused.
   Recommended: yes
   Answer: y

4. Old repositories still hold password hashes in their git history. Fix: a purge a director runs on purpose, never automatically. It rewrites history, so every clone has to be made again.
   Recommended: yes
   Answer: doesnt matter, was not used in prod anywhere

5. Confluence exports embed images as data URIs, which Confluence may not show. Fix: upload them as page attachments.
   Recommended: yes
   Answer: you have to attach those files somehow so these are embeded in text, not under as attachments. that is possible.

6. Some pandoc builds cannot write .docx inside the sandbox, and YARS then quietly runs them without it. Fix: show that under Admin › System.
   Recommended: yes
   Answer: leave as is

7. A director's git push to an approved finding moves the approval before the push is accepted; if the push then fails, the finding drops back to verification. Fix: move it only after the push lands.
   Recommended: yes
   Answer: y

8. Many first logins of one account at once over git are partly refused (401). Fix: find where they fail and fix it.
   Recommended: yes
   Answer: y

9. MCP reports the server's own failures (disk, database) as the client's mistake (`invalid`). Fix: a `server_error` code.
   Recommended: yes
   Answer: y

10. MCP's `transition` approves the finding as it is when the call lands, not the version the client read. Fix: an optional `base` (content hash), as the website already checks.
    Recommended: yes
    Answer: y

11. MCP reports version "1". Fix: report the real build version.
    Recommended: yes
    Answer: y

12. A retest copies attachments as they are; a later redaction in the source is not applied to the copy. Fix: redact in the retest too, and have a purge list the retests that hold a copy.
    Recommended: yes
    Answer: y

13. An attachment over 20 MB fails a retest with a vague "try again". Fix: the message names the file and the limit.
    Recommended: yes
    Answer: y

14. In a SHA-256 repository (only one made by hand), creating or deleting a branch gets a misleading refusal. Fix: correct the check.
    Recommended: yes
    Answer: y

## B. A decision about sign-offs

15. Changing an attachment of a finding in verification keeps its sign-offs; changing the text drops them. Should an attachment change drop them too?
    Recommended: yes, drop them (the stricter rule)
    Answer: y

## C. Limits to keep as they are

16. Script rules run every time, with no cache. The alternative is a cache the rule's author turns on (`cache: true`).
    Recommended: keep
    Answer: cache should be default, no need to add option to turn it off

17. Saving a section rewrites its heading in the standard `## Name` form (only when the section really changed).
    Recommended: keep
    Answer: y

18. MCP over HTTP has no OAuth metadata; it uses the bearer token, as documented.
    Recommended: keep
    Answer: y

19. A push to the main repository is refused right after the server updated it; the message says to pull first.
    Recommended: keep
    Answer: y

20. MCP ignores argument names it does not know; refusing them would break working clients.
    Recommended: keep
    Answer: y

21. The bulk bars sign off and approve without the finding having been opened; their rows show no text to read.
    Recommended: keep
    Answer: y

22. A workflow bar opened before a change refuses the sign-off; it says why, and a second click works.
    Recommended: keep
    Answer: y

23. A built-in check's message near 300 characters gets cut; none of the current messages is that long.
    Recommended: keep
    Answer: Keep the full message (up to a much higher limit, so a script or AI rule still can't flood the page). Let the Message column end in "…" on screen, and show the whole text on hover, as the shortened names already do.

## D. Small UI items

24. After d or r on a row (Rules, Webhooks, Users, Tokens), the page reloads and the selection goes back to the top. Fix: keep the same row selected.
    Recommended: yes
    Answer: y

25. The empty Sign off space between Return and Approve (a director who is not a reviewer).
    a) leave the gap
    b) a disabled Sign off button in it
    c) close the gap, so Approve moves left
    Recommended: b
    Answer: director always has reviewer options, even if not selected as reviewer. 

26. Outside an engagement, picking the engagement the picker already shows does nothing. Fix: open that engagement.
    Recommended: yes
    Answer: y

27. The selected row's tint is faint in the light theme. Fix: make it stronger (before and after shown to you).
    Recommended: yes
    Answer: n

28. Clicking a row's empty cell does not select the row, so a and r need the keyboard first. Fix: a click anywhere on the row selects it.
    Recommended: yes
    Answer: y

33. Browser Back on the team board loses a typed reply without asking (Back between leads stays inside the page, so neither the app's dialog nor the browser's leave warning appears).
    a) leave it
    b) Back asks "Discard changes?" first; Cancel keeps you on the lead you were on
    c) Back between leads reloads the page, so the browser's own leave warning appears
    Recommended: b
    Answer: b

## E. Dark theme

29. New dark-theme colours (the plan leaves choosing them to you): before release or after v1.0?
    Recommended: after
    Answer: before

## F. Release

30. Final test: the full test suite, the v1.0 walkthrough again on a fresh build with fresh test data, every page at 1440×900 in both themes, and a final review of the release PR. Should I also write a short checklist for your own pass?
    Recommended: yes
    Answer: yes + do a full demo test run using opencode deepseek to verify that agents can menage it

31. Release notes for v1.0.0 (docs/release-notes.md, ready to paste into the GitHub release).
    Recommended: yes
    Answer: yes, dont do it before asking me, dont push etc. 

32. How you will merge.
    a) #1 to #30 in order with "Create a merge commit" (not squash, which breaks the stacked branches), deleting each branch after merging so GitHub moves the next PR onto master
    b) merge #30's branch into master once and close #1–#29 (same code; those PRs show as closed, not merged)
    Recommended: a
    Answer: a
