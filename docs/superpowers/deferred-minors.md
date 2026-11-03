# Deferred minors (polish backlog)

Small issues found by the end-of-milestone reviews and deliberately left for the polishing phase.

## Core (M1–M2)
- Section anchor IDs can collide for non-ASCII section names.
- Heading trailing spaces are trimmed; an empty `## ` heading creates a section with no route.
- A BOM, empty front matter, or a file ending in `---` without a newline is rejected; the finding page shows a bare 500.
- Writes aren't atomic (truncate + write).
- Sessions never expire; users load only at startup; no login rate limit.
- No server timeouts or request body limits.

## M3 Workflow
- A 403 after a finding gets locked is invisible in an open htmx editor (plain-text 403 isn't swapped).
- The workflow bar isn't refreshed after a content save drops clearances (stale ✓ until reload).
- A denied action re-renders at the POST URL; a typed return reason is lost.
- The author can empty the reviewer list during verification.
- Every full page 500s if the index fails (the inbox badge is computed in `base()`).
- `cvss/calc` renders the editor on a locked finding (writes nothing).

## M4 Chat
- Readers can briefly see a half-written chat.jsonl (truncate-then-write; readers don't take the lock).
- A failed reply's text lands in the main composer.
- Resolving an already-resolved thread (double click) makes an extra commit.
- Replies can carry a section tag that means nothing.
- Missing timestamps in hand-edited lines show as `0001-01-01 00:00`.
- Sorting by Chat starts ascending (0 open first).
- Section open-thread counters only update on reload.
- After a server restart, polling with an expired session swaps the login page into the chat column.
- Test gaps: commit-failure rollback for chat; `.gitattributes` created by a transition; composer untouched by poll swaps.
