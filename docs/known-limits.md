# Known limits

What the polish backlog left open (it was `docs/superpowers/deferred-minors.md` until M34 triaged it and removed it), and what M34's reviews found and did not fix. Every other line of the backlog was fixed, each with a test that fails without the fix.

## Won't do

| Limit | Why not |
|---|---|
| Readers can briefly see a half-written `chat.jsonl` | `chat.jsonl` no longer exists: chat is in the database since M10. |
| Test gap: commit-failure rollback for chat | Chat makes no commit since M10. |
| Test gap: `.gitattributes` created by a transition | No transition writes `.gitattributes`. |

## Needs a decision

| Limit | Recommendation |
|---|---|
| A save writes a section heading in its canonical form (`## Name`, spaces after it trimmed) | Keep. An unchanged save no longer writes at all (M34), so only a real change rewrites the heading. |
| Script rules' results are not cached | Keep running scripts each time. A cache would need the rule's own promise that its script is deterministic: an opt-in `cache: true`, keyed by the script's content and the finding (Q13). |
| `/checks` has no limit on runs at once (one per finding already) | A server-wide limit that queues runs rather than refusing them, since Require Check (Q1) makes Check a required step. |
| Error-level AI rules can give another answer on the same text | Temperature 0 for Anthropic too, and AI results kept in the database by their cache key, so a run on unchanged text answers as the last one did. |
| Text in a finding can talk an AI rule into passing it (prompt injection) | Mark the finding's text as data in the prompt, and keep AI rules at warning level where they gate Submit. |
| Old repositories still hold password hashes in their git history (`users.yaml` is untracked since M6) | An opt-in history purge of `.yars/users.yaml` for directors, never automatic: a rewrite breaks every clone (D28's reasoning). |
| The Confluence push embeds images as data URIs, which Confluence may not show | Upload them through Confluence's attachments API after the page is made (about 100 lines with a fake-server test). |
| Some pandoc builds cannot write docx under `--sandbox`; the fallback runs without it | Say in `docs/deploy.md` that a static pandoc release keeps the sandbox, and show the fallback under Admin › System. |
| MCP over HTTP has no OAuth protected-resource metadata | Don't: YARS has no authorization server to name; the bearer token is documented in `docs/mcp.md`. |
| Attachments are not covered by a sign-off (the clearance hash is `finding.md`'s) | Drop sign-offs when an attachment of a finding in verification changes, as a text change does. It changes what a sign-off covers, so it is the user's call. |
| A director's push to an approved finding moves the approval before the push lands; if it then fails, the finding falls back to verification | Record the move in the hook and apply it after the push lands (about 65 lines). |
| A push to the main repository is refused as non-fast-forward right after the server moved engagement pointers | Keep: the server manages the pointers, and the refusal says to pull first (`docs/git.md`). |
| Many first logins of one account at once over git (found in M34: 24 parallel requests) are partly refused with 401 | Find where they fail (the login's database writes under load, most likely) and retry there; a clone fetching submodules in parallel can meet it. |
| MCP: a failure of the server itself (disk, database) answers with the code `invalid` (M32 kept the plan's seven codes) | An eighth code, `server_error`, so a client can tell its own mistake from the server's and retry. |
| MCP: argument names a tool does not know are ignored (M32) | Keep: clients and tests send extra names; refusing them would break working clients for no gain. |
| A retest copies its findings' attachments as they are: one redacted or purged later in the source stays as it was in the retest (D28 is about one engagement's history) | Redact in the retest too; a purge in the source could list the retests that hold a copy (M34 review). |
| An attachment over the 20 MB limit (only a hand edit makes one) fails a retest with the form's "try again" | Name the file and the limit in the form's message. |
| MCP's `transition` signs off and approves the finding as it is when the call lands, not as `read_finding` showed it (the website's bar refuses a changed finding since M34) | An optional `base` on `transition` for `clear` and `approve`: the content hash, which `read_finding` would return too. |
| The inbox's bulk bar signs off and approves without a viewed version | Keep: its rows show no finding text to have read. |
| A workflow bar opened before a change can refuse a sign-off of the content the page now shows (its refresh waits while a picker or reason panel is open) | Keep: the refusal says why, and the page comes back current, so a second click works. |
| A built-in check's configured message near the 300-character cut loses its detail | Keep: none of the built-in messages is that long. |
| In a SHA-256 repository a pushed branch deletion or new branch is refused with a misleading reason (the hook's zero id is SHA-1's) | Compare with the zero id of the pushed id's length. YARS makes SHA-1 repositories, so only one made by hand meets it. |
