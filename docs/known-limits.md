# Known limits

What the polish backlog left open (it was `docs/superpowers/deferred-minors.md` until M34 triaged it and removed it), what M34's reviews found and did not fix, and what is left after the decisions of 2026-11-22 (`docs/superpowers/release-questions.md`). Every other line of the backlog was fixed, each with a test that fails without the fix.

## Won't do

| Limit | Why not |
|---|---|
| Readers can briefly see a half-written `chat.jsonl` | `chat.jsonl` no longer exists: chat is in the database since M10. |
| Test gap: commit-failure rollback for chat | Chat makes no commit since M10. |
| Test gap: `.gitattributes` created by a transition | No transition writes `.gitattributes`. |
| Old repositories still hold password hashes in their git history (`users.yaml` is untracked since M6) | Decided 2026-11-22: no repository from before M6 was used in production. One that was: have the accounts of that time change their passwords. |
| Some pandoc builds cannot write docx under `--sandbox`; the fallback runs without it | Decided 2026-11-22: leave as is. The text pandoc gets is already cleaned (no raw HTML, images inlined); `docs/deploy.md` says a static pandoc release keeps the sandbox. |
| A save writes a section heading in its canonical form (`## Name`, spaces after it trimmed) | Decided 2026-11-22: keep. An unchanged save writes nothing, so only a real change rewrites the heading. |
| MCP over HTTP has no OAuth protected-resource metadata | Decided 2026-11-22: keep. YARS has no authorization server to name; the bearer token is documented in `docs/mcp.md`. |
| A push to the main repository is refused as non-fast-forward right after the server moved engagement pointers | Decided 2026-11-22: keep. The server manages the pointers, and the refusal says to pull first (`docs/git.md`). |
| MCP: argument names a tool does not know are ignored | Decided 2026-11-22: keep. Refusing them would break working clients. |
| The bulk bars (the inbox's and the findings list's) sign off and approve without a viewed version | Decided 2026-11-22: keep. Their rows show no finding text to have read. |
| A workflow bar opened before a change refuses a sign-off of the content the page now shows | Decided 2026-11-22: keep. The refusal says why, and a second click works. |

## Left after the 2026-11-22 decisions

| Limit | Note |
|---|---|
| Stored rule results (`rule_cache`) have no engagement column, so a purge does not clear them; they age out with the check-run retention | Clearing them per engagement needs a later migration; clearing the whole table would pay for every AI call again. |
| The push hook and `yars lint` run scripts and AI rules without the stored results | They work without the server's database by design. |
| Two OpenAI-compatible endpoints serving the same model name share stored AI results | The base URL is not part of the key, as in the in-memory cache before. |
| `checks.max_running` is set in `.yars/config.yaml` only | No Admin page shows or edits it. |
| MCP's `transition` `base` covers `finding.md`, not the attachments | The website also sends the attachments it showed (`seenfiles`); over MCP an attachment change since `read_finding` is not refused (it drops sign-offs in verification anyway). |
| A director may sign off their own finding, and a second director may then approve on that sign-off alone | As decided (Q25): the approver is someone other than the author. Requiring a third person is a one-line change in `reviewedByOther`. |
| An Approve can land while an attachment upload is being committed | The approval then stands for a file the director did not see; the upload, in verification, drops sign-offs. |
| A redaction does not reach a retest copy the redactor may not edit (a complete or reported copy for a non-director, a retest they are not on) | Those copies are reported after the redaction and listed on the purge page; a director's redaction reaches them. |
| The Confluence push's attachment calls were tested against a fake server only | Unconfirmed on a real Confluence: attachment PUT on older Server/DC, the comment in the attachment list, DELETE on Server/DC. An upload failure on a new page leaves it empty until the next send. |
| A built-in check's configured message near the 4,000-character cut loses its detail | None of the built-in messages is that long; the whole message shows on hover. |
| A redaction finds retest copies by the file's git object id | That assumes the source and the retest use the same object format, as every repository YARS makes does. |
