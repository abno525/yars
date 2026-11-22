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

## Left after the final test

| Limit | Note |
|---|---|
| Without an AI provider, every finding shows an orange "AI checks failed" badge after Check | The default rules include an AI rule (`acronyms-expanded`); its step fails with "no AI provider configured". As since aca92e8. Remove the rule or set a provider. |
| The pre-commit hook lets a commit through, "nothing checked", when it cannot reach the server | The hook never blocks a commit (M30); the server checks the push anyway. |
| A rules file restored with its old size and time (`cp -p`, `rsync -t`) more than 2 s after an earlier change is not seen as a change | The engine's reload, the script result cache and the check runs' "+changed" all go by size and time (and content within 2 s of a write). A plain copy or a git checkout sets a new time. |
| A run that started right after a rules save may be marked "+changed" once when nothing changed | Only when a file was written within 2 s of its start and changed again during it; Check again clears it. |
| A retest the redactor cannot see is counted under "no access" when its copy cannot be read, also if it holds none | Counted, never named. |
| The purge page lists a retest whose repository cannot be read as "(could not be read)" | It may hold the original; its own page tells. |
| In the assets editor, Add row after someone else saved asks before Cancel although nothing was typed | The rows on screen are not what is saved any more; asking is the safer side. |
| In the inbox and Go to, a long engagement ID is cut at 96 px, the whole one on hover | Two date-prefixed IDs (2026-11-acme-webapp, 2026-11-acme-api) can look alike there. |
| MCP `set_field assets` takes the port as a string | As documented; an agent sending a number is refused with the format and corrects it. |
| The History page still scrolls when a selected change's diff is taller than the window | The list column fits the window; the diff panel has no height limit. |
| The ./internal/web tests hold about 6 GB of memory while they run | Run them alone on a small machine (`go test -p 1 -parallel 2`); the server itself is not affected. |
