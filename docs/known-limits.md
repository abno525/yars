# Known limits

What YARS does not do, or does in a way that can surprise. Each row states today's behaviour.

## Checks and rules

| Limit | Note |
|---|---|
| An AI rule without an AI provider shows an orange "AI checks failed" badge on every finding after Check | Its step fails with the warning "AI rules skipped: no AI provider configured". Sign off and Approve are not held by it. `yars init` writes no rules, so a new data folder has none of this until someone adds an AI rule. Set a provider or turn the rule off. |
| An AI rule whose call failed holds nothing: Submit, Sign off and Approve go through, at level `error` too | The finding shows "AI checks failed" with Retry, and the service log has a `warn` line for each step taken so. Keep what must hold in pattern, built-in or script rules ([rules.md](rules.md)). |
| When the last rule is turned off, what it found in the finding's latest Check still holds Sign off and Approve, named by its message only | With no rule on, Require Check no longer asks for a run, and the latest run's results stay open, as with Require Check off. A Check clears them; so does dismissing them. |
| Stored rule results have no engagement, so a purge does not clear them | They age out with the check-run retention. |
| A git push and `yars lint --all` run every script each time, and `yars lint --all` sends the text to the AI provider each time | Stored results serve Check, MCP, `yars lint --staged --all` and the Test bench only ([rules.md](rules.md)). A push runs no AI rule; the plain `yars lint` runs neither scripts nor AI rules. |
| Two OpenAI-compatible endpoints serving the same model name share stored AI results | The base URL is not part of the key. |
| A Check has no time limit of its own | Each script has 10 s and each AI rule 90 s, so a Check with ten slow AI rules can take 15 minutes. It holds one of the `checks.max_running` places for that time. Cancel on the Checks strip stops it ([rules.md](rules.md)). An AI rule with more parts than fit in 90 s fails; give it a narrower `target`. |
| The AI spend limit can be passed by what is under way | A call that runs when the limit is reached ends and is counted, and so does one of each Check running at that time. |
| The AI spend limit is never reached with a provider that reports no tokens | The cost is worked out from the tokens the provider reports. Some OpenAI-compatible servers report none. |
| `yars lint --all` on the server's data folder is not held by the AI spend limit, and its calls are not counted | It calls the provider with the stored key on its own. |
| A cancelled Check holds its `checks.max_running` place until its running rule has stopped | A script is killed at once. A provider that does not close the connection is waited for until the AI time limit. |
| No MCP tool cancels a check or a fix | Cancel is on the Checks strip. `lint_finding all=true` answers the state `cancelled` when its run was cancelled. |
| A Fix with AI that is cancelled keeps what it committed | Each fix is its own commit. The item it was on and the items after it get no reply, and no Check follows: press Check. |
| `checks.max_running` is set in `.yars/config.yaml` only | No Admin page shows or edits it. |
| A rules file restored with its old size and time (`cp -p`, `rsync -t`) more than 2 s after an earlier change is not seen as a change | The engine's reload, the stored script results and a check run's "+changed" go by size and time (and by content within 2 s of a write). A plain copy or a git checkout sets a new time. |
| A run that started right after a rules save may be marked "+changed" once when nothing changed | Only when a file was written within 2 s of its start and changed again during it. Check again clears it. |
| A built-in check's configured message near the 4,000-character cut loses its detail | None of the built-in messages is that long; the whole message shows on hover. |
| The pre-commit hook lets a commit through, "nothing checked", when it cannot reach the server | The hook never blocks a commit; the server checks the push anyway. `yars lint --staged` by hand, without `--warn-only`, exits 3 then. |

## Review

| Limit | Note |
|---|---|
| A director may sign off their own finding, and a second director may then approve on that sign-off alone | The approver is someone other than the author. No third person is required. |
| An Approve can land while an attachment upload is being committed | The approval then stands for a file the director did not see; the upload, in verification, drops sign-offs. |
| The bulk bars (the inbox's and the findings list's) sign off and approve without a viewed version | Their rows show no finding text to have read. |
| A workflow bar opened before a change refuses a sign-off of the content the page now shows | The refusal says why, and a second click works. |

## Git

| Limit | Note |
|---|---|
| A push to the main repository is refused as non-fast-forward right after the server moved engagement pointers | The server manages the pointers, and the refusal says to pull first ([git.md](git.md)). |
| A clone of the main repository shows every engagement's ID, also of engagements the account is not on | The main repository is one repository for everyone and its `.gitmodules` names every engagement. Where an ID would name a client, choose one that does not. |
| A save writes a section heading in its canonical form (`## Name`, spaces after it trimmed) | An unchanged save writes nothing, so only a real change rewrites the heading. |

## MCP

| Limit | Note |
|---|---|
| MCP over HTTP has no OAuth protected-resource metadata | YARS has no authorization server to name; the bearer token is described in [mcp.md](mcp.md). |
| Argument names a tool does not know are ignored | Refusing them would break working clients. |
| `transition`'s `base` covers `finding.md`, not the attachments | The website also sends the attachments it showed. Over MCP an attachment change since `read_finding` is not refused; in verification it drops sign-offs anyway. |
| `set_field assets` takes the port as a string | An agent sending a number is refused with the format and corrects it. |
| No MCP tool writes rules | An agent adds rules through git: clone the main repository, add a file under `.yars/rules/`, push as an admin. |

## Export

| Limit | Note |
|---|---|
| Some pandoc builds cannot write docx under `--sandbox`; the fallback runs without it | The text pandoc gets is already cleaned (no raw HTML, images inlined). A static pandoc release keeps the sandbox ([deploy.md](deploy.md)). |
| The Confluence push's attachment calls were tested against a fake server only | Unconfirmed on a real Confluence: attachment PUT on older Server/DC, the comment in the attachment list, DELETE on Server/DC. An upload failure on a new page leaves it empty. The page is remembered, and the next send fills it. Where nothing is remembered (`yars export` without the server's database), the next send is refused for the title: remove the empty page first. |
| A Confluence push updates only the page it made before | The page is remembered per destination, engagement and finding; a push of several findings (`yars export`) has one page of its own. With no page remembered, or when it was deleted or moved to another space, a new page is made. Confluence refuses that when the space has a page of the same title: rename or remove that page. `yars export` on a clone without the server's database remembers nothing. |
| The report's first chapter is headed "Executive summary" whatever the first report section is called | The first report section (Admin › Structure) is the summary: its text stands above the severity counts. The others open "Scope and overview". |

## Redaction

| Limit | Note |
|---|---|
| A redaction does not reach a retest copy the redactor may not edit (a complete or reported copy for a non-director, a retest they are not on) | Those copies are reported after the redaction and listed on the purge page. A director's redaction reaches them. |
| A redaction finds retest copies by the file's git object id | That assumes the source and the retest use the same object format, as every repository YARS makes does. |
| A retest the redactor cannot see is counted under "no access" when its copy cannot be read, also if it holds none | Counted, never named. |
| The purge page lists a retest whose repository cannot be read as "(could not be read)" | It may hold the original; its own page tells. |

## Website

| Limit | Note |
|---|---|
| In the assets editor, Add row after someone else saved asks before Cancel although nothing was typed | The rows on screen are not what is saved any more; asking is the safer side. |
| In the inbox and Go to, a long engagement ID is cut at 96 px, the whole one on hover | Two date-prefixed IDs (2026-11-acme-webapp, 2026-11-acme-api) can look alike there. |
| "is editing" stays up to 150 s after an editor's tab was closed | Cancel and Save end it at once. A closed tab sends nothing; the server forgets the editor after 150 s without a sign of it. |
| The History page still scrolls when a selected change's diff is taller than the window | The list column fits the window; the diff panel has no height limit. |
| A notice about a chat message opens the finding at the top, not at the thread, when the chat is hidden, the thread is under Show older, or it is a resolved thread you hid | The link names the thread; the page has no element to go to then. Notices stored before the upgrade lead to the top too. |
| Opening a finding marks your notices of that finding read, also those you did not look at | Every notice of the finding counts as seen with its page. A part of the page that refreshes itself marks nothing. |

## Simple workflow

| Limit | Note |
|---|---|
| The workflow is chosen once, at `yars init`; a data folder cannot switch between simple and standard | A push that changes `workflow:` in `config.yaml` is refused; `serve` refuses to start when a committed `config.yaml` disagrees with the database; an uncommitted hand edit is undone at start. |
| Every account has a director's rights: merge, purge, archive, retests, export setup, editing complete findings | On purpose: the simple workflow has no chain of command. Admin stays separate (Admin pages, `config.yaml` and rule pushes). |
| A webhook consumer keyed on `approve` does not see a simple-workflow finding completed | `finding.status_changed` carries the action `complete` there ([webhooks.md](webhooks.md)). |
