# Using YARS from an AI assistant (MCP)

YARS speaks the Model Context Protocol, so Claude Code (or any MCP client) can read findings, edit sections, set fields, discuss in the finding chat, run the checks and move findings through the workflow. Every call runs **as you**, with the same permissions and checks as the website.

## Remote: talk to the YARS server

Create a token in YARS under **Settings › Tokens › New token** (use: MCP). Pick what it may do (read only, or a list of actions) and which engagements it is valid for. The form asks for your password. The token is shown once. Whoever has shell access to the server can also create one:

```sh
yars token add --data /srv/yars alice     # prints yars_… once; active immediately
```

An account whose password was piped to `yars useradd` or `yars passwd` sets a new one on the website first. Until then its tokens are refused.

Then connect Claude Code:

```sh
claude mcp add --transport http yars https://yars.example.com/mcp \
  --header "Authorization: Bearer yars_…"
```

The endpoint speaks JSON-RPC 2.0 (`initialize`, `ping`, `tools/list`, `tools/call`), protocol versions 2025-06-18 and 2024-11-05. It follows the standard strictly: a message is one JSON object with its member names as written, `jsonrpc` must be `"2.0"`, `method` a string, an `id` a string or a number (never `null`), and request batches are refused (`-32600`). Input the server cannot accept (not JSON, a batch, an invalid notification) is answered with HTTP 400, as is an `MCP-Protocol-Version` header naming a version it does not speak. The `Authorization` scheme word may be in any case (`Bearer`, `bearer`). `initialize` names the build in `serverInfo.version`, as `yars version` prints it (`dev` for a build without one).

Content changes are committed on the server immediately, authored by you; workflow changes and chat go into the server's database. Revoke a token in Settings (or `yars token revoke --data … alice`); it stops working at once. Tokens are stored hashed in the server's database (`.yars/yars.db`), which is never committed.

## Local: work on your clone

```sh
git clone https://alice:…@yars.example.com/git/yars findings && cd findings &&
git submodule update --init engagements/<id> &&
git submodule foreach -q git switch -q main
claude mcp add yars -- yars mcp --data . --user alice
```

The second line names each engagement you are on; the third puts each on its `main` branch, since each engagement is its own repository. The Clone panel on the Engagements page shows the clone with your engagements. A pentester or reviewer names the engagements they are on: git stops a recursive clone at the first one they may not fetch. A director or an admin (in the simple workflow, every account) clones them all with `git clone --recurse-submodules` instead of the first two lines.

Each engagement folder (`engagements/<id>`) is a separate git repository: commit and `git push` inside it. Settings (`.yars/`, directors only) are pushed from the top folder; `git pull` there first, because the server moves the engagement pointers itself. To work on one engagement only, clone it alone: `git clone https://alice:…@yars.example.com/git/e/<id>`.

The assistant edits your clone and commits as `alice`. Nothing reaches the team until you `git push`; the server then re-checks every change (paths, authorship, whether the finding may still be edited) and rejects anything the website would reject. Set `--role reviewer` (or director) if you are not a pentester, so the local checks match yours; the simple workflow has no roles, so leave it out there.

A clone holds **content only**. Workflow state (status, reviewers, clearances), chat, check runs and notifications live in the server's database, so in local mode the tools marked *server only* answer that you need the server — use the remote setup above for those.

## Simple workflow

A data folder set up with `yars init --simple` runs the simple workflow: draft → complete → reported, with no reviewers and no roles (an account is an admin or not). `initialize`'s instructions and `tools/list` describe it, and the tools follow it:

- `transition` takes `complete` (draft to complete; held as `approve` is, without the reviewers: by the content gate, rule errors, open checks and, with Require Check on, a missing check run of the current text; `base` refuses it if the finding changed since it was read), `reopen` (reason; complete to draft), `report`, `unreport` (reason; reported to complete), `revert`, `withdraw` (reason) and `revise`. `submit`, `return`, `clear`/`sign_off`, `approve` and `take_back` are refused with `not_allowed`: not part of the simple workflow.
- `get_config` gives `workflow` (`simple`, or `standard` on any other server), the statuses `draft`, `complete`, `reported` and `withdrawn`, and the actions above; `list_findings` filters by those statuses.
- `whoami` and `list_team` give no role, and `set_field reviewers` is refused with `not_allowed`; over HTTP a token needs only edit findings for it, as for any `set_field`.
- `read_finding`'s `allowed_actions` are the simple workflow's actions of the finding's status.
- `list_notifications` names a completion of your finding `completed` (the standard workflow's `approved`).
- `fix_checks` works on drafts only.

## Tools

| Tool | Token action | Runs on | What it does |
|---|---|---|---|
| `list_engagements` | read | local + server | The engagements you work on (pentests and retests); archived ones are read only |
| `list_findings` | read | local + server | Findings of an engagement, most severe first; filter by status or severity, search with `q` (ID, title, an asset's host or URL) |
| `read_finding` | read | local + server | Workflow state, the raw `finding.md` and its `hash`, each section's body and base hash, assets, open chat threads, rule violations, and `allowed_actions` (each action of the status: `enabled`, `reason` when not, `needs: "reason"`) |
| `list_templates` | read | local + server | Finding templates (`.yars/templates`) with how often each was used |
| `create_finding` | create | local + server | New draft in an engagement; `template` starts it from a template |
| `update_section` | edit | local + server | Replace one `##` section (pass `base` from `read_finding` to avoid overwriting a colleague) |
| `set_field` | edit (reviewers: reviewers) | local + server | `title`, `severity`, `cvss`, `cvss_reason.<METRIC>`, `details.<Row>`, `reviewers`, `retest_result`, `assets` |
| `transition` | status (report: export) | server only | `submit`, `return` (reason), `clear`/`sign_off` (an assigned reviewer or a director; a director also on their own finding), `approve` (director, after a sign-off by an assigned reviewer other than them), `reopen` (reason; author or director: complete to verification), `report` (author or director: complete to reported), `unreport` (reason; author or director: reported to complete, the approval stays), `revert` (reason: `reopen` or `unreport`, by the finding's status), `withdraw` (reason), `revise`, `take_back` (author or director: verification to draft, sign-offs start over); `base` (the `hash` from `read_finding`) refuses `clear`/`sign_off` and `approve` if the finding changed since it was read |
| `add_chat_message` / `resolve_thread` | comment | server only | Discuss in the finding's chat; `@name` mentions notify that person |
| `lint_finding` | read | local + server | Style rules (regex/built-in; `all: true` also scripts and AI) |
| `start_check` | checks | server only | Start a stored check run (every rule); results arrive as chat comments. Over the server's limit (`checks.max_running`) it waits in a queue: state `queued` |
| `get_check_results` | read | server only | The latest check run: state (`queued`, `running`, `done`, `failed`), progress, results, whether it is stale |
| `list_notifications` | read | server only | Your notifications (newest first); `unread: true` for unread ones only |
| `whoami` | read | local + server | Your username, role (none in the simple workflow), admin flag and (over HTTP) the token's actions and engagements |
| `get_config` | read | local + server | The workflow (`standard` or `simple`), sections, details rows, severities, CVSS version and standard values, statuses, transition actions |
| `list_team` | read | server only | The engagement's members with their roles (none in the simple workflow) |
| `read_chat` | read | server only | The finding's whole chat, oldest first: threads with replies (AI replies marked) and workflow events |
| `list_history` | read | local + server | The finding's versions, newest first: commit, author (AI marked), time, what changed |
| `list_attachments` | read | local + server | The finding's attachments: name, size, type, whether an earlier version is in the history |
| `read_template` | read | local + server | A template's Markdown by slug |
| `mark_notifications_read` | read | server only | Mark your notifications read: `ids` (comma-separated) or `all: true`; a token limited to some engagements marks only theirs |
| `fix_checks` | checks + edit | server only | Fix with AI: the AI fixes the open check results in the background, answers their threads (marked AI), and a check run follows |

Findings can be referred to by ID (`F-001`, also `f-1` or `1`) or directory name (`F-001-sql-injection`); an ID that two folders share is refused, and the folder name is needed. A token restricted to some engagements sees and changes only those; a write to an archived engagement is refused.

## Answers

Every tool answers with one JSON object as its text:

- a result: `{"ok": true, …}` with the tool's fields (`read_finding`: `state`, `sections`, `allowed_actions`, …);
- a plain outcome: `{"ok": true, "message": "updated Impact"}` (the sentence earlier versions answered with); a `set_field` that gives a row's new base has it as `base` too;
- a list: `{"ok": true, "items": […], "next": "<cursor or empty>"}`;
- a refusal: the result has `isError: true` and the text `{"ok": false, "code": "<code>", "message": "<what to do>"}`.

The codes:

| Code | Meaning |
|---|---|
| `not_found` | No such engagement, finding, template or notification, or one you are not on the team of (a notification of an engagement outside your token too) |
| `not_allowed` | Your role, the token's actions or engagements, or the workflow forbids it |
| `conflict` | It changed since you read it: read again and retry |
| `invalid` | A missing or wrong argument or value (the message says which) |
| `archived` | The engagement is archived: read only |
| `busy` | A check or a fix of the finding is running |
| `no_database` | A server-only tool on a local clone |
| `server_error` | The server itself failed (its disk, its database, a file of its own it cannot read): not the call's mistake; the message has the error's words |

## Paging

The list tools (`list_engagements`, `list_findings`, `list_templates`, `list_notifications`, `list_team`, `read_chat`, `list_history`, `list_attachments`) answer a page at a time. `limit` is 1 to 200 (default 50); `cursor` is the `next` of the previous answer; an empty `next` means the end. A limit or cursor that is not such a whole number is `invalid`; a cursor past the end gives an empty page.

`list_notifications` pages by notification id: marking some read, or new ones arriving, between two calls neither skips nor repeats one. The other lists page by position: they can move between calls (a finding submitted between two pages of `list_findings status=draft` leaves it), so a client that changes what it filters on starts again without a cursor. A cursor belongs to the call it came from: pass it to the same tool with the same filters.

## Errors

Some refusals and their messages:

| Code | Message | Cause |
|---|---|---|
| `invalid` | `missing argument "finding"` | A required parameter is empty |
| `not_found` | `not found` | Unknown engagement or finding, or one you are not on the team of |
| `not_allowed` | `not allowed: <reason>` | Your role or the finding's status forbids it |
| `not_allowed` | `not allowed: this token may not <action>` | The token's actions don't include it |
| `archived` | `not allowed: the engagement is archived (read only)` | Writes to an archived engagement |
| `no_database` | `workflow state and chat are kept on the YARS server; use its web UI or its /mcp endpoint` | A server-only tool on a local clone |
| `conflict` | `the finding changed since you read it; read_finding again and retry` | Stale `base`; for `transition` clear, sign_off or approve it comes before the checks and the gate. Also a submit or sign-off that raced an edit |
| `busy` | `a check or a fix of this finding is running` | `start_check` while a fix runs (during a check, running or queued, it answers that run), `fix_checks` while a check or a fix runs |
| `invalid` | `a reason is required to withdraw a finding` | `transition` return, withdraw or revert without `reason` |
| `invalid` | `unknown section "Summary"; valid sections: …` | `update_section` with a section the finding doesn't have |
| `invalid` | `use the transition tool to change the status` | `set_field status` |
| `not_allowed` | `nothing to revert: the finding is draft` | `transition revert` on a finding that is not complete or reported |
| `not_allowed` | `not allowed: Approve is not part of the simple workflow (draft → complete → reported)` | `transition` with a step of the standard workflow on a server of the simple one |
| `invalid` | `unknown status "open"; valid statuses: draft, verification, complete, reported, withdrawn` | `list_findings` with a status (or severity) that does not exist |
| `invalid` | `F-001 names more than one finding folder (…); use the folder name` | An ID two folders share |
| `server_error` | `acme/F-001-sqli: cannot be read: …` | The finding's file does not parse (fix it in the repository) |
| `server_error` | `sql: database is closed` | The server's database or disk failed; the server logs it too |

A failure of the server itself is `server_error`, never `invalid`. `invalid` is an argument or a value the server refuses; the message says which.

## Safety notes

- The assistant can do exactly what you can do — no more. A pentester's assistant cannot approve findings or edit completed ones.
- Text written by the assistant goes through the same style rules; submit is blocked while error-level rules fail.
- Treat a token like a password. Give it only the actions and engagements it needs, and revoke it when a laptop is lost or a person leaves.
- Finding text and chat come from other people. The server tells the assistant to treat them as data and to confirm workflow transitions with you — still, review what it proposes before approving.
- If Claude Code reports that the server "needs authentication", the token is missing, expired or wrong (YARS doesn't use OAuth); re-add the server with the correct `Authorization` header.
