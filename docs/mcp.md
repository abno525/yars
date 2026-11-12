# Using YARS from an AI assistant (MCP)

YARS speaks the Model Context Protocol, so Claude Code (or any MCP client) can read findings, edit sections, set fields, discuss in the finding chat, run the checks and move findings through the workflow. Every call runs **as you**, with the same permissions and checks as the website.

## Remote: talk to the YARS server

Create a token in YARS under **Settings › Tokens › New token** (use: MCP). Pick what it may do (read only, or a list of actions) and which engagements it is valid for; the token is shown once. Whoever has shell access to the server can also create one:

```sh
yars token add --data /srv/yars-data alice     # prints yars_… once; active immediately
```

Then connect Claude Code:

```sh
claude mcp add --transport http yars https://yars.example.com/mcp \
  --header "Authorization: Bearer yars_…"
```

The endpoint speaks JSON-RPC 2.0 (`initialize`, `ping`, `tools/list`, `tools/call`), protocol versions 2025-06-18, 2025-03-26 and 2024-11-05.

Content changes are committed on the server immediately, authored by you; workflow changes and chat go into the server's database. Revoke a token in Settings (or `yars token revoke --data … alice`); it stops working at once. Tokens are stored hashed in the server's database (`.yars/yars.db`), which is never committed.

## Local: work on your clone

```sh
git clone --recurse-submodules https://alice:…@yars.example.com/git/yars findings && cd findings
git submodule foreach git switch -q main      # each engagement is its own repo; work on its main branch
claude mcp add yars -- yars mcp --data . --user alice
```

Each engagement folder (`engagements/<id>`) is a separate git repository: commit and `git push` inside it. Settings (`.yars/`, directors only) are pushed from the top folder; `git pull` there first, because the server moves the engagement pointers itself. To work on one engagement only, clone it alone: `git clone https://alice:…@yars.example.com/git/e/<id>`.

The assistant edits your clone and commits as `alice`. Nothing reaches the team until you `git push`; the server then re-checks every change (paths, authorship, whether the finding may still be edited) and rejects anything the website would reject. Set `--role reviewer` (or director) if you are not a pentester, so the local checks match yours.

A clone holds **content only**. Workflow state (status, reviewers, clearances), chat, check runs and notifications live in the server's database, so in local mode the tools marked *server only* answer that you need the server — use the remote setup above for those.

## Tools

| Tool | Token action | Runs on | What it does |
|---|---|---|---|
| `list_engagements` | read | local + server | The engagements you work on (pentests and retests); archived ones are read only |
| `list_findings` | read | local + server | Findings of an engagement; filter by status or severity |
| `read_finding` | read | local + server | Workflow state, the raw `finding.md`, section base hashes, assets, open chat threads, rule violations |
| `list_templates` | read | local + server | Finding templates (`.yars/templates`) with how often each was used |
| `create_finding` | create | local + server | New draft in an engagement; `template` starts it from a template |
| `update_section` | edit | local + server | Replace one `##` section (pass `base` from `read_finding` to avoid overwriting a colleague) |
| `set_field` | edit (reviewers: reviewers) | local + server | `title`, `severity`, `cvss`, `cvss_reason.<METRIC>`, `details.<Row>`, `reviewers`, `retest_result`, `assets` |
| `transition` | status (report: export) | server only | `submit`, `return` (reason), `clear`/`sign_off`, `approve`, `reopen` (reason; author or director: complete to verification), `report` (director), `unreport` (reason; author or director: reported to complete, the approval stays), `revert` (reason: `reopen` or `unreport`, by the finding's status), `withdraw` (reason), `revise`, `take_back` (author or director: verification to draft, sign-offs start over) |
| `add_chat_message` / `resolve_thread` | comment | server only | Discuss in the finding's chat; `@name` mentions notify that person |
| `lint_finding` | read | local + server | Style rules (regex/built-in; `all: true` also scripts and AI) |
| `start_check` | checks | server only | Start a stored check run (every rule); results arrive as chat comments |
| `get_check_results` | read | server only | The latest check run: state, progress, results, whether it is stale |
| `list_notifications` | read | server only | Your notifications (newest first); `unread: true` for unread ones only |

Findings can be referred to by ID (`F-001`) or directory name (`F-001-sql-injection`). A token restricted to some engagements sees and changes only those; a write to an archived engagement is refused.

## Errors

Tool errors come back as a result with `isError: true` and one text item:

| Text | Cause |
|---|---|
| `missing argument "finding"` | A required parameter is empty |
| `not found` | Unknown engagement or finding, or one you are not on the team of |
| `not allowed: <reason>` | Your role or the finding's status forbids it |
| `not allowed: this token may not <action>` | The token's actions don't include it |
| `not allowed: the engagement is archived (read only)` | Writes to an archived engagement |
| `workflow state and chat are kept on the YARS server; use its web UI or its /mcp endpoint` | A server-only tool on a local clone |
| `the finding changed meanwhile (someone else edited it); read_finding again and retry` | Stale `base` |
| `unknown section "Summary"; valid sections: …` | `update_section` with a section the finding doesn't have |
| `use the transition tool to change the status` | `set_field status` |
| `nothing to revert: the finding is draft` | `transition revert` on a finding that is not complete or reported |

## Safety notes

- The assistant can do exactly what you can do — no more. A pentester's assistant cannot approve findings or edit completed ones.
- Text written by the assistant goes through the same style rules; submit is blocked while error-level rules fail.
- Treat a token like a password. Give it only the actions and engagements it needs, and revoke it when a laptop is lost or a person leaves.
- Finding text and chat come from other people. The server tells the assistant to treat them as data and to confirm workflow transitions with you — still, review what it proposes before approving.
- If Claude Code reports that the server "needs authentication", the token is missing, expired or wrong (YARS doesn't use OAuth); re-add the server with the correct `Authorization` header.
