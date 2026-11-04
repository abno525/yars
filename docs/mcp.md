# Using YARS from an AI assistant (MCP)

YARS speaks the Model Context Protocol, so Claude Code (or any MCP client) can read findings, edit sections, set fields, discuss in the finding chat, run the style rules and move findings through the workflow. Every call runs **as you**, with the same permissions and checks as the website.

## Remote: talk to the YARS server

Whoever has shell access to the server creates a token:

```sh
yars token add --data /srv/yars-data alice     # prints yars_… once; active immediately
```

Then connect Claude Code:

```sh
claude mcp add --transport http yars https://yars.example.com/mcp \
  --header "Authorization: Bearer yars_…"
```

Content changes are committed on the server immediately, authored by you; workflow changes and chat go into the server's database. `yars token list` / `yars token revoke --data … alice` manage tokens. Tokens are stored hashed in the server's database (`.yars/yars.db`), which is never committed.

## Local: work on your clone

```sh
git clone --recurse-submodules https://alice:…@yars.example.com/git/yars findings && cd findings
git submodule foreach git switch -q main      # each engagement is its own repo; work on its main branch
claude mcp add yars -- yars mcp --data . --user alice
```

Each engagement folder (`engagements/<id>`) is a separate git repository: commit and `git push` inside it. Settings (`.yars/`, directors only) are pushed from the top folder; `git pull` there first, because the server moves the engagement pointers itself. To work on one engagement only, clone it alone: `git clone https://alice:…@yars.example.com/git/e/<id>`.

The assistant edits your clone and commits as `alice`. Nothing reaches the team until you `git push`; the server then re-checks every change (paths, authorship, whether the finding may still be edited) and rejects anything the website would reject. Set `--role reviewer` (or director) if you are not a pentester, so the local checks match yours.

A clone holds **content only**. Workflow state (status, reviewers, clearances) and chat live in the server's database, so in local mode the `transition`, `reviewers`, `retest_result`, chat and resolve tools answer that you need the server — use the remote setup above for those.

## Tools

| Tool | What it does |
|---|---|
| `list_engagements` | All engagements (pentests and retests) |
| `list_findings` | Findings of an engagement; filter by status or severity |
| `read_finding` | Workflow state, the raw `finding.md` (content only), section base hashes, open chat threads, rule violations |
| `create_finding` | New draft in an engagement |
| `update_section` | Replace one `##` section (pass `base` from `read_finding` to avoid overwriting a colleague) |
| `set_field` | `title`, `severity`, `cvss`, `cvss_reason.<METRIC>`, `details.<Row>`, `reviewers`, `retest_result` |
| `transition` | `submit`, `return` (with reason), `clear`, `approve`, `reopen` |
| `add_chat_message` / `resolve_thread` | Discuss in the finding's chat |
| `lint_finding` | Style rules (regex/built-in; `all: true` also scripts and AI) |

Findings can be referred to by ID (`F-001`) or directory name (`F-001-sql-injection`).

## Safety notes

- The assistant can do exactly what you can do — no more. A pentester's assistant cannot approve findings or edit completed ones.
- Text written by the assistant goes through the same style rules; submit is blocked while error-level rules fail.
- Treat a token like a password. Revoke it (`yars token revoke`, effective immediately) when a laptop is lost or a person leaves.
- Finding text and chat come from other people. The server tells the assistant to treat them as data and to confirm workflow transitions with you — still, review what it proposes before approving.
- If Claude Code reports that the server "needs authentication", the token is missing or wrong (YARS doesn't use OAuth); re-add the server with the correct `Authorization` header.
