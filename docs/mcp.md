# Using YARS from an AI assistant (MCP)

YARS speaks the Model Context Protocol, so Claude Code (or any MCP client) can read findings, edit sections, set fields, discuss in the finding chat, run the style rules and move findings through the workflow. Every call runs **as you**, with the same permissions and checks as the website.

## Remote: talk to the YARS server

An admin (or you, with shell access to the server) creates a token:

```sh
yars token add --data /srv/yars-data alice     # prints yars_… once; active immediately
```

Then connect Claude Code:

```sh
claude mcp add --transport http yars https://yars.example.com/mcp \
  --header "Authorization: Bearer yars_…"
```

Changes are committed on the server immediately, authored by you. `yars token list` / `yars token revoke --data … alice` manage tokens. Tokens are stored hashed in `.yars/tokens.yaml`, which is never committed.

## Local: work on your clone

```sh
git clone https://alice:…@yars.example.com/git/yars findings && cd findings
claude mcp add yars -- yars mcp --data . --user alice
```

The assistant edits your clone and commits as `alice`. Nothing reaches the team until you `git push`; the server then re-checks every change (workflow, permissions, style rules) and rejects anything the website would reject. Set `--role reviewer` (or director) if you are not a pentester, so the local checks match yours.

## Tools

| Tool | What it does |
|---|---|
| `list_engagements` | All engagements (pentests and retests) |
| `list_findings` | Findings of an engagement; filter by status or severity |
| `read_finding` | The raw `finding.md`, section base hashes, open chat threads, rule violations |
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
