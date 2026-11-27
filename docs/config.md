# Config

`.yars/config.yaml` in the main repository; admins change it under **Admin › Structure**, or by push as a director with the admin flag. A value that is not valid is refused when the server loads the file. So is a key YARS does not know, such as `base-url` for `base_url`: the message names the key and its line.

| Key | Type | Default | Rule |
|---|---|---|---|
| `workflow` | string | — (standard) | `simple` or `standard`; set by `yars init` (`--simple`), cannot change |
| `severities` | list | critical, high, medium, low, info | must include all five |
| `sections` | list | Description, Impact, Steps to Reproduce, Remediation, References | — |
| `details_rows` | list | Location, Cause, Result, Attack condition, Business impact | — |
| `report_sections` | list | Executive summary, Scope, Methodology | stored as `report/<slug>.md` per engagement |
| `cvss.version` | string | 3.1 | only 3.1 |
| `cvss.standard` | map | AV:N AC:L PR:N UI:N S:U C:N I:N A:N | `-` drops a metric |
| `ai.provider` | string | — | `openai` or `anthropic` |
| `ai.base_url` | string | — | https; plain http only for localhost |
| `ai.model` | string | — | — |
| `ai.api_key_env` | string | — | name of the environment variable holding the key; must start with `YARS_` |
| `base_url` | string | — | the server's address; links in webhooks and email, and the clone and MCP addresses on the pages; no email is sent without it |
| `smtp.host` | string | — | a host name or an address alone, no scheme and no port (IPv6 in `[ ]`); set with `smtp.from` to send notification email |
| `smtp.port` | number | 25 | 1 to 65535 |
| `smtp.from` | string | — | sender address alone, such as `yars@example.com`, no name in front |
| `smtp.username` | string | — | empty = no login |
| `smtp.password_env` | string | — | name of the environment variable holding the password; must start with `YARS_` |
| `checks.max_running` | number | 4 | at least 1; check runs the server runs at once |
| `log.level` | string | info | `debug`, `info`, `warn` or `error`; read at the start |
| `log.format` | string | text | `text` or `json`; read at the start |

## Example

```yaml
severities: [critical, high, medium, low, info]
sections:
  - Description
  - Impact
  - Steps to Reproduce
  - Remediation
  - References
cvss:
  version: "3.1"
  standard: { AC: L, A: "-" }
ai:
  provider: anthropic
  model: claude-opus-5-5
  api_key_env: YARS_AI_KEY
base_url: https://yars.example.com
smtp:
  host: mail.example.com
  port: 587
  from: yars@example.com
  username: yars
  password_env: YARS_SMTP_PASSWORD
checks:
  max_running: 4
log:
  level: info
  format: text
```

Notification email needs `smtp.host`, `smtp.from` and `base_url`. Without one of them no mail is sent and the Email column of the notification settings is hidden. A mail's link starts with `base_url`. `yars serve` logs at the start when SMTP is set and `base_url` is not.

## A file that is refused

A file with an unknown key or a value that is not valid is refused in three places: on Admin › Structure, on a push, and at the start. `yars serve` then does not start and names the key. A server that does not start takes no push. To fix it:

1. Correct the key or the value in `.yars/config.yaml` in the data folder.
2. Commit it there as the service account: `git -C /srv/yars commit .yars/config.yaml -m config`. An edit that is not committed is undone at the next start.
3. Start the service.

A file that loaded before an upgrade can be refused after it: an unknown key was ignored before, and `smtp.host`, `smtp.port` and `smtp.from` were not checked.

## Environment variables

`ai.api_key_env` and `smtp.password_env` name a variable of the server's environment. The name must start with `YARS_`, followed by capital letters, digits or underscores. The value is sent to `ai.base_url` or `smtp.host`, so no other variable of the server can be named.

A file that names another variable is refused: on Admin › Structure, on a push, and at the start. `yars serve` then does not start and says which key to change. To fix a server that does not start:

1. Rename the variable where the service gets its environment (`/etc/yars/env`), for example `OPENAI_API_KEY` to `YARS_OPENAI_API_KEY`.
2. Set the new name in `.yars/config.yaml` in the data folder.
3. Commit it there as the service account: `git -C /srv/yars commit .yars/config.yaml -m config`. An edit that is not committed is undone at the next start.
4. Start the service.

## Log

`yars serve` writes its log to stderr, one line for each thing that happened. `log.format: text` writes `time=… level=… msg=… key=value …`. `log.format: json` writes one JSON object a line. `log.level` is the lowest level written. `yars serve --log-level debug` goes over the file's level for one start.

Both keys are read when the server starts. A file saved or pushed later changes neither until the next start. A word that is no level or no format is refused: on Admin › Structure, on a push, and at the start. `yars serve` then does not start and names the key.

Admin › System can set `debug` for 15 minutes without a restart. After that the level is the one of the start again.

The setup code of a first start is written at every level.

How to read the log, its fields and what a line never holds: [deploy.md](deploy.md#logs).

## Workflow

`yars init --simple` writes `workflow: simple` at the top of the file: findings go draft → complete → reported, with no roles, reviewers or sign-off. The standard workflow (`yars init`) writes no key. Init also records the workflow in the database, and it stays as init set it: `yars serve` does not start when the file says another one ("config.yaml says workflow standard but this data folder was set up with simple (yars init); put workflow: simple back"), a push that changes the key is refused ([git.md](git.md)), and a running server keeps its workflow whatever a saved file says. A data folder whose database is missing (`yars.db` deleted, or the folder copied without it) gets a new, empty one, which takes the workflow the file names.

## Check runs

A check run (the Check button, `start_check`, the run after Fix with AI) runs every rule, scripts and AI included. The server runs at most `checks.max_running` of them at once. Further runs wait in a queue and start in the order they were asked for, as runs end. A queued run is the finding's run: Check again, or `start_check`, answers it. The Checks strip and the Check button show it as Queued; `start_check` and `get_check_results` give the state `queued`. A queued run checks the finding as it was when it was asked for, as a running one does. If the rules change while it waits, it runs them as they are when it starts and reads as stale. If its engagement is archived while it waits, it fails without running. Raising the limit starts queued runs at once. When the server begins to stop, the queued runs are dropped and fail as interrupted, and no further run starts.
