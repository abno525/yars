# Config

`.yars/config.yaml` in the main repository; admins change it by push or under **Admin › Structure**. Unknown values are rejected when the server loads it.

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
| `ai.api_key_env` | string | — | name of the environment variable holding the key |
| `base_url` | string | — | the server's address; links in webhooks and email |
| `smtp.host` | string | — | set with `smtp.from` to send notification email |
| `smtp.port` | number | 25 | — |
| `smtp.from` | string | — | sender address |
| `smtp.username` | string | — | empty = no login |
| `smtp.password_env` | string | — | name of the environment variable holding the password |
| `checks.max_running` | number | 4 | at least 1; check runs the server runs at once |

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
```

Without `smtp.host` and `smtp.from` the Email column of the notification settings is hidden.

## Workflow

`yars init --simple` writes `workflow: simple` at the top of the file: findings go draft → complete → reported, with no roles, reviewers or sign-off. The standard workflow (`yars init`) writes no key. Init also records the workflow in the database, and it stays as init set it: `yars serve` does not start when the file says another one ("config.yaml says workflow standard but this data folder was set up with simple (yars init); put workflow: simple back"), a push that changes the key is refused ([git.md](git.md)), and a running server keeps its workflow whatever a saved file says. A data folder whose database is missing (`yars.db` deleted, or the folder copied without it) gets a new, empty one, which takes the workflow the file names.

## Check runs

A check run (the Check button, `start_check`, the run after Fix with AI) runs every rule, scripts and AI included. The server runs at most `checks.max_running` of them at once. Further runs wait in a queue and start in the order they were asked for, as runs end. A queued run is the finding's run: Check again, or `start_check`, answers it. The Checks strip and the Check button show it as Queued; `start_check` and `get_check_results` give the state `queued`. A queued run checks the finding as it was when it was asked for, as a running one does. If the rules change while it waits, it runs them as they are when it starts and reads as stale. If its engagement is archived while it waits, it fails without running. Raising the limit starts queued runs at once. When the server begins to stop, the queued runs are dropped and fail as interrupted, and no further run starts.
