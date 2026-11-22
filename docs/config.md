# Config

`.yars/config.yaml` in the main repository; admins change it by push or under **Admin › Structure**. Unknown values are rejected when the server loads it.

| Key | Type | Default | Rule |
|---|---|---|---|
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

## Check runs

A check run (the Check button, `start_check`, the run after Fix with AI) runs every rule, scripts and AI included. The server runs at most `checks.max_running` of them at once. Further runs wait in a queue and start in the order they were asked for, as runs end. A queued run is the finding's run: Check again, or `start_check`, answers it. The Checks strip and the Check button show it as Queued; `start_check` and `get_check_results` give the state `queued`. A queued run checks the finding as it was when it was asked for, as a running one does. Raising the limit starts queued runs at once. When the server stops, the queued runs are dropped and fail as interrupted.
