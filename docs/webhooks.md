# Webhooks

Admins add webhooks at `/admin/webhooks` (the **Webhooks** button on this page): a URL and the events it takes. YARS POSTs each event as JSON, one request per event.

## Request

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `X-YARS-Event` | the event, e.g. `finding.status_changed` |
| `X-YARS-Delivery` | the delivery number (a redelivery gets a new one) |
| `X-YARS-Signature` | `sha256=` + hex HMAC-SHA256 of the body with the webhook's secret |

The secret (`whsec_…`) is shown once, when the webhook is added. Check the signature before trusting a request:

```python
import hmac, hashlib

def valid(secret: str, body: bytes, header: str) -> bool:
    want = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header)
```

## Example payload

```json
{
  "event": "finding.status_changed",
  "at": "2026-11-05T14:12:09Z",
  "actor": "rev1",
  "engagement": "demo",
  "finding": {
    "id": "F-001",
    "dir": "F-001-sql-injection-in-login",
    "title": "SQL injection in login",
    "severity": "critical",
    "author": "pen1"
  },
  "action": "return",
  "from": "verification",
  "to": "draft",
  "reason": "add a PoC",
  "url": "https://yars.example.com/e/demo/f/001"
}
```

| Event | Extra fields |
|---|---|
| `finding.status_changed` | `action`, `from`, `to`, `reason`; `destination` when an export marked it reported |
| `finding.created` | — |
| `finding.updated` | `changed`: what changed (`Title`, `Severity`, `CVSS`, `Details`, `Assets`, section names, `Attachments`) |
| `chat.posted` | `message`: `{id, text, section, reply}` |
| `export.sent` | `destination`, `ok`, `error`, `export_url`, `findings` (IDs) |
| `check.finished` | `state` (`done` or `failed`), `errors`, `warnings` |

`url` uses `base_url` from the config; without it, it is a path.

## Delivery

- A 2xx answer within 10 s counts as delivered; anything else is retried.
- Retries wait 10 s, 20 s, 40 s, 80 s and 160 s; after 6 tries the delivery is given up.
- Each webhook shows its last delivery; **Redeliver** sends a delivery again.
- A disabled webhook gets nothing; events are not kept for it.
