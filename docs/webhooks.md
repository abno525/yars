# Webhooks

Admins add webhooks at `/admin/webhooks` (the **Webhooks** button on this page): a URL and the events it takes. YARS POSTs each event as JSON, one request per event.

## Request

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `X-YARS-Event` | the event, e.g. `finding.status_changed` |
| `X-YARS-Delivery` | the delivery number (a redelivery gets a new one) |
| `X-YARS-Event-ID` | the event's ID, the payload's `id`: the same on every try, on a redelivery and for every webhook that takes the event |
| `X-YARS-Timestamp` | when this try was sent, in Unix seconds |
| `X-YARS-Signature` | `sha256=` + hex HMAC-SHA256 of the timestamp, a dot and the body (`1762351929.{"id":…`) with the webhook's secret |

The secret (`whsec_…`) is shown once, when the webhook is added. Check the signature before trusting a request. Refuse a timestamp older than a few minutes, and remember the event IDs you have handled: a request caught on the way cannot be sent again later, and a retry or a redelivery is not handled twice.

```python
import hmac, hashlib, time

seen = set()  # event IDs already handled; keep them at least as long as the window

def valid(secret: str, body: bytes, headers) -> bool:
    ts = headers["X-YARS-Timestamp"]
    if not ts.isdigit() or abs(time.time() - int(ts)) > 300:
        return False
    signed = ts.encode() + b"." + body
    want = "sha256=" + hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, headers["X-YARS-Signature"])

def first_time(headers) -> bool:
    event_id = headers["X-YARS-Event-ID"]
    if event_id in seen:
        return False
    seen.add(event_id)
    return True
```

A delivery queued by a version without event IDs has no `X-YARS-Event-ID` header and no `id`.

## New secret and test

Select a webhook in the list. Its Deliveries panel has two buttons.

- **New secret** replaces the secret and shows the new one once. The webhook and its deliveries stay. There is no time in which both secrets work: a delivery still waiting is signed with the new secret at its next try. Change the receiver right after.
- **Send test** queues one delivery of the event `ping`. It is signed and listed as any other, and it is tried once. Its payload is `{"id": …, "event": "ping", "at": …, "url": …}`. A test that fails does not count towards the switch-off. A webhook that is off cannot be tested.

## Example payload

```json
{
  "id": "evt_3f9c2a1b7d4e5f60718293a4b5c6d7e8",
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
| `finding.status_changed` | `action` (`submit`, `return`, `clear`, `approve`, `reopen`, `report`, `unreport`, `withdraw`, `revise`, `take_back`; a server of the simple workflow sends `complete`, `reopen`, `report`, `unreport`, `withdraw` and `revise`, so a finding reaches complete with `complete`, never `approve`), `from`, `to`, `reason` (set for `return`, `withdraw`, `reopen` and `unreport`, the two reverts); `destination` when an export marked it reported |
| `finding.created` | — |
| `finding.updated` | `changed`: what changed (`Title`, `Severity`, `CVSS`, `Details`, `Assets`, section names, `Attachments`) |
| `chat.posted` | `message`: `{id, text, section, reply}` |
| `export.sent` | `destination`, `ok`, `error`, `export_url`, `findings` (IDs) |
| `check.finished` | `state` (`done` or `failed`), `errors`, `warnings` |

`url` uses `base_url` from the config; without it, it is a path.

## Delivery

- A 2xx answer within 10 s counts as delivered; anything else is retried.
- A redirect is followed only on the webhook's own scheme, host and port. A redirect to another host is refused and counts as a failed try: the delivery's error is `redirect to <host> refused`. Give the webhook the final URL.
- Retries wait 10 s, 20 s, 40 s and so on, doubling up to one hour. After 12 tries, about three and a half hours after the first, the delivery is given up.
- A try without an HTTP answer says why in the delivery's Error: `timeout`, `DNS`, `connection refused`, `TLS` or `no answer`.
- Each webhook shows its last delivery; **Redeliver** sends a delivery again.
- A disabled webhook gets nothing; events are not kept for it.
- After 5 deliveries given up in a row YARS switches the webhook off. Every admin gets a notification, and Admin › Activity has a `webhook.disable` row by `yars`. A delivery that arrives starts the count again. So does switching the webhook on again, and saving it with another URL.
