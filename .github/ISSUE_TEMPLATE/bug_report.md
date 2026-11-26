---
name: Bug report
about: Something does not work as the docs say
labels: bug
---

<!--
Use made-up data. No real finding, client name, host, engagement ID or token.
A security problem does not go here: see SECURITY.md.
-->

**What happened**

**What you expected**

**Steps**

1.
2.

**Versions**

- `yars version`:
- `git --version`:
- Workflow: standard / simple
- Browser, if the website is involved:

**Service log**, if there is an error.

An error page or toast shows a request ID, such as `Request 4f2a9c1b`. Paste the lines with that ID:

```
journalctl -u yars | grep req=<ID>
```

Without an ID, paste the warnings and errors around the time (`journalctl -u yars`, or `yars status`).
Log lines hold usernames and engagement IDs: replace them before you paste.
