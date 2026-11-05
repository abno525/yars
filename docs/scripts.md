# Scripts

YARS runs two kinds of scripts kept in the main repository: **script rules** check a finding, **script exporters** turn the complete findings of an engagement into a file. Both read JSON on stdin and run with a clean environment.

## Script rules

A rule in `.yars/rules/*.yaml` names a script file in `.yars/rules`:

```yaml
- id: no-internal-hosts
  level: error            # error | warning
  message: Internal host name in client-facing text
  script: no_internal_hosts.py
  enabled: true
```

### stdin: the finding (rules.Doc)

| Field | Type | Value |
|---|---|---|
| `id` | string | `"F-005"` |
| `title` | string | `"SQL injection in report export"` |
| `status` | string | `draft`, `verification`, `complete`, `reported`, `withdrawn` |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `cvss` | string | `"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"` |
| `cvss_reasons` | map[string]string | metric → reason for a non-standard value |
| `details` | map[string]string | details row → value |
| `sections` | []{name, body} | in file order, bodies trimmed of blank lines |
| `author` | string | `"pen1"` |
| `reviewers` | []string | `["rev1"]` |
| `retest_result` | string | `fixed`, `partially_fixed`, `not_fixed` or `""` |
| `attachments` | []string | files of `attachments/` the sections use |

### stdout: the violations

A JSON array; `[]` means the finding passes.

| Field | Type | Value |
|---|---|---|
| `message` | string | empty → the rule's message |
| `quote` | string | the offending text, cut to 80 characters + … |
| `target` | string | `title`, `section:<Name>`, `details:<Row>`, `cvss`, or empty (`finding`) |

### Example

```python
#!/usr/bin/env python3
import json, re, sys

doc = json.load(sys.stdin)
host = re.compile(r"\b[\w.-]+\.(?:internal|corp|lan)\b")
hits = []
for s in doc["sections"]:
    for m in host.finditer(s["body"]):
        hits.append({"quote": m.group(0), "target": "section:" + s["name"]})
for row, value in (doc["details"] or {}).items():
    for m in host.finditer(value):
        hits.append({"quote": m.group(0), "target": "details:" + row})
json.dump(hits, sys.stdout)
```

### Limits

| Limit | Value |
|---|---|
| Timeout | 10 s · kill wait 1 s |
| stdout | 1 MB |
| stderr | 64 KB · first 80 characters shown |
| Hits per rule | 20 |
| Quote | 80 characters |
| Environment | `PATH`, `HOME` |
| Working directory | `.yars/rules` |
| Script path | inside `.yars/rules` · symlinks resolved · executable |
| Runs | Check button · `start_check` and `lint_finding all=true` (MCP) · `yars lint` · git push |

### Failures

A rule that can't run reports a violation with target `rules` at the rule's level:

| Message | Cause |
|---|---|
| `rule failed: script outside rules dir` | Path |
| `rule failed: timed out` | Over 10 s |
| `rule failed: output too large (limit 1 MB)` | stdout |
| `rule failed: <stderr>` | Non-zero exit |
| `rule failed: invalid output (want a JSON array): …` | Not a JSON array |
| `rule invalid (hosts.yaml): …` | The YAML file: unknown keys, duplicate id, not exactly one of `regex_forbid`, `regex_require`, `check`, `script`, `ai` |

## Script exporters

A destination in `.yars/exporters/*.yaml` of type `script` (edit them under **Export › Destinations**):

```yaml
name: CSV summary
type: script
script: csv_summary.py
extension: csv
statuses: [complete, reported]
mark_reported: false
```

### stdin

| Field | Shape |
|---|---|
| `engagement` | `{id, name, client, type, source, start, end, archived}` |
| `engagement_id` | string |
| `findings` | rules.Doc + `html_sections` for each finding with one of `statuses`, by severity, then ID |
| `html_sections` | section name → rendered HTML |

### stdout

The file itself, saved as `<engagement id>.<extension>` (`application/octet-stream`).

### Limits

| Limit | Value |
|---|---|
| Timeout | 120 s · kill wait 2 s |
| stdout | 100 MB |
| stderr | 64 KB · the end shown |
| Environment | `PATH`, `HOME` |
| Working directory | `.yars/exporters` |
| Script path | inside `.yars/exporters` · symlinks resolved · executable |
| After success | `mark_reported: true` moves the sent complete findings to reported |

### Failures

| Message | Cause |
|---|---|
| `export script timed out` | Over 120 s |
| `export script output too large` | stdout |
| `export script failed: exit status 1: …` | Non-zero exit |
| `… is outside the exporters directory` | Path |
| `csv.yaml: script exporter needs script and a plain extension (letters/digits)` | The YAML file |
