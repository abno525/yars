# Script exporters

A destination in `.yars/exporters/*.yaml` of type `script` (edit them under **Export › Destinations**) names a script file in `.yars/exporters`. The script reads the engagement's findings as JSON on stdin, runs with a clean environment and writes the file to stdout:

```yaml
name: CSV summary
type: script
script: csv_summary.py
extension: csv
statuses: [complete, reported]
mark_reported: false
```

The script runs on the server as the service account. So only an admin makes a script destination, names its script, or adds, changes or deletes a script file in `.yars/exporters`. A director without the admin flag still edits its name, extension, statuses and `mark_reported`.

## stdin

| Field | Shape |
|---|---|
| `engagement` | `{id, name, client, type, source, start, end, archived}` |
| `engagement_id` | string |
| `findings` | rules.Doc + `html_sections` for each finding with one of `statuses`, by severity, then ID |
| `html_sections` | section name → rendered HTML |

## stdout

The file itself, saved as `<engagement id>.<extension>` (`application/octet-stream`).

## Limits

| Limit | Value |
|---|---|
| Timeout | 120 s · kill wait 2 s |
| stdout | 100 MB |
| stderr | 64 KB · the end shown |
| Environment | `PATH`, `HOME` |
| Working directory | `.yars/exporters` |
| Script path | inside `.yars/exporters` · symlinks resolved · executable |
| After success | `mark_reported: true` moves the sent complete findings to reported |

## Failures

| Message | Cause |
|---|---|
| `export script timed out` | Over 120 s |
| `export script output too large` | stdout |
| `export script failed: exit status 1: …` | Non-zero exit |
| `… is outside the exporters directory` | Path |
| `csv.yaml: script exporter needs script and a plain extension (letters/digits)` | The YAML file |
