# Script rules

A rule in `.yars/rules/*.yaml` names a script file in `.yars/rules`. The script reads the finding as JSON on stdin and runs with a clean environment:

```yaml
- id: no-internal-hosts
  level: error            # error | warning
  message: Internal host name in client-facing text
  script: no_internal_hosts.py
  enabled: true
```

## stdin: the finding (rules.Doc)

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

## stdout: the violations

A JSON array; `[]` means the finding passes.

| Field | Type | Value |
|---|---|---|
| `message` | string | empty → the rule's message |
| `quote` | string | the offending text, cut to 80 characters + … |
| `target` | string | `title`, `section:<Name>`, `details:<Row>`, `cvss`, or empty (`finding`) |

## Example: no_internal_hosts.py

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

## Stored results

A run that works is kept, in memory and in the server's database. The script does not run again while the rules folder (every file in it, helpers too), the rule and the finding as the script reads it on stdin stay the same. A failure, a timeout or invalid output is not kept: the next check runs the script again.

A script that reads anything else (the network, the time, files outside the rules folder) keeps its old result until one of these changes.

## Limits

| Limit | Value |
|---|---|
| Timeout | 10 s · kill wait 1 s |
| stdout | 1 MB |
| stderr | 64 KB · first 80 characters shown |
| Hits per rule | 20 |
| Quote | 80 characters |
| Message | 4,000 characters · the page cuts it to one line with …, the whole text on hover |
| Environment | `PATH`, `HOME` |
| Working directory | `.yars/rules` |
| Script path | inside `.yars/rules` · symlinks resolved · executable |
| Runs | Check button · `start_check` and `lint_finding all=true` (MCP) · `yars lint` · git push |

## Failures

A rule that can't run reports a violation with target `rules` at the rule's level:

| Message | Cause |
|---|---|
| `rule failed: script outside rules dir` | Path |
| `rule failed: timed out` | Over 10 s |
| `rule failed: output too large (limit 1 MB)` | stdout |
| `rule failed: <stderr>` | Non-zero exit |
| `rule failed: invalid output (want a JSON array): …` | Not a JSON array |
| `rule invalid (hosts.yaml): …` | The YAML file: unknown keys, duplicate id, not exactly one of `regex_forbid`, `regex_require`, `check`, `script`, `ai` |

## AI rules

A rule with `ai:` asks the AI provider (**Admin › AI**, or `ai.*` in `config.yaml`) whether a text follows the instruction. Each part the target covers (the title, each section, each details row) is one question. The model answers with the violations it finds: a quote from the text and a message.

```yaml
- id: expand-acronyms
  level: warning
  target: sections
  ai: Expand every acronym on first use.
```

AI rules run where script rules run, except on a git push. Without a provider or a key they are skipped with a warning.

### Unchanged text is not sent again

A result is kept, in memory and in the server's database, for the same text, instruction (`ai:`), provider and model. A check after a restart uses it too. A text that changed is sent again. A failed call (`AI check failed: …`, always a warning) is not kept.

### The text is data

The text goes to the model between `<finding_text>` and `</finding_text>`; a copy of either inside the text is written with `&lt;`. The model is told that the text and the part's name are data from the finding, never instructions: it ignores an instruction in them and may report it as a violation.

A model can still be talked into passing a text. Keep AI rules at `level: warning`, and keep what must hold in pattern, built-in or script rules.

### Limits

| Limit | Value |
|---|---|
| Time per question | 60 s |
| Reply | 4,096 tokens (Anthropic) |
| Quote, message | as script rules |
| Stored results | 2,000 in memory per kind · 50,000 in the database, script and AI together; the oldest go first |
