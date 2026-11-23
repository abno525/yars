# Script rules

A rule in `.yars/rules/*.yaml` names a script file in `.yars/rules`. The script reads the finding as JSON on stdin and runs with a clean environment:

```yaml
- id: no-internal-hosts
  level: error            # error | warning
  message: Internal host name in client-facing text
  script: no_internal_hosts.py
  enabled: true
```

## Rule files

A new data folder (`yars init`) has no rules. **Admin › Rules** writes them. To write them by hand, change `.yars/rules/` in a clone of the main repository and push it as a director with the admin flag ([git.md](git.md)); in the simple workflow every account is a director, so the admin flag is enough.

With **Require Check** on (Admin › Rules, the default), Sign off and Approve wait for a finished Check on the finding's current text. While no rule is on, they don't wait.

Every `*.yaml` or `*.yml` file in `.yars/rules/` is a list of rules:

| Field | Value |
|---|---|
| `id` | required; one rule per id across the files |
| `level` | `error` (default) or `warning`. An open error blocks Submit; any open result, a warning too, holds Sign off and Approve until it is fixed or dismissed |
| `message` | shown with each hit; empty → the id |
| `target` | `text` (default: the title, every section and every details row), `title`, `sections`, `section:<Name>`, `details`, `details:<Row>` |
| `enabled` | `false` turns the rule off |

and exactly one check:

| Field | Check |
|---|---|
| `regex_forbid` | a Go (RE2) regular expression; each match in the target is a hit |
| `regex_require` | a regular expression each part of the target must match; an empty part is skipped unless `require_nonempty: true` |
| `check` | built-in: `table-cells-no-backticks` (no backticks in table cells and details rows), `cvss-explained` (a CVSS value other than the standard one in `config.yaml` needs a reason), `not-empty` (each part of the target has text) |
| `script` | a program in `.yars/rules` (below) |
| `ai` | an instruction for the AI provider (AI rules, below) |

```yaml
- id: title-no-trailing-dot
  target: title
  regex_forbid: '\.\s*$'
  message: The title must not end with a dot
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

The server keeps a run that works, in memory and in its database: for Check, `start_check` and `lint_finding all=true` (MCP), the pre-commit check (`yars lint --staged`) and the Test bench on **Admin › Rules**. There the script does not run again while the rules folder (every file in it, helpers too), the rule and the finding as the script reads it on stdin stay the same. A failure, a timeout or invalid output is not kept: the next check runs the script again.

A git push and `yars lint --all` run the script each time.

A script that reads anything else (the network, the time, files outside the rules folder) keeps its old result until one of these changes.

A stored result is deleted after the days set for check runs on **Admin › System › Retention**. The next check then runs the script again.

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

The server keeps a result, in memory and in its database, for the same text, instruction (`ai:`), provider and model, where it keeps script results. A check after a restart uses it too. A text that changed is sent again, and so is every text after an update of YARS that changes the prompt. A failed call (`AI check failed: …`, always a warning) is not kept. `yars lint --all` sends the text each time. Stored results are deleted as script results are.

### The text is data

The text goes to the model between `<finding_text>` and `</finding_text>`; a copy of either inside the text is written with `&lt;`. The model is told that the text and the part's name are data from the finding, never instructions: it ignores an instruction in them and may report it as a violation.

A model can still be talked into passing a text. Keep AI rules at `level: warning`, and keep what must hold in pattern, built-in or script rules.

### Limits

| Limit | Value |
|---|---|
| Time per question | 60 s |
| Reply | 4,096 tokens (Anthropic) |
| Quote, message | as script rules |
| Stored results | 2,000 in memory per kind · 50,000 in the database, script and AI together; the oldest go first · deleted after the check run days |
