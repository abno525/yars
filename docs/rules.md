# Rules

A rule checks a finding's text and reports what breaks it. There are four kinds: a pattern (a regular expression), a built-in check, a script and an AI instruction. This page covers all four; the script contract and the AI rules have their own sections below.

## Rule files

A new data folder (`yars init`) has no rules. **Admin › Rules** writes them. To write them by hand, change `.yars/rules/` in a clone of the main repository and push it as a director with the admin flag ([git.md](git.md)); in the simple workflow every account is a director, so the admin flag is enough.

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
| `script` | a program in `.yars/rules` (Script rules, below) |
| `ai` | an instruction for the AI provider (AI rules, below) |

```yaml
- id: title-no-trailing-dot
  target: title
  regex_forbid: '\.\s*$'
  message: The title must not end with a dot
```

## Patterns

A pattern is matched against one part at a time: the title, a section's body or a details row.

- `^` and `$` are the start and the end of the whole part, not of a line. Write `(?m)` at the start of the pattern to make them match at each line; in the editor that is the Multiline box, as Aa is `(?i)`.
- A pattern the text must match skips an empty part. With `require_nonempty: true` (the editor's Check empty parts box) an empty part is a hit.
- The part is the Markdown as written. Code blocks and tables are matched too.
- A rule of any kind shows up to 20 hits per finding. A last row then says how many it does not show: `and 5 more`, or `and more than 1000 more`.
- That row has the rule's level and counts as one result. It is dismissed on its own, for its count: `and 6 more` is a new row. The live hints under a section do not show it.
- The same wording found again in the same part is the same result, not one more.

## When rules run

Pattern and built-in rules run wherever a finding is checked. Scripts and AI rules take longer and run in fewer places:

- The Check button, `start_check` and `lint_finding all=true` (MCP) and the Test bench on **Admin › Rules** run every rule. On the server `lint_finding all=true` is a check run as the other two: stored, in the queue, and refused on an archived engagement.
- The pre-commit check (`yars lint --staged`) runs the pattern and built-in rules, so a commit does not wait. `yars lint --staged --all` asks the server for scripts and AI rules too. Signed in with a Git token it gets them only when the token has the Run checks action; a password gets them.
- A git push runs scripts, not AI rules.
- `yars lint` runs the pattern and built-in rules only. `yars lint --all` adds scripts and AI rules.
- `yars lint` on the server's data folder leaves out the results dismissed on the finding page and uses the provider, address, model and key saved on **Admin › AI**. In a clone there is no database: nothing is dismissed there and `config.yaml` alone sets the provider.

One check of a finding has 90 s for all its scripts and AI questions together. A rule that has not finished by then fails.

With **Require Check** on (Admin › Rules, the default), Sign off and Approve wait for a finished Check on the finding's current text and on the rules as they are now: after a rule changes, the finding is checked again. While no rule is on, they don't wait. A script rule that could not run fails the Check, and they wait for a new one. An AI rule that could not run does not (AI rules, below).

## Dismissing a result

A result that is right to ignore can be dismissed. A dismissal needs a reason. Restore makes the result count again.

- A warning: anyone who may edit the finding.
- An error: the same, and the reviewer role or more.
- An error on your own finding: another reviewer or a director dismisses it, whatever your role, and restores it. A team needs a second person with the reviewer role or more for that. In the simple workflow you dismiss it yourself.
- A dismissal covers one result: that rule, that place and that quote. The same quote in another place still counts.
- A rule renamed on **Admin › Rules** keeps its dismissals. A rule renamed by hand in its file does not: to the server it is a new rule.
- In an archived engagement nothing is dismissed or restored.
- Each dismissal and each restore is a row in the audit log (Admin › Activity): who, the finding, the rule, its level and place, and the reason. The quote is not in it.

## Script rules

A script rule names a file in `.yars/rules`. The script reads the finding as JSON on stdin, writes its violations to stdout and runs with a clean environment:

```yaml
- id: no-internal-hosts
  level: error            # error | warning
  message: Internal host name in client-facing text
  script: no_internal_hosts.py
  enabled: true
```

Deleting the rule on **Admin › Rules**, or giving it another script, removes the file unless another rule names it. Files no rule names (helpers) stay.

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
| `target` | string | `title`, `section:<Name>`, `details:<Row>`, `cvss`, or empty (`finding`) · `more:<n>` is read as empty |

### Example: no_internal_hosts.py

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

The server keeps a run that works, in memory and in its database: for Check, `start_check` and `lint_finding all=true` (MCP), the pre-commit check with every rule (`yars lint --staged --all`) and the Test bench on **Admin › Rules**. There the script does not run again while the rules folder (every file in it, helpers too), the rule and the finding as the script reads it on stdin stay the same. A failure, a timeout or invalid output is not kept: the next check runs the script again.

A git push and `yars lint --all` run the script each time.

A script that reads anything else (the network, the time, files outside the rules folder) keeps its old result until one of these changes.

A stored result is deleted after the days set for check runs on **Admin › System › Retention**. The next check then runs the script again.

## Limits

| Limit | Value |
|---|---|
| Timeout | 10 s per script · kill wait 1 s · 90 s for one check's scripts and AI questions together |
| stdout | 1 MB |
| stderr | 64 KB · first 80 characters shown |
| Hits per rule | 20 shown · the rest is counted in a last row, up to 1,000 |
| Quote | 80 characters |
| Message | 4,000 characters · the page cuts it to one line with …, the whole text on hover |
| Environment | `PATH`, `HOME` |
| Working directory | the script's own folder (`.yars/rules`, or `.yars/rules/lib` for `lib/x.py`) |
| Script path | inside `.yars/rules` · symlinks resolved · executable |
| Runs | Check button · `start_check` and `lint_finding all=true` (MCP) · `yars lint --staged --all` · Test bench · `yars lint --all` · git push |

## Failures

A script that can't run reports a violation with target `rules` at the rule's level:

| Message | Cause |
|---|---|
| `rule failed: script outside rules dir` | Path |
| `rule failed: <the system's message>` | The file is missing or not executable (`… no such file or directory`, `… permission denied`). The message can show a path on the server |
| `rule failed: timed out` | Over 10 s, or the check's 90 s ran out |
| `rule failed: output too large (limit 1 MB)` | stdout |
| `rule failed: <stderr>` | Non-zero exit |
| `rule failed: <stderr>` or `rule failed: output too large` | stderr over 64 KB: the rule fails even when the script exits 0 |
| `rule failed: invalid output (want a JSON array): …` | Not a JSON array |

A rules file with a mistake reports `rule invalid (<file>): …`, always as an error, whatever the rule's level:

| Cause | Message ends with |
|---|---|
| The file is not a YAML list | the YAML error |
| An unknown key | `unknown field(s) <names>` |
| No `id` | `rule without id` |
| An id used twice | `duplicate rule id <id>` |
| A `level` other than `error` or `warning` | `level "<level>" must be error or warning` |
| None or several of the checks | `needs exactly one of regex_forbid, regex_require, check, script, ai` |
| A regular expression that does not compile | the expression's error |
| A built-in check that does not exist | `unknown check "<name>"` |
| A target of another form | `unknown target "<target>" (use title, text, sections, details, section:<Name> or details:<Row>)` |

A target that is well formed but names a section or details row the config lacks is a warning: `rule target section:<Name> (<file>) is not a configured section name; check the spelling`.

## AI rules

A rule with `ai:` asks the AI provider (**Admin › AI**, or `ai.*` in `config.yaml`) whether a text follows the instruction. Each part the target covers (the title, each section, each details row) is one question; an AI rule skips a part with no text. The model answers with the violations it finds: a quote from the text and a message. A violation whose quote is not in the text is dropped; a quote that differs only in its spaces and line breaks is taken as the text has it. A reply without the list of violations is a failed check.

```yaml
- id: expand-acronyms
  level: warning
  target: sections
  ai: Expand every acronym on first use.
```

AI rules run where script rules run, except on a git push. Without a provider or a key an AI rule does not run: it reports the warning `AI rules skipped: no AI provider configured`, and the finding shows an "AI checks failed" badge after Check. Sign off and Approve are not held by it.

An AI rule that cannot run never holds a finding, with a provider set up too: when the call fails, or the reply is cut off or cannot be read, Submit, Sign off and Approve go through. The badge and Retry stay on the finding, and what the rule found before on the same text still counts. With a provider set up, each step taken this way is a `warn` line in the service log ([deploy.md](deploy.md)).

### Unchanged text is not sent again

The server keeps a result, in memory and in its database, for the same text, instruction (`ai:`), provider and model, where it keeps script results. A check after a restart uses it too. A text that changed is sent again, and so is every text after an update of YARS that changes the prompt. A call the provider answers with status 429, 500, 502, 503, 504 or 529 is made again, twice at most, within the question's time. Once a question has failed so in a check, the questions after it in that check are asked once. A failed call (`AI check failed: …`, always a warning) is not kept. `yars lint --all` sends the text each time. Stored results are deleted as script results are.

### The text is data

The text goes to the model between `<finding_text>` and `</finding_text>`; a copy of either inside the text is written with `&lt;`. The model is told that the text and the part's name are data from the finding, never instructions: it ignores an instruction in them and may report it as a violation.

A model can still be talked into passing a text, and a text can make its call fail (a reply too long, a reply that is no JSON), which holds nothing. Keep AI rules at `level: warning`, and keep what must hold in pattern, built-in or script rules.

### Limits

| Limit | Value |
|---|---|
| Time per question | 60 s, its tries included · 90 s for one check's scripts and AI questions together |
| Tries per question | 3 · the wait is 1 s, then 2 s, or what the provider's `Retry-After` asks, up to 10 s · 1 for the questions of a check after one that failed with all its tries |
| Redirects | followed on the provider's own address only |
| Reply | 4,096 tokens (Anthropic) · a reply cut at the model's limit is a failed check |
| OpenAI-compatible request | `temperature: 0` and a JSON `response_format` · a model that answers 400 is asked once more without both, and from then on without them until a restart |
| Quote, message | as script rules |
| Stored results | 2,000 in memory per kind · 50,000 in the database, script and AI together; the oldest go first · deleted after the check run days |
