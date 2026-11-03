# YARS — CVSS calculator, CVSS reasoning table, details table (design)

Builds on milestones 1–2 (branch `feat/core`). Parent spec: `2026-11-03-yars-design.md`.

## Intent
Every finding in the team's report carries two tables besides its prose sections:

1. **Details table** — 5 descriptive rows. Two rows are known now: **Location** and
   **Business impact**. The other three will be named by the user later, so row names must be
   configuration, not code.
2. **CVSS reasoning table** — lists only the CVSS metrics whose value is *non-standard*, each
   with a written reason. This also enforces the team rule "a non-standard CVSS score has to
   be explained".

Plus a **built-in CVSS calculator** so nobody leaves the app to compute a vector, and the
finding's severity always matches its score. Prior art the user referenced: DefectDojo and
typical pentest report templates.

## Goals / non-goals
- Goals: click-to-set CVSS calculator on the finding page; live score, rating and vector;
  pasting an existing vector works; severity derived from score; a details table whose 5 row
  names come from `.yars/config.yaml`; a CVSS reasoning table showing only non-standard
  metrics with reasons; everything stored in `finding.md` front matter so local/AI edits work.
- Non-goals now: CVSS 4.0 (see "My calls"), temporal/environmental metrics, CWE/CVE pickers,
  rule-engine enforcement (milestone 5 picks this up).
- Anti-goals: tiny fields; a calculator that lives on a separate page; severity and score
  disagreeing; row names hard-coded in templates.

## Storage (front matter of `finding.md`)
```yaml
severity: high                 # derived from cvss when cvss is set
cvss: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
cvss_reasons:                  # keyed by metric abbreviation; only non-standard ones needed
    AC: Exploitation requires winning a race against the session refresh.
details:                       # keyed by configured row name
    Location: https://app.acme.com/login (parameter user)
    Business impact: Any customer account can be taken over.
    Row 3: ""
```
- Details values are plain text (may be multi-line; YAML block scalar). They render as plain
  text with line breaks — not Markdown — because the team rule forbids Markdown such as
  backticks in table fields.
- Unknown keys under `details` (e.g. a row later renamed) are kept and shown under an
  "Other" label rather than dropped.
- Front matter edits must patch the YAML node tree (not re-encode the struct) so comments, key
  order and untouched fields survive — this was a known follow-up from milestone 1–2.

## Configuration (`.yars/config.yaml`)
```yaml
details_rows: [Location, Business impact, Row 3, Row 4, Row 5]
cvss:
    version: "3.1"
    standard:                  # the team's "standard" value per metric
        AV: N
        AC: L
        PR: N
        UI: N
        S: U
```
- `details_rows` defaults to the list above (placeholders "Row 3..5" until the user names them).
- A metric is **non-standard** when the finding's value differs from `cvss.standard[metric]`.
  C, I and A default to standard `N` (user decision 2026-11-03), so any Low/High impact needs
  an explanation; options are listed None → Low → High. Metrics with no standard (removed
  via `"-"`) are never non-standard.

## Behaviour
- **Calculator panel** (top of finding page, under the title): one button group per base metric
  (AV, AC, PR, UI, S, C, I, A) with full names on hover. Clicking updates score, rating, and
  vector live (server computes via htmx; one Go implementation of the CVSS 3.1 formula is the
  single source of truth, also used by tests and later by the rule engine/MCP). A text box
  accepts a pasted vector (3.0 or 3.1 prefix accepted, stored as 3.1).
- Under the calculator, an "Explanation of non-standard values" table (Metric | Value |
  Explanation) has one textarea per non-standard metric (user decision 2026-11-03). Save commits once:
  `F-001: set CVSS 8.1`.
- Missing reason for a non-standard metric: save is allowed, the panel shows a warning, and the
  reasoning table shows "reason missing" in red. Blocking is left to the rule engine / the
  draft→verification gate (milestone 3/5).
- **Severity**: when `cvss` is set, severity = CVSS 3.1 rating (0.0 → info, 0.1–3.9 low,
  4.0–6.9 medium, 7.0–8.9 high, 9.0–10.0 critical). Without a vector, severity stays manually
  settable (select in the same panel).
- **Details panel**: shows the 5-row table; Edit opens one large textarea per row in a single
  form; one commit `F-001: edit details`. Same optimistic-concurrency (`base` hash) as sections.
- **Read view**: finding page order = title/meta → Details table → CVSS (score, vector,
  reasoning table, hidden if empty) → prose sections.
- Engagement table gains a CVSS score column; severity sort unchanged.
- Default prose sections drop `Location` (it now lives in the details table): Description,
  Impact, Steps to Reproduce, Remediation, References. Existing files with a `## Location`
  section keep it.

## Edge cases (settled after builder check)
- **Foreign `cvss` values** (bare number, 4.0 vector, temporal/environmental metrics, garbage):
  shown read-only as written, with a note "not a CVSS 3.1 base vector — using the calculator
  will replace it". Nothing is cleaned up silently. Severity stays as stored (manual).
- **Derivation happens on read**: the index and finding page compute severity from a valid 3.1
  base vector; a stored `severity` that disagrees is ignored for display/sort (and rewritten on
  the next CVSS save). So table, sort and score can never disagree.
- **Calculator start state**: metrics that have a team standard start pre-selected at that
  standard; C/I/A start empty. Save requires all 8 metrics (button stays disabled until then).
  A "Clear" action removes `cvss` and keeps the last severity as a manual value.
- **Config `cvss.standard` merges** over the defaults; a value of `"-"` removes a default
  standard; standards may be set for C/I/A too.
- **Severity names**: CVSS ratings map to `info/low/medium/high/critical`. Config load fails with
  a clear error if `severities` lacks any of these (a mapping can be added later if a team
  renames them).
- **Reasons for metrics back at standard** are kept in the file but not shown or exported, so an
  accidental toggle never deletes text.

## Verification
- Unit tests: CVSS 3.1 scores against the FIRST spec examples (incl. scope changed and the
  round-up function), vector parse/format/round-trip, non-standard detection, front-matter
  node patching keeps comments and order.
- Web tests: set vector → commit + severity; reasons saved; details save with 409 on conflict.
- Manual: click through the calculator in the browser on the demo data.

## My calls (please check)
- CVSS **3.1 only** for now; the stored vector keeps its version prefix so 4.0 can be added later
  without migrating files.
- "Non-standard" = differs from a per-metric team standard in config (defaults above).
- Missing reasons warn, they don't block (yet).
- Details rows are plain text, not Markdown.
- Severity is derived from the score whenever a vector exists (no manual override).
- Location moves from a prose section to the details table.
