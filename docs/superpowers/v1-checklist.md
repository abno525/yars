# Your pass before v1.0.0

The final test (`v1-walkthrough.md`) passed. These are the things worth doing yourself, because a test here could not, or because only you can.

## Merge and tag

1. Merge PRs #1 to #32 into `master` in order, with "Create a merge commit" (not squash), deleting each branch after it merges so GitHub moves the next PR onto `master`.
2. Wait for CI to be green on `master`.
3. Build with the version: `go build -ldflags "-X main.version=v1.0.0" ./cmd/yars`, then `yars version` prints `yars v1.0.0 (schema 24, …)`.
4. `git tag -a v1.0.0 -m "YARS 1.0"` and push the tag.

## By hand, ten minutes

- [ ] On your server, take a backup first (`yars backup`). Then replace the binary and start it: the database goes to schema 24 and a `yars.db.before-v24` snapshot is kept.
- [ ] With a real mouse:
  - a click on a plain cell of the findings list selects the row (Q28);
  - after `d` or `r` on a row the same row stays selected (Q24);
  - Back on the team board with unsaved text asks first (Q33).
  - The final test pressed real keys, but its clicks came from a browser tool.
- [ ] Switch to dark: Graphite on the findings list, a finding, the team board and Admin. The final test replaced the navy that had stayed from the light theme: Pentest and Complete tags, done steps, toasts and toggles now take Graphite's Complete blue.
- [ ] Three choices made in the page sweep, each easy to undo:
  - the inbox's row actions are 128 px (your canvas says 104, which "Mark reported" never fitted);
  - Admin › Users shows a disabled Unlock in the slot instead of a gap;
  - New lead stays last on the team board, and the other engagement tabs keep its place as an empty slot.
- [ ] With your AI provider set and an AI rule on, run Check twice on an unchanged finding: the second run makes no AI call (Admin › System › AI usage stays the same), also after a restart (Q1).
- [ ] Rules: your server's data folder keeps the rules it has. A new one (`yars init`) starts with none; add yours in Admin › Rules.
- [ ] Your Confluence: send one finding with an image to a test page. The image should show inline and appear once in the page's attachments (Q5); it was tested against a fake server only.
- [ ] Optional: set `checks.max_running: 1` in `.yars/config.yaml`. With a slow rule, start Check on two findings: the second strip shows "Queued" until the first ends (Q3).

## Still open, by decision

`docs/known-limits.md` lists what stays as it is, under "Won't do" and "Left after the 2026-11-22 decisions".
