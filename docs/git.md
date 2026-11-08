# Git

Everything YARS keeps as content is in git: the main repository (`/git/yars`) holds the settings (`.yars/`) and one submodule per engagement; each engagement is its own repository (`/git/e/<id>`) with its findings. Sign in with your YARS username and password, or with a token made for Git (Settings › Tokens) as the password.

## Layout

```text
findings/                    /git/yars
├── .gitmodules
├── .yars/
│   ├── config.yaml
│   ├── rules/               *.yaml, scripts
│   ├── exporters/           *.yaml, scripts
│   └── templates/           *.md
└── engagements/
    └── demo/                /git/e/demo
        ├── engagement.yaml
        ├── report/          *.md
        └── findings/
            └── F-005-sql-injection-in-report-export/
                ├── finding.md
                └── attachments/
```

Workflow state (status, reviewers, sign-offs), chat, check runs and notifications are not in git: they live in the server's database.

## Push rules

Only `refs/heads/main` can be pushed, and every commit in the push is checked on its own, as if it were made on the website: a commit the website could not have made is refused even when a later commit repairs it, since history keeps both. Each refusal reads `commit <hash> <file>: <rule>`; the hash is the commit to fix, with `git commit --amend` for the last one or `git rebase -i <hash>~1` (mark it `edit`) for an earlier one. Only the parts a commit changes are checked, so a finding that already broke a rule on the server can still have its other parts edited. Up to 50 problems are listed, then their count.

| Message | Reason | Fix |
|---|---|---|
| `commit 1a2b3c4: authored by … <…>, but the account … has the email …` | The author email is not your account's email (the name may differ; directors too) | `git config user.email <account email>` · `git commit --amend --reset-author` |
| `the email … of account … is also the email of account …` | Two accounts share an email (from before emails had to be unique) | one of them changes it in Settings › Account |
| `…/finding.md: CVSS vector … is not written as this server's CVSS 3.1 vector; write …` | Another version (3.0) or metric order | the vector the message gives |
| `…/finding.md: CVSS vector …: missing metric …` | Incomplete or invalid vector | a complete `CVSS:3.1/…` base vector, or none |
| `…/finding.md: severity … does not match the CVSS vector (score … is …)` | The website derives the severity from the vector | `severity: <the rating named>` |
| `…/finding.md: asset 2: port must be 1–65535` | An asset row the website refuses (also: host or URL, URL with scheme and host, one line) | correct the row |
| `…/finding.md: the title must be one line of 1–200 characters` | Empty, multi-line or long title | one line |
| `…/finding.md: the title has … hidden text-direction characters` | Bidi controls (they can disguise `gnp.exe` as `exe.png`) | retype the title |
| `…/attachments/x: only images and text files can be attached` | Program, archive, PDF … | attach a screenshot or text |
| `…/attachments/x: attachments cannot be executable` | Mode 755 | `git update-index --chmod=-x <file>` |
| `…/attachments/x: attachment names are letters, digits, . _ -` | Spaces, sub-folders | rename the file |
| `…: 11.0 MB; files over 10 MB are not accepted` | Any file over 10 MB, even one a later commit deletes | rebase it out of the commit |
| `engagement.yaml: name is required` · `dates are YYYY-MM-DD` · `the end is before the start` | The engagement's Settings tab rules | correct the value |
| `engagement.yaml: type is fixed when the engagement is created; keep type: …` | Type or source changed | restore `type` / `source` |
| `refs/heads/wip: only refs/heads/main can be pushed` | Other branch | `git push origin wip:main` |
| `refs/heads/main: deleting the branch is not allowed` | Branch delete | — |
| `engagements/demo: engagement pointers are managed by the server` | Submodule pointer in the main repo | push inside `engagements/demo` · top: `git pull` |
| `…/finding.md: findings live in the engagement's own repository` | Finding pushed to the main repo | commit inside `engagements/<id>` |
| `notes.txt: not allowed here` | Path outside a finding | `git rm --cached notes.txt` |
| `…/poc.txt: not allowed here; a finding's files go in findings/<finding>/attachments/` | A file beside `finding.md` | `git mv` it into `attachments/` |
| `…: F-005 is in verification; only its reviewers (bob) and directors can change it` | Submitted: locked for its author too, text and attachments (stricter than the website, where the author may still edit) | a reviewer returns it, or a reviewer pushes the change |
| `…: F-005 is complete; only a director can change it` | Approved, reported or withdrawn, text and attachments | ask a director |
| `…/finding.md: workflow state is managed in YARS, not in the file` | Workflow keys in the file | delete the keys |
| `…/finding.md: id F-005 does not match the directory …` | id ≠ folder | rename the folder or the id |
| `…/finding.md: duplicate id …` | Two folders, one id | use the next free number |
| `…/finding.md: author must be you` | New finding, other author | `author: <you>` |
| `…/finding.md: author cannot change` | Edited author | restore the author |
| `…/finding.md: unknown severity …` | Not in `severities` | one of the configured severities |
| `.yars/…: only a director can change .yars` | Settings, not a director | ask a director |
| `.yars/config.yaml: only an admin can change .yars/config.yaml and .yars/rules` | Not an admin (the website keeps Structure, AI and Rules to admins) | ask an admin |
| `.yars/config.yaml: Sections: "impact" twice` · `Severities: "Urgent" must be one lowercase word` · `cannot load: …` | A value Admin › Structure refuses, or a file that does not load | correct the value |
| `.yars/config.yaml: section "Impact" is still used by: acme/F-001, … (+N more). Change those findings first, then remove the name; renames are done in Admin › Structure.` | A section, severity or details row removed (or renamed) while findings of any engagement, archived ones too, still use it | change those findings first, then push again; rename in Admin › Structure |
| `.yars/config.yaml: cannot be deleted` | Every setting would fall back to its default | push the settings you want |
| `.yars/rules/x.yaml: rule invalid (x.yaml): …` | A rule Admin › Rules refuses (regex, unknown field, duplicate id); problems the folder already had don't block | correct the rule |
| `.yars/exporters/x.yaml: …` · `address and key variables: admin only` | An exporter the export setup refuses; a service address set by a non-admin | correct it · ask an admin |
| `.yars/users.yaml: accounts, tokens and the database stay on the server` | Server-only file | `git rm --cached .yars/users.yaml` |
| `…: only regular files are allowed (no symlinks or submodules)` | Symlink | copy the file |
| `…/finding.md: only a director can delete a finding` | Deleted finding | `git checkout HEAD~1 -- <path>` |
| `the engagement is archived (read only)` | Archived engagement | a director reopens it |

Settings pushed to the main repository take effect on the website as soon as the push is accepted, as a save on the Admin pages does: `config.yaml` is read again; rules, exporters and templates are read from disk each time they are used. A push can't tell a rename from a removal, so a `config.yaml` that drops a section, details row or severity some finding still uses is refused: change those findings first. Renames are done in Admin › Structure.

## Check rules on push

Once a push passes the rules above, the server's check rules (`.yars/rules` as the server has them, never the pushed ones) run on each finding the push changes, as its last commit has it: the regex, built-in and script rules the Check button runs. AI rules don't run on push, since they wait on the AI provider; Check on the finding page runs them, and the push lists them as `(could not run)`.

| Output | When | Push |
|---|---|---|
| `commit 1a2b3c4 findings/F-005-…/finding.md: check <rule> (error): <message>` | An error on a finding in verification, complete or reported | refused; fix it in a new commit |
| `… check <rule> (error; blocks Submit): <message>` | An error on a draft (the website saves drafts with errors too; Submit is gated) | accepted |
| `… check <rule> (warning): <message>` | A warning | accepted |

Errors and warnings dismissed on the finding's Checks panel don't count. The results are not stored as a check run; press Check to see them on the finding page.
