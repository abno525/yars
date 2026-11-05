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

Only `refs/heads/main` can be pushed, and every commit is checked as if it were made on the website:

| Message | Reason | Fix |
|---|---|---|
| `commit … is authored by …; commit as yourself` | Author is not the pusher | `git config user.email <you>@…` · `git commit --amend --reset-author` |
| `refs/heads/wip: only refs/heads/main can be pushed` | Other branch | `git push origin wip:main` |
| `refs/heads/main: deleting the branch is not allowed` | Branch delete | — |
| `engagements/demo: engagement pointers are managed by the server` | Submodule pointer in the main repo | push inside `engagements/demo` · top: `git pull` |
| `…/finding.md: findings live in the engagement's own repository` | Finding pushed to the main repo | commit inside `engagements/<id>` |
| `notes.txt: not allowed here` | Path outside a finding | `git rm --cached notes.txt` |
| `…/finding.md: the finding is verification; only a director can change it` | Submitted or approved | a reviewer returns it |
| `…/finding.md: workflow state is managed in YARS, not in the file` | Workflow keys in the file | delete the keys |
| `…/finding.md: id F-005 does not match the directory …` | id ≠ folder | rename the folder or the id |
| `…/finding.md: duplicate id …` | Two folders, one id | use the next free number |
| `…/finding.md: author must be you` | New finding, other author | `author: <you>` |
| `…/finding.md: author cannot change` | Edited author | restore the author |
| `…/finding.md: unknown severity …` | Not in `severities` | one of the configured severities |
| `.yars/…: only a director can change .yars` | Settings, not a director | ask a director |
| `.yars/users.yaml: accounts, tokens and the database stay on the server` | Server-only file | `git rm --cached .yars/users.yaml` |
| `…: only regular files are allowed (no symlinks or submodules)` | Symlink | copy the file |
| `…/finding.md: only a director can delete a finding` | Deleted finding | `git checkout HEAD~1 -- <path>` |
| `the engagement is archived (read only)` | Archived engagement | a director reopens it |

Rules (`.yars/rules`) run on every push; an error-level violation of a finding that is submitted or later rejects the push.
