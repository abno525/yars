# Git

Everything YARS keeps as content is in git: the main repository (`/git/yars`) holds the settings (`.yars/`) and one submodule per engagement; each engagement is its own repository (`/git/e/<id>`) with its findings. Sign in with your YARS username and password, or with a token made for Git (Settings › Tokens) as the password. A token restricted to some engagements cannot clone the main repository: clone each engagement alone (`/git/e/<id>`).

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

A sign-off covers a finding's text and its attachments. A push that changes either while the finding is in verification drops its sign-offs, as an edit on the website does.

## Cloning and pulling

Directors and admins (in the simple workflow, every account) see every engagement and clone them all:

```sh
git clone --recurse-submodules https://<server>/git/yars findings && cd findings &&
git submodule foreach -q git switch -q main
```

A pentester or reviewer may fetch only the engagements whose team they are on, and git stops a recursive clone at the first one they are not on. So they name their own, as the Clone panel on the Engagements page does for them; the other engagements stay empty folders:

```sh
git clone https://<server>/git/yars findings && cd findings &&
git submodule update --init engagements/<id> engagements/<id2> &&
git submodule foreach -q git switch -q main
```

The Clone panel clones into `yars`, git's default name for that address; the examples here use `findings`. Either name works.

Each line but the last ends with `&&`, so a paste stops at the first failure instead of running the rest in the current folder. Git checks submodules out on a detached HEAD: a commit made there is on no branch, and the push of `main` leaves it out. The last line puts every engagement on `main`. To pull, run `git pull` in the top folder, then `git submodule foreach -q git pull -q`: each engagement pulls its `main`. `git pull --recurse-submodules` (and `git submodule update`) detaches them again, and switching back to `main` after it lands on the `main` of the previous pull: pull there too. A pull touches only the engagements the clone checked out.

A new engagement is checked out with `git submodule update --init engagements/<id>` (a director or an admin may leave out the path), then switched to `main` as above. Without the path, a pentester's or reviewer's `git submodule update --init` stops at the first engagement they are not on. A plain `git pull` leaves that one alone, but `git pull --recurse-submodules` and `git submodule update` try it again each time.

An engagement you were taken off, while checked out, stops `git submodule foreach -q git pull -q`, and `git pull` fails each time it moves. Take out such an engagement, or one registered by mistake, with `git submodule deinit engagements/<id>` (it may warn that it could not unset `core.worktree`, which does no harm). For one you were taken off, also delete `.git/modules/engagements/<id>`, with any commits not pushed in it: git keeps fetching it while that repository is there.

With a clone URL that holds your user name, as Developers › Git shows it, git prints `warning: redirecting to …/git/yars/`: it compares the URL it was given with the one it reached, which has no user name. Nothing is redirected, and the clone is whole.

### A clone from before engagements had their own repositories

Engagements were once folders of the main repository; `yars migrate` makes each a repository of its own. A clone from before that with commits not pushed yet: push them before the server is upgraded. After the upgrade such a clone's next pull meets modify/delete conflicts, since the engagement folders left the main repository. Then clone again (as above), copy the files you changed from the old clone into the new one's `engagements/<id>/`, and commit and push them there.

## Push rules

Only `refs/heads/main` can be pushed, and every commit in the push is checked on its own, as if it were made on the website: a commit the website could not have made is refused even when a later commit repairs it, since history keeps both. Each refusal of a file reads `commit <hash> <file>: <rule>` (the author check and a purged original read `commit <hash>: …`); the hash is the commit to fix, with `git commit --amend` for the last one or `git rebase -i <hash>~1` (mark it `edit`) for an earlier one. Only the parts a commit changes are checked, so a finding that already broke a rule on the server can still have its other parts edited. Up to 50 problems are listed, then their count.

| Message | Reason | Fix |
|---|---|---|
| `commit 1a2b3c4: authored by … <…>, but the account … has the email …` | The author email is not your account's email (the name may differ; directors too) | `git config user.email <account email>` · `git commit --amend --reset-author` |
| `the email … of account … is also the email of account …` | Two accounts share an email (from before emails had to be unique) | one of them changes it in Settings › Account |
| `…/finding.md: CVSS vector … is not written as this server's CVSS 3.1 vector; write …` | Another version (3.0) or metric order | the vector the message gives |
| `…/finding.md: CVSS vector …: missing metric A (Availability): add A:N, A:L or A:H` | Incomplete vector | one of the values the message names |
| `…/finding.md: CVSS vector …: invalid value Q for I (Integrity): use N, L or H` (also `no value for …`, `invalid component …: write metric:value`) | A metric with a value it does not take, or a part that is not `metric:value` | one of the values the message names |
| `…/finding.md: severity … does not match the CVSS vector (score … is …)` | The website derives the severity from the vector | `severity: <the rating named>` |
| `…/finding.md: asset 2: port must be 1–65535` | An asset row the website refuses (also: host or URL, URL with scheme and host, one line) | correct the row |
| `…/finding.md: the title must be one line of 1–200 characters` | Empty, multi-line or long title | one line |
| `…/finding.md: the title has … hidden text-direction characters` | Bidi controls (they can disguise `gnp.exe` as `exe.png`) | retype the title |
| `…/attachments/x: only images and text files can be attached` | Program, archive, PDF … | attach a screenshot or text |
| `…/attachments/x: attachments cannot be executable` | Mode 755 | `git update-index --chmod=-x <file>` |
| `…/attachments/x: attachment names are letters, digits, . _ -` | Spaces, sub-folders | rename the file |
| `…: 11.0 MB; files over 10 MB are not accepted` | Any file over 10 MB, even one a later commit deletes | rebase it out of the commit |
| `commit 1a2b3c4: …/attachments/x.png brings back x.png, which was purged from this engagement's history; …` | The clone was made before a director purged the image's original (Purge from history); its old commits still hold it | clone the engagement again and redo your change |
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
| `README.md: only a director can change README.md` | The main repository's `README.md` or `.gitignore`, not a director: both land in every clone | ask a director |
| `.yars/config.yaml: only an admin can change .yars/config.yaml and .yars/rules` | Not an admin (the website keeps Structure, AI and Rules to admins); every file under `.yars/rules/`, scripts in subfolders too | ask an admin |
| `.gitattributes: only an admin can change .gitattributes` | Not an admin: its lines set how files are checked out, the rule scripts and `config.yaml` too | ask an admin |
| `.yars/CONFIG.yaml: spell it .yars/config.yaml` · `.yars/exporters/jira.YAML: spell it .yaml` | `config.yaml`, `rules`, `exporters` or `templates`, or the extension the server reads there (`.yaml`, `.yml`, `.md`), in another case: a case-insensitive checkout takes it for the real one (removing such a file is accepted) | fix the commit itself (`git commit --amend`, or `git rebase -i` for an earlier one); every commit is checked on its own, so a rename in a later commit does not save it |
| `.yars/ruleſ/x.yaml: .yars names are plain ASCII, without ~` | A letter outside ASCII or a `~` in a name under `.yars`: some file systems take `ſ` for `s` or `CONFIG~1.YAM` for `config.yaml` | fix the commit itself, as above |
| `.yars/config.yaml: Sections: "impact" twice` · `Severities: "Urgent" must be one lowercase word` · `cannot load: …` | A value Admin › Structure refuses, or a file that does not load | correct the value |
| `.yars/config.yaml: section "Impact" is still used by: acme/F-001, … (+N more). Change those findings first, then remove the name.` | A section, severity or details row removed (or renamed) while findings of any engagement, archived ones too, or a template (`template x.md`) still use it | change those findings (or templates) first, then push again |
| `.yars/config.yaml: cannot be deleted` | Every setting would fall back to its default | push the settings you want |
| `.yars/config.yaml: workflow is set by yars init (this server runs the simple workflow) and cannot change` | The pushed file's `workflow` key is not the workflow the server runs: changed, removed or added (each commit is held to the server's workflow, not to its parent's file) | put the key back to the server's workflow (`workflow: simple`, or none for the standard workflow) |
| `.yars/rules/x.yaml: rule invalid (x.yaml): …` | A rule Admin › Rules refuses (regex, unknown field, duplicate id); problems the folder already had don't block | correct the rule |
| `.yars/exporters/x.yaml: …` · `address, space, parent page, project, issue type, key variables, script and template: admin only` | An exporter the export setup refuses; a service's address or target, a script or a template set by a non-admin | correct it · ask an admin |
| `.yars/exporters/x.sh: only an admin can change the scripts and templates in .yars/exporters …` | Not an admin: any file there that is not a destination's `<id>.yaml`, in subfolders too | ask an admin |
| `.yars/users.yaml: accounts, tokens and the database stay on the server` | Server-only file | `git rm --cached .yars/users.yaml` |
| `…: only regular files are allowed (no symlinks or submodules)` | Symlink | copy the file |
| `…/finding.md: only a director can delete a finding` | Deleted finding | `git checkout HEAD~1 -- <path>` |
| `the engagement is archived (read only)` | Archived engagement | a director reopens it |

Settings pushed to the main repository take effect on the website as soon as the push is accepted, as a save on the Admin pages does: `config.yaml` is read again; rules, exporters and templates are read from disk each time they are used. A push can't tell a rename from a removal, so a `config.yaml` that drops a section, details row or severity some finding still uses is refused: change those findings first.

A director's Purge from history (an attachment's Purge on the finding page) rewrites the engagement's history: every commit from the first one that held an earlier version gets a new id, so existing clones must be cloned again, and the main repository's older commits point at engagement commits that no longer exist. Backups made before the purge still hold the original. When the same image is uploaded again later, the server holds those bytes again, and a pre-purge clone's old commits are no longer refused.

A redaction also reaches the retests made from the engagement, and their retests: each copy of the image that still holds an earlier version of it (the original, or one an earlier redaction did not reach) gets the redacted image, in a commit of its own there, as the redactor's change. A copy changed since is left as it is. So is a copy in an archived retest, one that only a director may edit there (complete or reported), and one in a retest the redactor is not on the team of. The redaction names the first two, and a copy it could not change, and counts the last. A purge is per engagement: its page lists the retests whose files or history still hold the original, to purge there too, also a retest whose copy was deleted since.

## Check rules on push

Once a push passes the rules above, the server's check rules (`.yars/rules` as the server has them, never the pushed ones) run on each finding the push changes, as its last commit has it: the regex, built-in and script rules the Check button runs. AI rules don't run on push, since they wait on the AI provider; Check on the finding page runs them, and the push lists them as `(could not run)`.

| Output | When | Push |
|---|---|---|
| `commit 1a2b3c4 findings/F-005-…/finding.md: check <rule> (error): <message>` | An error on a finding in verification, complete or reported | refused; fix it in a new commit |
| `… check <rule> (error; blocks Submit): <message>` | An error on a draft (the website saves drafts with errors too; Submit is gated); `blocks Complete` in the simple workflow | accepted |
| `… check <rule> (warning): <message>` | A warning | accepted |

Errors and warnings dismissed on the finding's Checks panel don't count. The results are not stored as a check run; press Check to see them on the finding page.

## Check before you commit

```sh
yars hook install --data <clone>
```

Run it once in each clone (a main clone or an engagement clone), and again after a new engagement is checked out in a main clone (`git submodule update --init engagements/<id>`): it puts a `pre-commit` hook in every engagement repository. Each commit then sends the `finding.md` files it adds or changes (as staged, not the work tree) to the server, which checks them as the Check button does, with the same rules, AI rules included, and the finding's workflow state, so a commit can take as long as a Check does (at most two minutes). Nothing of it is kept on the server (no commit, no check run) except what Check keeps too: the AI usage records, under your account, and the stored script and AI results (Script rules › Stored results).

The hook signs in with the login git has saved for the clone and never asks for one: the login in the clone URL (a Git token from Settings › Tokens works there, and failed tokens never lock the account), or the one git's credential helper keeps. Stock git keeps none: set a helper once (`git config --global credential.helper store`, or `cache`, or your system's keyring helper), then `git fetch` once to save the login. A login the server refuses is forgotten by the helper, as git does. The hook reaches the server as git does (`http.sslCAInfo`, `http.sslVerify`, `http.proxy`).

Signed in with a token, the check runs script and AI rules only when the token has the Run checks action. With any other token, a read-only one too, the server runs the pattern and built-in rules and leaves the others out of the answer.

| Output | When |
|---|---|
| `findings/F-005-…/finding.md error <rule>: <message> ("<quote>") [<target>]` | A rule the finding breaks; `warning` for a warning |
| `findings/F-005-…/finding.md could not run <rule>: <message> [ai]` | A rule the server could not run (no AI provider, a broken script); not counted |
| `yars: 1 errors, 0 warnings in 1 findings (commit not blocked)` | The last line |
| `yars: could not ask <host>: <reason>; nothing checked` | The server is down, slow or refused the login |
| `yars: no saved login for <host>; …` | git has no login for the server (see above) |
| `<hook>: a pre-commit hook exists already; add this line to it: …` | At install: a hook you wrote is kept; add the line yourself |
| `<engagement>: core.hooksPath is set (…); add this line to its pre-commit hook: …` | At install: your hooks live elsewhere; add the line there |

The hook never blocks a commit: the push is checked again by the server (see above). `yars lint --staged` runs the same check by hand, and without `--warn-only` exits 1 when there are errors.
