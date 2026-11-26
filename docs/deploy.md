# Deploy, back up, upgrade

Running YARS for a team: one server, one data folder, a proxy for HTTPS.

## Requirements

- **git 2.30 or later**, on the server's `PATH`. An older git lacks an option YARS reads refs with. YARS keeps every engagement in a git repository and serves clones and pushes itself. Removing a file from history (Purge) uses `git filter-branch`; some small images package it apart from git.
- **Go 1.27.2 or later**, to build the binary. Build with the newest patch release: it has the security fixes of Go's own packages, which end up in the binary.
- **pandoc** (optional), for the PDF, Word and other pandoc downloads and destinations. Without it, those are refused; the ZIP downloads and the Confluence HTML destination still work.
  - Some packaged pandoc builds cannot load their own data files under `--sandbox`. YARS then runs pandoc without the sandbox: what it is given is already sanitised, and images are already inlined. A static release from pandoc's website keeps the sandbox.
- **xelatex** (optional), for PDF: the report theme is a LaTeX template. It needs the LaTeX packages fontspec, xcolor, geometry, graphicx, longtable, booktabs, array, calc, etoolbox, fancyhdr, fvextra and hyperref, and looks as designed with the IBM Plex fonts installed (else TeX Gyre). Without xelatex, PDFs fail with pandoc's message, and the other formats still work.

## Install

```sh
go build -ldflags "-X main.version=v1.0.0" -o yars ./cmd/yars
sudo install -m 0755 yars /usr/local/bin/yars
yars version
```

`yars version` prints the version, the database schema it writes and the Go release, for example `yars v1.0.0 (schema 25, go1.27.2)`. Built in a clone without `-ldflags`, it shows the git revision; installed with `go install` without them, the release it installed, such as `v1.0.0`.

Without a clone, one command builds the newest release. The binary lands in `$(go env GOBIN)`, or in `$(go env GOPATH)/bin` when `GOBIN` is not set.

```sh
go install github.com/abno525/yars/cmd/yars@latest
sudo install -m 0755 "$(go env GOPATH)/bin/yars" /usr/local/bin/yars
```

Settings › About shows the version, the license and a Source link. A changed YARS must offer its own source to its users: build it with `-X main.source=https://your.host/your-yars` in the same `-ldflags`.

Create the account the service runs as, its data folder and the backup folder:

```sh
sudo useradd --system --user-group --home-dir /var/lib/yars --create-home --shell /usr/sbin/nologin yars
sudo install -d -o yars -g yars -m 0700 /srv/yars
sudo install -d -o yars -g yars -m 0700 /backups
sudo -u yars yars init /srv/yars
echo 'change-me-now' | sudo -u yars yars useradd --data /srv/yars --role director --admin alice
```

The account's home is outside the data folder: rule and exporter scripts run with it as `HOME`, and anything in the data folder goes into every backup. The last line makes the first admin; the password (at least 10 characters and at most 72 bytes, as on the website) is read from standard input. A piped password is a temporary one: the first login on the website asks for a new one, and until then the account's git logins and tokens are refused. `yars passwd` follows the same rule. On a terminal, without the `echo`, both commands ask for the password twice and do not show it; a password typed there stays. Without the last line, `yars serve` logs a setup code at each start while there is no account, and the first visit to the website opens `/setup`, which asks for that code and creates the admin. Read the code in the service log (`journalctl -u yars`). A server that started with an account never opens `/setup`.

Both folders are `0700`: only the service account reads the findings and the backups. YARS writes its own folders `0700` and its files `0600`, and the commands that work on the data folder run git with a umask of `077`. A data folder made by an older YARS keeps the modes it has: a file gets the new mode when it is next saved, and `sudo chmod -R go= /srv/yars` closes the rest at once.

The umask is that of everything these commands start: rule scripts, script destinations and pandoc, as well as git. A file a script makes is `0600`, and a folder `0700`, also outside the data folder. A script whose files another account or a web server reads sets its own umask (`umask 022` at its start).

An account with the admin flag can add a rule or exporter script, and scripts run on the server as the service account, with its `HOME`. So an admin can run commands on the server. Give the flag only to people who may.

For a solo reporter or a team of two, `sudo -u yars yars init --simple /srv/yars` sets up the simple workflow instead: draft → complete → reported, with no roles, reviewers or sign-off; `useradd` then takes no `--role` (`yars useradd --data /srv/yars --admin alice`), and `yars role` is refused. The workflow is fixed at init: it is written to `.yars/config.yaml` and the database, `yars serve` does not start when the two disagree, and a push cannot change it. In the simple workflow every account has a director's rights, so the Team panel does not limit who sees an engagement: every account sees them all.

A new data folder has no check rules. Add the ones you want in Admin › Rules, or in a clone pushed by a director with the admin flag ([rules.md](rules.md)); a file put straight into the server's `.yars/rules/` is not in git.

Admin › System › Restore writes the restored folder next to the data folder, so it needs `/srv` writable by `yars`. With `/srv` owned by root, restore from the shell instead (see the restore drill).

## Run as a service

`/etc/systemd/system/yars.service`:

```ini
[Unit]
Description=YARS
After=network.target

[Service]
User=yars
Group=yars
ExecStart=/usr/local/bin/yars serve --data /srv/yars --addr 127.0.0.1:8080 --https
Restart=on-failure
# keys for Confluence and Jira destinations, the mail password and the AI
# key, under the names the settings give (the mail password and the AI key
# under names that start with YARS_); owned by root, mode 0600
EnvironmentFile=-/etc/yars/env
# the service writes to its data folder and its home, nowhere else
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/srv/yars /var/lib/yars
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

With `ProtectSystem=strict` the whole file system is read-only for the service, except the two `ReadWritePaths`. The home is there because pandoc, xelatex and scripts keep their caches in it. Admin › System › Restore writes next to the data folder, which this unit does not allow: restore from the shell (see the restore drill), or add the parent folder to `ReadWritePaths`. A script that writes elsewhere needs its folder added too.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now yars
journalctl -u yars -f
```

`--https` says a proxy in front serves HTTPS, so cookies are `Secure` and responses carry HSTS. A stop (`systemctl stop`) gives requests in flight and running checks 30 seconds each to finish.

## Confluence

A Confluence destination with a `base_url` publishes through Confluence's REST API. From the website each finding gets a page of its own. `yars export` does the same for a single finding; several go on one page, with the report sections, whose pictures are left out. A later send updates the same page.

A finding's pictures become attachments of the page and show where they stand in the text. Each is named after its finding and file, for example `F-003-shot.png`. A send uploads only the pictures that are new or changed: the attachment's comment holds the file's SHA-256.

A picture that is no longer in the page's text is deleted from the page once the new text is written. This covers a picture taken out of a finding, a finding renumbered, and a finding no longer on a `yars export` page. Confluence Cloud moves it to the space's trash. Attachments added in Confluence by hand stay.

The account behind the key needs permission, in the space, to view it, add pages, add attachments and delete attachments. Without adding, a send with pictures fails with `confluence upload of F-003-shot.png failed: HTTP 403 …`. An existing page then keeps its old text; a new one stays empty. Without deleting, a send that drops a picture fails with `confluence delete of F-003-shot.png failed: HTTP 403 …`. The page then has its new text, and the picture stays attached until it is deleted in Confluence.

The Confluence HTML download has no page to attach to: its pictures stay inside the file.

A Confluence or Jira destination sends its key and the findings to the destination's own address only. A redirect to another host, another port or from `https` to `http` is refused, and the send fails with `redirect to <host> refused`. Set the destination's `base_url` to the final address.

`yars export` writes a file destination's result to `--out`, or to the engagement's name in the current folder, readable by you alone (`0600`). It does not replace a file that is there: `--force` does. A device or a pipe (`--out /dev/stdout` into a pipe, `/dev/null`, a FIFO) is written into, with or without `--force`.

## HTTPS

Put a reverse proxy in front, or let YARS serve TLS itself.

**Caddy** (gets and renews the certificate):

```
yars.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

**nginx:**

```nginx
server {
    listen 443 ssl;
    server_name yars.example.com;
    ssl_certificate     /etc/ssl/yars/fullchain.pem;
    ssl_certificate_key /etc/ssl/yars/privkey.pem;

    # YARS sets its own limits (a push up to 2 GiB, a restore upload up to
    # 16 GiB); bodies pass through unbuffered so they reach it as sent
    client_max_body_size 0;
    proxy_request_buffering off;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        # the client's address, for the failed-login lines of the service log
        proxy_set_header X-Forwarded-For $remote_addr;
        # Run integrity (git fsck) and a push being checked answer nothing
        # for a while
        proxy_read_timeout 1h;
    }
}
```

The proxy must keep the `Host` header: YARS refuses cross-origin form posts by it. YARS does not read `X-Forwarded-Proto`. The clone and MCP addresses on the pages come from `base_url` (below). Without `base_url` they use the request's `Host` header, with `https` only when the server runs with `--https` or a certificate; `yars serve` then logs at the start that `base_url` is not set. The live-update stream asks nginx not to buffer it (`X-Accel-Buffering: no`) and sends a ping every 25 seconds.

Set the address people use in `.yars/config.yaml`, so links in mail and webhooks are whole and the pages show the right clone and MCP addresses:

```yaml
base_url: https://yars.example.com
```

The file is in the main repository: a director with the admin flag changes it in a clone and pushes it (in the simple workflow every account is a director; see [config.md](config.md)). An edit made in place on the server is undone at the next start, which resets the data folder's tree to its last commit.

**Without a proxy:**

```sh
yars serve --data /srv/yars --addr :443 --tls-cert /etc/ssl/yars/fullchain.pem --tls-key /etc/ssl/yars/privkey.pem
```

Binding port 443 needs `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the unit, and the `yars` account must be able to read the key. The certificate is read at the start: restart the service after renewing it. A certificate that does not load stops the start before anything changes.

## Sessions

A login ends when it is not used for the number of days set under Admin › System › Retention (Sessions): 14 by default, and 0 means 14 too. It ends 30 days after the login at the latest, however much it is used. The session cookie lives as long as its session.

## Backup

A git clone holds the findings only. Accounts, workflow state, reviewers, chat and check results are in the server's database, so back up with `yars backup`. It works while the server runs.

```
# crontab of the yars account: every night at 02:30
30 2 * * * /usr/local/bin/yars backup --data /srv/yars --out /backups/yars-$(date +\%F).zip
# and at 03:30, delete the backups older than 30 days
30 3 * * * find /backups -name 'yars-*.zip' -mtime +30 -delete
```

(cron needs the `%` escaped.) Add `--key` to include the key that decrypts the stored AI and personal keys and the webhook secrets; keep such a backup as safe as the server. Admin › System shows the last backup and can download one.

A backup on the same disk is lost with the server. Copy the files to another machine as well, for example with `rsync` from there. A backup holds every finding, and with `--key` the stored keys: the copy needs the same care as the server.

### Restore drill

Try a restore now and then, on the same server, without touching the live one:

```sh
sudo install -d -o yars -g yars -m 0700 /srv/yars-restored
sudo -u yars yars restore --from /backups/yars-2026-11-11.zip --data /srv/yars-restored
sudo -u yars yars serve --data /srv/yars-restored --addr 127.0.0.1:8081
```

A restore always goes into a new (or empty) folder and checks it before it reports success. It takes no git hook from the ZIP, and of each repository's git config only the basic settings; the server writes its own settings and its push hook at the next start. A hook or git setting added by hand on the old server must be added again. Open the second server (an SSH tunnel to port 8081 will do) and compare Admin › System's counts of engagements and findings with the live server's. Then stop it and remove the folder (`sudo rm -r /srv/yars-restored`).

## Upgrade

```sh
yars version                      # the running release and its schema
sudo systemctl stop yars
sudo cp /usr/local/bin/yars /usr/local/bin/yars.previous
sudo install -m 0755 yars /usr/local/bin/yars
yars version                      # the new release and its schema
sudo systemctl start yars
```

At the start the database is brought up to the new schema. When the schema changes, a copy is kept next to it first, `/srv/yars/.yars/yars.db.before-v<old schema>` (the two newest copies are kept). The git repositories need nothing.

**Going back:** when the two `yars version` lines show the same schema, put `yars.previous` back as `/usr/local/bin/yars` and restart. When the schema changed:

1. Stop the service.
2. Put `yars.previous` back as `/usr/local/bin/yars`.
3. Replace `.yars/yars.db` with `yars.db.before-v<old schema>`, and delete `.yars/yars.db-wal` and `.yars/yars.db-shm`.
4. Start the service.

Changes to the database made since the upgrade (chat, workflow state, accounts) are lost; findings in git are not. A newer database refuses to open with an older binary, so the copy is needed.

## Health

Admin › System:

- **Health** lists, row by row, the rules, the destinations, pandoc and the PDF engine, the repositories the git server serves, the AI provider, the free disk space, and the database.
- **Run integrity** runs the full checks: the database's `integrity_check`, `git fsck` on every repository, and a test call to the AI provider.
- **Server** shows the version, the uptime, the database size and the counts.
- **Operations** has the schema and the last index build. Its buttons sync the engagement pointers, rebuild the index and list what still needs `yars migrate`.
- **Current state** shows what the server does now: the checks running and queued, the fixes running, the webhook deliveries waiting, the mails being sent, the open event streams by account, and each repository lock that is held or waited for.
- **Log** shows the last 200 warnings and errors of the service log, newest first, and has the switch **Debug level for 15 minutes**.

The same state is on the command line (see [Logs](#logs)):

```sh
sudo -u yars yars status --data /srv/yars
```

## Logs

YARS writes its log to stderr. The journal of systemd keeps it. YARS writes no log file and rotates nothing.

```sh
journalctl -u yars -f                                  # follow the log
journalctl -u yars --since "1 hour ago"
journalctl -u yars | grep -E 'level=(WARN|ERROR)'      # warnings and errors
journalctl -u yars | grep req=4f2a9c1b                 # the lines of one request
```

### Format and levels

A line is `time=… level=… msg=… key=value …`. A value with a space is in quotes. With `log.format: json` a line is one JSON object ([config.md](config.md)).

`log.level` sets the lowest level written. The default is `info`.

| Level | For | Examples |
|---|---|---|
| `error` | a request or a job failed; someone should look | a commit failed, a template error, a check run crashed |
| `warn` | it went on, but not as it should | a failed login, a failed AI call, a webhook tried again, a slow request |
| `info` | one line for each thing that happened | a request, a check run, an export, a push, start and stop |
| `debug` | detail for one problem | static files, the heartbeat of a live stream |

The same field has the same name on every line:

| Field | Holds |
|---|---|
| `req` | the request's ID, 8 characters |
| `user` | the account's username |
| `token` | the ID of the token used, never its value |
| `eng` | the engagement's ID |
| `finding` | the finding's ID, such as `F-002` |
| `route` | the route's pattern, never the address with its query |
| `status` | the HTTP status |
| `ms` | the time taken, in milliseconds |
| `err` | what failed |

A line never holds finding text, a title, chat, a reason, a file's name, a password, a token's value, a key, an AI prompt or answer, a request body or a query string. It holds IDs and usernames. An error's text is cleaned the same way. There is one exception: the setup code of a first start.

### One request, one line

```
time=2026-11-26T14:00:03.000Z level=INFO msg=request req=4f2a9c1b method=GET route="GET /e/{eng}/f/{fid}" status=200 ms=12 user=alice eng=acme finding=F-002
```

The website, the git endpoint and MCP each write this line. A request over 2 seconds is a `warn` line.

Every response carries the ID as the `X-Request-ID` header. An internal error shows it on the page and in the toast: `Request 4f2a9c1b`. The error's own line has the same `req`, so one `grep` finds both.

### Background work

Each job writes one line when it ends, with `ms` and its outcome.

| `msg` | When |
|---|---|
| `yars serving` | the start: version, schema, workflow, address, and whether AI, SMTP and pandoc are on |
| `yars stopping`, `yars stopped` | the stop |
| `check run finished` | a check run ended: its state and the counts of errors and warnings |
| `check run crashed` | a check run failed inside the server (`error`) |
| `fix with AI finished` | a Fix with AI ended: how many were fixed |
| `ai call finished`, `ai call failed` | one call to the AI provider: the rule, the model, the tokens (`warn` when it failed) |
| `export finished` | a download or a send: the destination's ID and the counts (`warn` when a finding failed) |
| `webhook delivered` | a webhook delivery arrived |
| `webhook delivery failed; it is tried again` | a delivery failed and waits for its next try (`warn`) |
| `webhook delivery given up` | the last try failed (`warn`) |
| `webhook delivery dropped` | the webhook was turned off with this delivery waiting |
| `notification email sent`, `notification email not sent` | one mail; a refusal is named by its SMTP code (`warn`) |
| `push accepted`, `push refused` | a git push, with who pushed |
| `backup downloaded` | a backup download from Admin › System |
| `retention: the daily prune finished` | the daily prune, with what it deleted |
| `lock: a long wait for a repository's lock` | a write waited over 5 seconds for another one (`warn`) |

A webhook delivery that got no HTTP answer has `status=0` and one word in `err`: `no answer`, `redirect refused`, `secret`, `address`, `removed`, `disabled` or `database`. The line never holds the webhook's address.

### Failed logins

One `warn` line for each failed password login, on the website and over git, and one when a name is locked out:

```
time=2026-11-26T14:00:03.000Z level=WARN msg="login failed" user=alice remote=127.0.0.1:53412 forwarded_for=203.0.113.9 req=7c1e0b3a
time=2026-11-26T14:00:03.000Z level=WARN msg="git login failed" user=alice remote=127.0.0.1:53418 forwarded_for=203.0.113.9 req=0d5f9a21
time=2026-11-26T14:00:03.000Z level=WARN msg="login locked" user=alice until=2026-11-26T14:15:00Z
```

`remote` is the address that connected: behind a proxy, the proxy's. `forwarded_for` is the `X-Forwarded-For` header, written only when the server runs with `--https` or a certificate. A client can send that header too: trust it only when your proxy sets it, as the nginx example does. `user` is what was typed, cut at 64 characters; a name with a space or a quote is in quotes.

### fail2ban

An example filter. The name comes before the address and is the client's own text, so the pattern reads it as a whole, quoted or not.

`/etc/fail2ban/filter.d/yars.conf`:

```ini
[INCLUDES]
before = common.conf

[Definition]
_daemon = yars
failregex = ^%(__prefix_line)stime=\S+ level=WARN msg="(?:git )?login failed" user=(?:"(?:[^"\\]|\\.)*"|[^\s"=]+) remote=<HOST>:\d+(?: |$)
```

`/etc/fail2ban/jail.d/yars.conf`:

```ini
[yars]
enabled = true
backend = systemd
journalmatch = _SYSTEMD_UNIT=yars.service
ignoreip = 127.0.0.1/8 ::1
```

Behind a proxy `remote` is the proxy. Keep the proxy in `ignoreip`, and match `forwarded_for` instead. Do this only when the proxy sets the header itself, as the nginx example does: a proxy that adds to the client's header passes on what the client claimed.

```ini
failregex = ^%(__prefix_line)stime=\S+ level=WARN msg="(?:git )?login failed" user=(?:"(?:[^"\\]|\\.)*"|[^\s"=]+) remote=\S+ forwarded_for=<HOST>(?: |$)
```

Test a filter before you rely on it: `fail2ban-regex systemd-journal /etc/fail2ban/filter.d/yars.conf`.

### What the server does now

```sh
sudo -u yars yars status --data /srv/yars
```

It prints the version, the schema, the uptime, the log level, the checks running and queued, the webhook deliveries waiting, the open event streams, the repository locks, and the last 200 warnings and errors. It asks the running server over a socket in the data folder (`.yars/status.sock`) that only the service account opens: run it as that account. It needs no password, and it answers when the database is locked.

Admin › System shows the same in **Current state** and **Log**. The 200 lines are kept in memory: they are lost at a restart, and the journal has every line.

### Debug for 15 minutes

Admin › System › Log has the switch **Debug level for 15 minutes**. It sets the log to `debug` without a restart and shows when it ends. After 15 minutes the level is the one the server started with. Each change is in Admin › Activity as `system.debug`. It changes the level only: a `debug` line holds no more text than any other line.

## Uninstall

Take the data out first:

```sh
sudo -u yars yars backup --data /srv/yars --key --out /backups/yars-final.zip
sudo install -m 0600 /backups/yars-final.zip /root/yars-final.zip
```

The ZIP holds everything: the repositories, the database and, with `--key`, the key for the stored secrets. `yars restore` on any server brings it back. For the findings alone, a clone is enough ([git.md](git.md)): each finding is a Markdown file.

The second line puts a copy in root's home, outside every folder removed below. Then remove YARS:

```sh
sudo systemctl disable --now yars
sudo rm -f /etc/systemd/system/yars.service /usr/local/bin/yars /usr/local/bin/yars.previous
sudo rm -r /srv/yars
sudo rm -rf /etc/yars
sudo crontab -r -u yars
sudo userdel --remove yars
```

`userdel --remove` deletes the account's home, `/var/lib/yars`, too. `crontab -r` reports an error when the account had no crontab; go on.

The backup folder goes last, once the final ZIP is on another machine and a restore from it worked there:

```sh
sudo rm -r /backups
```

Revoke the keys YARS used at Confluence, Jira, the mail server and the AI provider.
