# Deploy, back up, upgrade

Running YARS for a team: one server, one data folder, a proxy for HTTPS.

## Requirements

- **git**, on the server's `PATH`. YARS keeps every engagement in a git repository and serves clones and pushes itself.
- **Go 1.27.2 or later**, to build the binary.
- **pandoc** (optional), for the PDF, Word and other pandoc downloads and destinations. Without it, those are refused; the ZIP downloads and the Confluence HTML destination still work.
  - Some packaged pandoc builds cannot load their own data files under `--sandbox`. YARS then runs pandoc without the sandbox: what it is given is already sanitised, and images are already inlined. A static release from pandoc's website keeps the sandbox.
- **xelatex** (optional), for PDF: the report theme is a LaTeX template. It needs the LaTeX packages fontspec, xcolor, geometry, graphicx, longtable, booktabs, array, calc, etoolbox, fancyhdr, fvextra and hyperref, and looks as designed with the IBM Plex fonts installed (else TeX Gyre). Without xelatex, PDFs fail with pandoc's message, and the other formats still work.

## Install

```sh
go build -ldflags "-X main.version=v1.0.0" -o yars ./cmd/yars
sudo install -m 0755 yars /usr/local/bin/yars
yars version
```

`yars version` prints the version, the database schema it writes and the Go release, for example `yars v1.0.0 (schema 22, go1.27.2)`. Built without `-ldflags`, it shows the git revision instead.

Create the account the service runs as, its data folder and the backup folder:

```sh
sudo useradd --system --user-group --home-dir /var/lib/yars --create-home --shell /usr/sbin/nologin yars
sudo install -d -o yars -g yars /srv/yars
sudo install -d -o yars -g yars -m 0700 /backups
sudo -u yars yars init /srv/yars
echo 'change-me' | sudo -u yars yars useradd --data /srv/yars --role director --admin alice
```

The account's home is outside the data folder: rule and exporter scripts run with it as `HOME`, and anything in the data folder goes into every backup. The last line makes the first admin; the password is read from standard input. Without it, the first visit to the website opens `/setup` to create one.

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
# key, under the names the settings give (CONFLUENCE_*, JIRA_*, …)
EnvironmentFile=-/etc/yars/env

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now yars
journalctl -u yars -f
```

`--https` says a proxy in front serves HTTPS, so cookies are `Secure` and responses carry HSTS. A stop (`systemctl stop`) gives requests in flight and running checks 30 seconds each to finish.

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
        # Run integrity (git fsck) and a push being checked answer nothing
        # for a while
        proxy_read_timeout 1h;
    }
}
```

The proxy must keep the `Host` header (YARS refuses cross-origin form posts by it, and builds clone URLs from it) and send `X-Forwarded-Proto`. The live-update stream asks nginx not to buffer it (`X-Accel-Buffering: no`) and sends a ping every 25 seconds.

Set the address people use in `.yars/config.yaml`, so links in mail and webhooks are whole:

```yaml
base_url: https://yars.example.com
```

The file is in the main repository: a director changes it in a clone and pushes it (see `docs/config.md`). An edit made in place on the server is undone at the next start, which resets the data folder's tree to its last commit.

**Without a proxy:**

```sh
yars serve --data /srv/yars --addr :443 --tls-cert /etc/ssl/yars/fullchain.pem --tls-key /etc/ssl/yars/privkey.pem
```

Binding port 443 needs `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the unit, and the `yars` account must be able to read the key. The certificate is read at the start: restart the service after renewing it. A certificate that does not load stops the start before anything changes.

## Backup

A git clone holds the findings only. Accounts, workflow state, reviewers, chat and check results are in the server's database, so back up with `yars backup`. It works while the server runs.

```
# crontab of the yars account: every night at 02:30
30 2 * * * /usr/local/bin/yars backup --data /srv/yars --out /backups/yars-$(date +\%F).zip
```

(cron needs the `%` escaped.) Add `--key` to include the key that decrypts the stored AI and personal keys; keep such a backup as safe as the server. Admin › System shows the last backup and can download one.

### Restore drill

Try a restore now and then, on the same server, without touching the live one:

```sh
sudo install -d -o yars -g yars /srv/yars-restored
sudo -u yars yars restore --from /backups/yars-2026-11-11.zip --data /srv/yars-restored
sudo -u yars yars serve --data /srv/yars-restored --addr 127.0.0.1:8081
```

A restore always goes into a new (or empty) folder and checks it before it reports success. Open the second server (an SSH tunnel to port 8081 will do) and compare Admin › System's counts of engagements and findings with the live server's. Then stop it and remove the folder (`sudo rm -r /srv/yars-restored`).

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

The service log (`journalctl -u yars`) has every error the pages answered with "internal error".
