<p align="center"><img src="docs/assets/logo.svg" alt="YARS" width="280"></p>

<p align="center"><b>Yet Another Reporting System</b><br>Git-backed reporting for penetration tests.</p>

## Quick start

Requires Go 1.27.

```sh
go build -o yars ./cmd/yars
./yars init data
echo 'change-me' | ./yars useradd --data data --role director --admin alice
./yars serve --data data
```

Open <http://localhost:8080>. Further documentation is in [docs](docs).

## Default data folder

`./yars use data` makes `data` the default, so `--data` can be left out:
`./yars serve`, `./yars unlock alice`. `./yars use` shows the default and
where it comes from. `--data` wins over `YARS_DATA`, which wins over the
folder set with `yars use` (`data:` in `~/.config/yars/config.yaml`).
`yars seed` always needs `--data`.

`./yars unlock <user>` ends a user's login lockout (after 5 wrong
passwords), for when no admin can log in.

## Backup and restore

A git clone holds the findings only. Accounts, workflow state, reviewers,
chat and check results are in the server's database, so back up with:

    ./yars backup --out /backups/yars-$(date +%F).zip

Add `--key` to include the key that decrypts stored AI and personal keys.
Run it from cron; it works while the server runs.

    ./yars restore --from /backups/yars-2026-11-11.zip --data /srv/yars-restored
    ./yars serve --data /srv/yars-restored

A restore always goes into a new folder and checks it before it reports success.
