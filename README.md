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
