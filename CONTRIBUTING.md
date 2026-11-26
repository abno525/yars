# Contributing

## Before you start

- A bug or an idea: open an issue first. Small fixes can go straight to a pull request.
- A security problem: report it in private, see [SECURITY.md](SECURITY.md).
- Use made-up data in issues, tests and screenshots. Never a real finding, client name, host, engagement ID or token.

## Build and test

Needs Go 1.27.2 or later and git.

```sh
go build -o yars ./cmd/yars
go mod tidy -diff
test -z "$(gofmt -l .)"
go vet ./...
go test ./...
```

CI runs the same commands. The tests make git commits, so git needs a name, an email and `main` as the default branch:

```sh
git config --global user.name you
git config --global user.email you@example.com
git config --global init.defaultBranch main
```

The whole test run is heavy. While you work, run the package you touched: `go test ./internal/rules/`.

## Pull requests

- One change per pull request.
- A fix comes with a test that fails without it.
- Commit messages say what is now true: `fix(web): the switch keeps its size`.
- Behaviour that changes is changed in `docs/` too.
- Add a line to [CHANGELOG.md](CHANGELOG.md) under Unreleased.

## License

YARS is licensed under [AGPL-3.0](LICENSE). Your contribution is under the same license.
