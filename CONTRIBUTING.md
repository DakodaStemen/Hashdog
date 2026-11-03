# Contributing

`main` stays stable. Work happens on branches and lands through a pull request. Run `make ci` before you push.

## Setup

Needs Go (the version in `go.mod`) and shellcheck.

```sh
make setup   # go mod download
make help    # list targets
```

## Branches and pull requests

| Prefix | Use |
| :---- | :---- |
| `feat/...` | New features |
| `fix/...` | Bug fixes |
| `docs/...` | Documentation |
| `chore/...` | Tooling and repository hygiene |
| `ci/...` | Workflow changes |
| `test/...` | Tests only |

- PR titles follow Conventional Commits, matching the prefix: `feat: add ...`, `fix: ...`.
- One purpose per PR. Fill in `.github/PULL_REQUEST_TEMPLATE.md`.
- Commit messages state what changed and why. Weak: `updated files`. Strong: `fix: reject baselines signed with a different key before reading entries`.

## Running tests and lint

```sh
make lint    # gofmt, go vet, shellcheck (errors only) on bench/ and docs/ scripts
make test    # go test -race -count=1 ./...
make build   # builds ./hashdog
make ci      # lint + test + build
```

## Rules

- Keep the exit codes in the README table stable; add a test when you change one.
- A change to the baseline format needs a format version bump and a test for the old format.
- Never commit signing keys (`*.key` is ignored) or real file inventories from a production host.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).
