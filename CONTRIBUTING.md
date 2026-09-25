# Contributing

Issues and pull requests are welcome. For anything beyond a small fix, please
open an issue first to agree the approach. Security problems: see
[SECURITY.md](SECURITY.md) — please don't open a public issue.

## Development

```sh
git config core.hooksPath .githooks   # Conventional Commits check on commit
go test -race ./...                   # library
(cd examples/demo && go test ./...)   # demo (its own module)
```

The demo module resolves the library from this tree via a `replace` directive;
a local `go.work` covering both modules also works (it is gitignored).

## Checks

`main` is protected by a repository ruleset: changes land only through pull
requests, squash-merged (linear history, no force pushes or deletion), and
require passing checks — `commit-lint` plus [`ci.yml`](.github/workflows/ci.yml)
(`gofmt`, `go mod tidy`, `go vet`, staticcheck, build, `go test -race`,
govulncheck for both modules; a no-push build of the demo image; actionlint).

## Commit messages

Commit messages and PR titles follow [Conventional Commits](https://www.conventionalcommits.org/):
`<type>(<scope>)?!?: <summary>`, with type one of `build`, `chore`, `ci`,
`docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style` or `test`, e.g.
`feat(myinfo): expose container-level source`. The rule lives in
[`scripts/check-commit-msg.sh`](scripts/check-commit-msg.sh) and is enforced
in three places:

- **Locally** — enable the bundled `commit-msg` hook once per clone:
  `git config core.hooksPath .githooks`.
- **Pull requests** — [`commit-lint.yml`](.github/workflows/commit-lint.yml)
  checks the PR title and every commit. PRs are squash-merged with the PR title
  as the commit subject.
- **Pushes to `main`** — the `commit-lint` job in
  [`deploy.yml`](.github/workflows/deploy.yml) re-checks the pushed commits (and
  `deploy.yml` re-runs `ci.yml`) before deploying.

## Releases

Releases are automated by [release-please](https://github.com/googleapis/release-please)
([`release-please.yml`](.github/workflows/release-please.yml)). From the
Conventional Commits on `main` it keeps a release PR open that bumps the
version and updates `CHANGELOG.md`; merging it tags `vX.Y.Z` (the Go module
version) and publishes a GitHub release. Before 1.0, `feat` bumps the minor
version, `fix` the patch, and breaking changes (`!` / `BREAKING CHANGE:`) the
minor. Changes only under `examples/` don't trigger a library release. To force
a version, add a `Release-As: X.Y.Z` footer to a commit.

## Dependencies

[Dependabot](.github/dependabot.yml) opens weekly update PRs (plus security
updates) for Go modules, GitHub Actions and the demo's Docker images. Library
dependency bumps are titled `fix(deps): …`, so they produce a patch release;
demo, Actions and Docker bumps are `chore(deps): …` and don't.
