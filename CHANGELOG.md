# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The repository has no version tags yet.

## [Unreleased]

### Added

- 2026-11-03: Engineering baseline: `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, PR and issue templates, `.editorconfig`, `.gitattributes`, markdownlint config, pre-commit config, `docs/adr/` with ADR-0001, and a `Makefile` with `setup`, `lint`, `test`, `build` and `ci`.
- 2026-11-03: CI runs a docs lint job and `make lint` (gofmt, go vet, shellcheck).

### Changed

- 2026-11-03: CI workflow gets `concurrency`, job timeouts and no persisted checkout credentials. Dependabot is now weekly (gomod) and monthly (Actions), grouped, one open PR each, 7-day cooldown.
