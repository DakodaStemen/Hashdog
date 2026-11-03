# ADR-0001: Go with a small dependency set, SHA-256 Merkle tree and ed25519 baselines

| Field | Value |
| :---- | :---- |
| Status | Accepted |
| Date | 2026-11-03 |
| Deciders | @DakodaStemen |

## Context

The tool watches a directory tree, reports modified, added and removed files, and must detect a tampered baseline. It should ship as one static binary for Linux and macOS and run from systemd.

## Decision

- Write it in Go (module `github.com/DakodaStemen/custos`, `go` version in `go.mod`), built with `CGO_ENABLED=0` for release.
- Hash the tree into a SHA-256 Merkle tree (`internal/merkle`), which gives per-directory hashes and inclusion proofs.
- Sign baselines with ed25519 from the standard library (`internal/baseline`); the public key comes from outside the baseline file.
- Watch with fsnotify events plus a periodic full verify as a fallback (`internal/scanner`).
- Release through GoReleaser with a cosign-signed checksum file.

## Alternatives considered

| Alternative | Why not chosen |
| :---- | :---- |
| Flat list of file hashes | No directory hashes and no inclusion proofs |
| Polling only | Slow to alert; events plus periodic verify gives both |
| Rust or C | Go gives a static binary and a standard crypto library with less code |

## Consequences

**Positive**

- One binary, tests with `go test -race`, `make ci` reproduces CI.
- A modified baseline is rejected (exit code 2).

**Negative**

- The stat cache trades certainty for speed on event scans; `-paranoid` disables it (see the README limitations).
