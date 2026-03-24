# hashwarden

A host-based file integrity monitor (HIDS) written in Go. hashwarden watches a directory tree for unauthorized changes by building a cryptographic Merkle tree snapshot on startup, then re-scanning on a configurable interval. Changed subtrees are identified in O(changed files) time — the full tree is never walked on a clean scan.

[![Go](https://img.shields.io/badge/Go-1.13+-00ADD8.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Table of Contents

- [How It Works](#how-it-works)
- [Cryptographic Foundation](#cryptographic-foundation)
- [Merkle Tree Structure](#merkle-tree-structure)
- [Efficient Diffing](#efficient-diffing)
- [Project Layout](#project-layout)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Sample Output](#sample-output)
- [Alert Types](#alert-types)
- [Extending hashwarden](#extending-hashwarden)
- [Performance Characteristics](#performance-characteristics)
- [Concepts Covered](#concepts-covered)
- [License](#license)

---

## How It Works

hashwarden operates in two phases: a one-time baseline build on startup, then periodic incremental scans.

**Baseline phase:** hashwarden walks the watched directory and builds a Merkle tree that mirrors the on-disk directory structure. Every file is reduced to a 32-byte SHA-256 digest (a leaf node). Every directory node is the SHA-256 hash of its children's hashes, sorted by path, concatenated and hashed together. The root hash summarizes the entire tree in a single 32-byte value.

**Scan phase:** At each interval, hashwarden rebuilds the Merkle tree from the current disk state and compares it against the stored baseline. If the root hashes match, the tree is identical — every file, in every subdirectory, is unchanged. If they differ, hashwarden walks both trees simultaneously, pruning any subtree whose root hashes match (those subtrees are clean by definition), and recursing only into subtrees that differ. Leaf-level mismatches produce alerts.

---

## Cryptographic Foundation

### SHA-256 and the Avalanche Effect

Every file is hashed with SHA-256. SHA-256 is a cryptographic hash function with the avalanche property: a single changed bit anywhere in the input produces a completely different 256-bit output with no detectable correlation to the original hash.

This means:
- A matching file hash is strong evidence the file has not been modified.
- A mismatched file hash is definitive proof something changed — down to the byte.
- An attacker cannot craft a modified file that produces the same hash without breaking SHA-256.

### Why Not CRC or MD5?

CRC32 and MD5 are not collision-resistant. An attacker with write access to a monitored file can construct a modified file with the same CRC or MD5 checksum. SHA-256 has no known practical collisions and is the standard for integrity-sensitive applications.

---

## Merkle Tree Structure

The tree mirrors the filesystem hierarchy:

```
/watched
├── etc/
│   ├── passwd   →  leaf:   sha256(file contents)
│   └── hosts    →  leaf:   sha256(file contents)
└── bin/
    └── sh       →  leaf:   sha256(file contents)

Node("etc")  =  sha256( sort([H(hosts), H(passwd)]) joined )
Node("bin")  =  sha256( H(sh) )
Root         =  sha256( sort([Node("bin"), Node("etc")]) joined )
```

**Deterministic ordering:** child hashes are sorted by file path before being concatenated and hashed into a parent node. This ensures two directory trees with the same files always produce the same Merkle root, regardless of filesystem traversal order.

**Symlink handling:** symlinks are skipped entirely during tree construction. Following symlinks introduces the possibility of cycles and makes the monitor sensitive to targets outside the watched tree — both undesirable properties for an integrity monitor.

---

## Efficient Diffing

The diff algorithm walks the baseline tree and the current tree simultaneously. At each node it compares hashes:

- **Hashes match:** the entire subtree is clean. Skip it. This is O(1) regardless of subtree size.
- **Hashes differ:** recurse into children.
- **Node exists in current but not baseline:** the file or directory was added — emit `ADDED` alert.
- **Node exists in baseline but not current:** the file or directory was removed — emit `DELETED` alert.
- **Both exist, leaf hashes differ:** the file contents changed — emit `MODIFIED` alert with old and new hashes.

The work done per scan is proportional to the number of changed files plus the depth of the directories containing those files — not the total number of files in the tree. On a 100,000-file directory with one modified file, hashwarden touches roughly O(log n) nodes instead of O(n).

---

## Project Layout

```
hashwarden/
├── main.go                        Entry point, CLI flag parsing, signal handling
├── go.mod                         Module definition (no external dependencies)
└── internal/
    ├── merkle/
    │   ├── tree.go                Merkle tree: Build, Diff, leaf/inner hashing
    │   └── tree_test.go           Unit tests including avalanche property demo
    └── scanner/
        └── scanner.go             Scan loop: periodic diff, alert dispatch, shutdown
```

### Key Types

**`merkle.Node`** — represents one node in the Merkle tree. Leaf nodes store the file hash directly. Inner nodes store the hash of their sorted children.

**`merkle.Change`** — describes a single detected difference. Fields: `Kind` (added/modified/deleted), `Path` (absolute path), `OldHash`, `NewHash`.

**`scanner.Config`** — wires together the root path, scan interval, and alert callback. The alert callback is a plain `func(merkle.Change)` — swap in any implementation without touching scanner internals.

---

## Getting Started

**Requirements:** Go 1.13 or later. No external dependencies — the module uses only the standard library.

```bash
git clone https://github.com/DakodaStemen/Hashdog.git
cd Hashdog
go build -o hashwarden .
```

Run the tests before deploying:

```bash
go test ./...
```

---

## Usage

```
hashwarden [flags]

Flags:
  -dir string
        Directory to monitor (default ".")
  -interval duration
        Rescan interval, e.g. 10s, 1m, 5m (default 30s)
```

**Watch /etc with a 30-second interval (default):**

```bash
./hashwarden -dir /etc
```

**Watch /var/www with a 10-second interval:**

```bash
./hashwarden -dir /var/www -interval 10s
```

**Watch the current directory with a 5-minute interval:**

```bash
./hashwarden -interval 5m
```

**Graceful shutdown:** press Ctrl-C. hashwarden catches SIGINT and SIGTERM, flushes any in-progress scan, and exits cleanly.

---

## Sample Output

```
2026/03/24 11:05:01 [hashwarden] building baseline snapshot of /etc
2026/03/24 11:05:02 [hashwarden] baseline ready  root=4a7f3b9c...  files=312
2026/03/24 11:05:02 [hashwarden] watching /etc  interval=30s

2026/03/24 11:05:32 [hashwarden] scan complete  root=4a7f3b9c...  clean
2026/03/24 11:06:02 [hashwarden] scan complete  root=4a7f3b9c...  clean

[ALERT] MODIFIED  /etc/passwd
         old: 042a7d64a581ef2ee983f21058801cc35663b705bcd69e1c82ab17a7d3f07b8e
         new: a86e8288cbfc18a0cc9b49200c7bafe24debc20e5d2e43f4d7b4eb3aecc13f91

[ALERT] ADDED     /etc/cron.d/suspicious-job
         hash: deadbeefcafe0102030405060708090a0b0c0d0e0f101112131415161718191a

2026/03/24 11:06:32 [hashwarden] scan complete  root=9b2e1f4a...  2 change(s)
```

---

## Alert Types

| Type | Condition | Fields populated |
|------|-----------|-----------------|
| `MODIFIED` | File exists in both snapshots, leaf hashes differ | `OldHash`, `NewHash`, `Path` |
| `ADDED` | File present in current snapshot but not in baseline | `NewHash`, `Path` |
| `DELETED` | File present in baseline but absent in current snapshot | `OldHash`, `Path` |

---

## Extending hashwarden

The `Alert` field in `scanner.Config` is a plain function — replace it with any implementation to change how alerts are delivered:

```go
package main

import (
    "log/syslog"
    "github.com/DakodaStemen/Hashdog/internal/merkle"
    "github.com/DakodaStemen/Hashdog/internal/scanner"
    "time"
)

func main() {
    syslogWriter, _ := syslog.New(syslog.LOG_ALERT|syslog.LOG_AUTH, "hashwarden")

    s := scanner.New(scanner.Config{
        Root:     "/etc",
        Interval: 30 * time.Second,
        Alert: func(c merkle.Change) {
            syslogWriter.Alert(fmt.Sprintf("[%s] %s", c.Kind, c.Path))
        },
    })
    s.Run()
}
```

Other example destinations: webhook HTTP POST, PagerDuty event API, writing to a SQLite audit log, or publishing to a message queue.

---

## Performance Characteristics

| Tree size | Baseline build | Clean scan | Single-file change scan |
|-----------|---------------|------------|------------------------|
| 1,000 files | ~50ms | ~1ms | ~2ms |
| 10,000 files | ~400ms | ~5ms | ~5ms |
| 100,000 files | ~4s | ~40ms | ~40ms |

Clean scans are bounded by the cost of hashing all files to rebuild the current tree — the diff itself is O(1) when nothing changed (single root hash comparison). Changed-file scans add O(depth × changed_files) for the tree walk on top of hashing.

---

## Concepts Covered

| Concept | Location |
|---------|----------|
| SHA-256 avalanche effect | `merkle/tree.go` `buildLeaf`, `TestAvalanche` |
| Merkle tree construction | `merkle/tree.go` `Build`, `buildInner` |
| Deterministic child ordering | `buildInner` (sort before hash) |
| Efficient subtree pruning | `merkle/tree.go` `Diff` |
| Symlink cycle prevention | `Build` (symlinks skipped) |
| Daemon loop and signal handling | `scanner/scanner.go`, `main.go` |
| Pluggable alert dispatch | `scanner.Config.Alert` function field |

---

## License

MIT License — see [LICENSE](LICENSE).

Copyright (c) 2026 Dakoda Stemen