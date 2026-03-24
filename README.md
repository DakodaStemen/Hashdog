# hashwarden

A host-based file integrity monitor (HIDS) written in Go.

hashwarden watches a directory tree for unauthorized changes. On startup it
builds a cryptographic snapshot of every file, then re-scans on a configurable
interval. Any modification, addition, or deletion is reported immediately as
an alert. Unchanged directories are skipped entirely, so the check stays fast
even on large trees.

---

## How it works

### Cryptographic hashing

Every file is reduced to a 32-byte SHA-256 digest. SHA-256 has the avalanche
property: a single changed bit anywhere in the file produces a completely
different digest. This means a matching hash is strong evidence that a file
has not been touched; a mismatched hash is definitive proof that something
changed.

### Merkle tree

hashwarden organizes file hashes into a Merkle tree that mirrors the directory
structure on disk.

```
/watched
├── etc/
│   ├── passwd   →  leaf: sha256(passwd contents)
│   └── hosts    →  leaf: sha256(hosts contents)
└── bin/
    └── sh       →  leaf: sha256(sh contents)

Node("etc")  =  sha256( H(hosts) + H(passwd) )   sorted by path
Node("bin")  =  sha256( H(sh) )
Root         =  sha256( Node("bin") + Node("etc") )
```

A change to any file changes its leaf hash, which changes every ancestor node
all the way to the root. Two identical directory trees always produce the same
root hash; two trees that differ in any way always produce different root
hashes.

### Efficient diffing

When the root hashes between two snapshots differ, hashwarden walks both trees
simultaneously. Any subtree whose root hashes already match is skipped in a
single comparison, no matter how many files it contains. Only changed branches
are explored. In practice this means the work done per scan is proportional to
the number of changed files, not the total size of the watched tree.

---

## Project layout

```
hashwarden/
├── main.go                   entry point, CLI flags, signal handling
├── go.mod
└── internal/
    ├── merkle/
    │   ├── tree.go           Merkle tree construction and diff
    │   └── tree_test.go      unit tests including avalanche demo
    └── scanner/
        └── scanner.go        periodic scan loop and alert dispatch
```

---

## Getting started

**Requirements:** Go 1.13 or later. No external dependencies.

```bash
git clone https://github.com/DakodaStemen/Hashdog.git
cd Hashdog
go build -o hashwarden .
```

**Watch a directory:**

```bash
./hashwarden -dir /etc -interval 30s
```

**Run the tests:**

```bash
go test ./...
```

---

## Usage

```
hashwarden [flags]

  -dir string
        directory to monitor (default ".")
  -interval duration
        rescan interval, e.g. 10s, 1m, 5m (default 30s)
```

Press Ctrl-C for a clean shutdown.

---

## Sample output

```
2026/03/24 11:05:01 [hashwarden] building baseline snapshot of /etc
2026/03/24 11:05:01 [hashwarden] baseline ready  root=4a7f3b...
2026/03/24 11:05:01 [hashwarden] watching /etc  interval=30s
2026/03/24 11:05:31 [hashwarden] clean  root=4a7f3b...
[ALERT] MODIFIED  /etc/passwd
         old: 042a7d64a581ef2ee983f21058801cc35663b705...
         new: a86e8288cbfc18a0cc9b49200c7bafe24debc20e...
[ALERT] ADDED     /etc/cron.d/malicious
         hash: deadbeef...
```

---

## Concepts covered

| Concept | Where |
|---|---|
| SHA-256 avalanche effect | `merkle/tree.go` `buildLeaf`, `TestAvalanche` |
| Merkle tree construction | `merkle/tree.go` `buildInner`, `innerHash` |
| Efficient subtree pruning | `merkle/tree.go` `diff` |
| Deterministic hashing | sorted children before hashing in `buildInner` |
| Symlink safety | skipped in `build` to avoid cycles |
| Daemon loop and signal handling | `scanner/scanner.go`, `main.go` |

---

## Extending hashwarden

The `Alert` type in `scanner` is a plain function — swap in any implementation
to change where alerts go:

```go
scanner.New(scanner.Config{
    Root:     "/etc",
    Interval: 30 * time.Second,
    Alert: func(c merkle.Change) {
        // write to syslog, send a webhook, page someone, etc.
    },
})
```
