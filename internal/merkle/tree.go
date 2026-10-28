// Package merkle builds a Merkle tree over a directory and can diff two
// trees to find exactly which files changed.
//
// How it works
// ------------
// Every file is a leaf node whose value is the SHA-256 hash of its contents.
// Every directory is an inner node whose value is the SHA-256 hash of its
// children's hashes, concatenated in sorted path order.  The root hash is
// therefore a single 32-byte fingerprint of the entire watched tree.
//
// Because SHA-256 has the avalanche property, a single changed byte anywhere
// in any file produces a completely different leaf hash, which propagates up
// through every ancestor node to the root.  That means:
//
//   - Two identical trees always produce the same root hash.
//   - Two trees that differ in any way always produce different root hashes.
//
// The diff walks both trees simultaneously and prunes any subtree whose root
// hashes already match, so only the changed branches are visited.
//
// Example layout:
//
//	/watched
//	├── etc/
//	│   ├── passwd   → leaf H(passwd)
//	│   └── hosts    → leaf H(hosts)
//	└── bin/
//	    └── sh       → leaf H(sh)
//
//	Node("etc")  = H( H(hosts) ++ H(passwd) )   // sorted by path
//	Node("bin")  = H( H(sh) )
//	Root         = H( Node("bin") ++ Node("etc") )
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

// Kind distinguishes a file leaf from a directory inner node.
type Kind int

const (
	File Kind = iota
	Dir
)

// Node is a single vertex in the Merkle tree.
// File nodes are leaves; directory nodes are inner nodes whose hash is
// derived from their children.
type Node struct {
	Path     string   // absolute path on disk
	Hash     [32]byte // SHA-256 of contents (file) or children hashes (dir)
	Kind     Kind
	Children []*Node

	// Stat metadata for file leaves, used only by the optional rehash cache
	// (see Options). Never part of the hash.
	Size    int64
	ModTime int64     // UnixNano
	Hashed  time.Time // when the contents were actually read and hashed
}

// HexHash returns the hash as a lowercase hex string, useful for log output.
func (n *Node) HexHash() string {
	return hex.EncodeToString(n.Hash[:])
}

// racyWindow: a file whose mtime is within this window of the moment it was
// last hashed could have been modified again without changing its mtime, so
// the cache never trusts it (same idea as git's "racily clean" entries).
const racyWindow = 2 * time.Second

// Options tunes Build.
type Options struct {
	// Prev, when non-nil, enables a stat-based rehash cache: a file whose
	// size and mtime match its entry in Prev (and is not racily clean) reuses
	// the old hash instead of being read again. This is fast but is NOT a
	// full verification, since an attacker can restore mtime. Leave nil for a
	// full verify.
	Prev *Node
}

// Build walks root and returns the Merkle tree for that directory, reading
// and hashing every file. Symlinks are skipped; following them risks cycles
// and blurs the boundary of what is actually being monitored.
func Build(root string) (*Node, error) { return BuildWith(root, Options{}) }

// BuildWith is Build with options.
func BuildWith(root string, opt Options) (*Node, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	b := &builder{sem: make(chan struct{}, runtime.NumCPU())}
	if opt.Prev != nil {
		b.prev = map[string]*Node{}
		collectLeaves(opt.Prev, func(n *Node) { b.prev[n.Path] = n })
	}
	return b.build(root, info)
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 256<<10); return &b }}

type builder struct {
	prev map[string]*Node
	sem  chan struct{} // bounds concurrent file reads/hashes
}

func (b *builder) build(path string, info os.FileInfo) (*Node, error) {
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil
	}
	if info.IsDir() {
		return b.buildInner(path)
	}
	if !info.Mode().IsRegular() {
		return nil, nil // sockets, devices, FIFOs: reading could block
	}
	return b.buildLeaf(path, info)
}

// buildLeaf hashes the raw byte contents of a regular file (streamed).
// SHA-256's avalanche property means even a single changed byte produces
// a completely different 32-byte digest, making silent tampering detectable.
func (b *builder) buildLeaf(path string, info os.FileInfo) (*Node, error) {
	mt := info.ModTime().UnixNano()
	if p, ok := b.prev[path]; ok && p.Size == info.Size() && p.ModTime == mt &&
		p.Hashed.Sub(info.ModTime()) > racyWindow {
		c := *p
		return &c, nil
	}
	b.sem <- struct{}{}
	defer func() { <-b.sem }()
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	if _, err := io.CopyBuffer(struct{ io.Writer }{h}, struct{ io.Reader }{f}, *bp); err != nil {
		return nil, err
	}
	n := &Node{Path: path, Kind: File, Size: info.Size(), ModTime: mt, Hashed: time.Now()}
	copy(n.Hash[:], h.Sum(nil))
	return n, nil
}

// buildInner recursively builds child nodes, then hashes their digests.
// Children are sorted by path before hashing so the result is deterministic
// regardless of the readdir order returned by the OS.
func (b *builder) buildInner(path string) (*Node, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	node := &Node{Path: path, Kind: Dir}

	// Children are built concurrently (file hashing is bounded by b.sem);
	// results land in a fixed slot so ordering stays deterministic.
	results := make([]*Node, len(entries))
	var wg sync.WaitGroup
	for i, e := range entries {
		wg.Add(1)
		go func(i int, e os.DirEntry) {
			defer wg.Done()
			cp := filepath.Join(path, e.Name())
			info, err := e.Info()
			if err != nil {
				results[i] = errorNode(cp, err)
				return
			}
			child, err := b.build(cp, info)
			if err != nil {
				// One unreadable file should not abort the entire scan.
				// Use a sentinel hash so the path still shows up in diffs.
				child = errorNode(cp, err)
			}
			results[i] = child
		}(i, e)
	}
	wg.Wait()
	for _, c := range results {
		if c != nil {
			node.Children = append(node.Children, c)
		}
	}

	sort.Slice(node.Children, func(i, j int) bool {
		return node.Children[i].Path < node.Children[j].Path
	})

	node.Hash = innerHash(node.Children)
	return node, nil
}

// innerHash is the core Merkle step: hash the concatenation of every child's
// hash in order.  A change anywhere below bubbles up through every ancestor.
func innerHash(children []*Node) [32]byte {
	h := sha256.New()
	for _, c := range children {
		h.Write(c.Hash[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// errorNode creates a synthetic leaf for a path that could not be read.
// The error message is hashed so that if the file later becomes readable
// (or disappears entirely) the change will still be reported.
func errorNode(path string, err error) *Node {
	sentinel := "ERROR:" + err.Error()
	return &Node{
		Path: path,
		Hash: sha256.Sum256([]byte(sentinel)),
		Kind: File,
	}
}

// ChangeKind describes the type of change found during a diff.
type ChangeKind string

const (
	Modified ChangeKind = "MODIFIED"
	Added    ChangeKind = "ADDED"
	Removed  ChangeKind = "REMOVED"
)

// Change is a single file-level difference found between two snapshots.
type Change struct {
	Kind    ChangeKind
	Path    string
	OldHash [32]byte // zero value for Added changes
	NewHash [32]byte // zero value for Removed changes
}

// Diff returns all file-level changes between two Merkle snapshots.
// Subtrees whose root hashes already match are skipped entirely, so the
// work done is proportional to the number of changed files, not the total.
func Diff(old, next *Node) []Change {
	var changes []Change
	diff(old, next, &changes)
	return changes
}

func diff(old, next *Node, out *[]Change) {
	switch {
	case old == nil && next == nil:
		return

	case old == nil:
		// Brand-new subtree; every file inside it is an addition.
		collectLeaves(next, func(n *Node) {
			*out = append(*out, Change{Kind: Added, Path: n.Path, NewHash: n.Hash})
		})

	case next == nil:
		// Subtree is gone; every file that was in it is a removal.
		collectLeaves(old, func(n *Node) {
			*out = append(*out, Change{Kind: Removed, Path: n.Path, OldHash: n.Hash})
		})

	case old.Hash == next.Hash:
		// Hashes match: this entire subtree is clean. Skip it.
		return

	case old.Kind == File && next.Kind == File:
		// Same path, different hash: the file was modified.
		*out = append(*out, Change{
			Kind:    Modified,
			Path:    next.Path,
			OldHash: old.Hash,
			NewHash: next.Hash,
		})

	case old.Kind != next.Kind:
		// File became a directory or vice versa: remove one, add the other.
		diff(old, nil, out)
		diff(nil, next, out)

	default:
		// Directory node with changed hash: recurse into children.
		diffChildren(old.Children, next.Children, out)
	}
}

// diffChildren compares two sets of child nodes by path and recurses into
// any that are new, removed, or have a different hash.
func diffChildren(oldKids, nextKids []*Node, out *[]Change) {
	oldMap := indexByPath(oldKids)
	nextMap := indexByPath(nextKids)

	for path, o := range oldMap {
		diff(o, nextMap[path], out)
	}
	for path, n := range nextMap {
		if _, exists := oldMap[path]; !exists {
			diff(nil, n, out)
		}
	}
}

func indexByPath(nodes []*Node) map[string]*Node {
	m := make(map[string]*Node, len(nodes))
	for _, n := range nodes {
		m[n.Path] = n
	}
	return m
}

// collectLeaves calls fn for every file leaf in the subtree rooted at n.
func collectLeaves(n *Node, fn func(*Node)) {
	if n.Kind == File {
		fn(n)
		return
	}
	for _, c := range n.Children {
		collectLeaves(c, fn)
	}
}
