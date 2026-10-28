// Package merkle builds a Merkle tree over a directory and can diff two
// trees to find exactly which files changed.
//
// How it works
// ------------
// Every file (and symlink) is a leaf node. A leaf's value is
//
//	SHA-256( "hashdog-leaf-v2\0" || SHA-256(contents) || mode || uid || gid || symlink-target )
//
// so a chmod, chown or retargeted symlink changes the root just as a content
// edit does. (Format v1 hashed contents only; see package baseline.)
// Every directory is an inner node whose value is the SHA-256 hash of its
// children's hashes, concatenated in sorted path order.  The root hash is
// therefore a single 32-byte fingerprint of the entire watched tree.
//
// Because SHA-256 has the avalanche property, a single changed byte anywhere
// in any leaf's contents or metadata produces a completely different leaf hash, which propagates up
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
	"encoding/binary"
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
	Hash     [32]byte // leaf hash (see LeafHash) for files, children hashes for dirs
	Kind     Kind
	Children []*Node

	// Leaf fields that ARE part of the leaf hash.
	ContentHash [32]byte // SHA-256 of file contents; zero for symlinks
	Mode        uint32   // type + permission + setuid/setgid/sticky bits (see ModeBits)
	UID, GID    int      // -1 where the platform does not report ownership
	Target      string   // symlink target ("" for regular files)
	Err         string   // non-empty: leaf could not be read; Hash covers this text

	// Stat identity of the file when it was hashed, used only by the optional
	// rehash cache (see Options). Never part of the hash.
	Size    int64
	ModTime int64     // UnixNano
	Ctime   int64     // UnixNano; 0 if unavailable
	Ino     uint64    // inode number
	Dev     uint64    // device
	Hashed  time.Time // when the contents were actually read and hashed
}

// IsLink reports whether the leaf is a symlink.
func (n *Node) IsLink() bool { return os.FileMode(n.Mode)&os.ModeSymlink != 0 }

// modeMask selects the mode bits that are hashed: file type, permissions and
// the setuid/setgid/sticky bits. Go-defined constants, so stable across OSes.
const modeMask = os.ModeType | os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky

// ModeBits returns the hashed subset of m as a stable uint32.
func ModeBits(m os.FileMode) uint32 { return uint32(m & modeMask) }

const leafDomain = "hashdog-leaf-v2\x00"

// LeafHash is the v2 leaf hash. Fields are fixed-width or length-prefixed so
// the encoding is unambiguous.
func LeafHash(content [32]byte, mode uint32, uid, gid int, target string) [32]byte {
	h := sha256.New()
	h.Write([]byte(leafDomain))
	h.Write(content[:])
	var b [12]byte
	binary.BigEndian.PutUint32(b[0:], mode)
	binary.BigEndian.PutUint32(b[4:], uint32(int32(uid)))
	binary.BigEndian.PutUint32(b[8:], uint32(int32(gid)))
	h.Write(b[:])
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(target)))
	h.Write(l[:])
	h.Write([]byte(target))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func errHash(msg string) [32]byte { return sha256.Sum256([]byte("ERROR:" + msg)) }

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
	// size, mtime, ctime, inode and device all match its entry in Prev (and is
	// not racily clean) reuses the old CONTENT hash instead of being read
	// again. Mode/uid/gid/symlink target are always re-read from the fresh
	// stat. Platforms without ctime never get cache hits. This is fast but is NOT a
	// full verification: an attacker with root can forge mtime (and, with
	// effort, ctime and inode). Leave nil for a full verify.
	Prev *Node

	// Paranoid ignores Prev: every file is read and hashed on every build.
	Paranoid bool
}

// Build walks root and returns the Merkle tree for that directory, reading
// and hashing every file. Symlinks inside the tree are recorded as leaves
// (their target string is hashed) but never followed; sockets, devices and
// FIFOs are skipped.
func Build(root string) (*Node, error) { return BuildWith(root, Options{}) }

// BuildWith is Build with options.
func BuildWith(root string, opt Options) (*Node, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// A symlinked root (e.g. -dir /etc -> /private/etc) is followed once.
		if info, err = os.Stat(root); err != nil {
			return nil, err
		}
	}
	b := &builder{sem: make(chan struct{}, runtime.NumCPU())}
	if opt.Prev != nil && !opt.Paranoid {
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
		return b.buildLink(path, info)
	}
	if info.IsDir() {
		return b.buildInner(path)
	}
	if !info.Mode().IsRegular() {
		return nil, nil // sockets, devices, FIFOs: reading could block
	}
	return b.buildLeaf(path, info)
}

// buildLink records a symlink as a leaf whose hash covers its target string
// and lstat metadata. The target is never followed.
func (b *builder) buildLink(path string, info os.FileInfo) (*Node, error) {
	target, err := os.Readlink(path)
	if err != nil {
		return nil, err
	}
	st := statOf(info)
	n := &Node{Path: path, Kind: File, Mode: ModeBits(info.Mode()), UID: st.uid, GID: st.gid, Target: target}
	n.Hash = LeafHash(n.ContentHash, n.Mode, n.UID, n.GID, n.Target)
	return n, nil
}

// buildLeaf hashes the raw byte contents of a regular file (streamed).
// SHA-256's avalanche property means even a single changed byte produces
// a completely different 32-byte digest, making silent tampering detectable.
func (b *builder) buildLeaf(path string, info os.FileInfo) (*Node, error) {
	mt := info.ModTime().UnixNano()
	st := statOf(info)
	n := &Node{Path: path, Kind: File, Mode: ModeBits(info.Mode()), UID: st.uid, GID: st.gid,
		Size: info.Size(), ModTime: mt, Ctime: st.ctime, Ino: st.ino, Dev: st.dev}
	if p, ok := b.prev[path]; ok && st.hasCtime && cacheHit(p, n) {
		n.ContentHash, n.Hashed = p.ContentHash, p.Hashed
		n.Hash = LeafHash(n.ContentHash, n.Mode, n.UID, n.GID, n.Target)
		return n, nil
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
	copy(n.ContentHash[:], h.Sum(nil))
	n.Hashed = time.Now()
	n.Hash = LeafHash(n.ContentHash, n.Mode, n.UID, n.GID, n.Target)
	return n, nil
}

// cacheHit reports whether prev's content hash may be reused for cur: the
// stat identity (size, mtime, ctime, inode, device) is unchanged and the
// entry is not racily clean relative to the later of mtime/ctime.
func cacheHit(prev, cur *Node) bool {
	if prev.Kind != File || prev.IsLink() || prev.Err != "" || prev.Hashed.IsZero() {
		return false
	}
	if prev.Size != cur.Size || prev.ModTime != cur.ModTime || prev.Ctime != cur.Ctime ||
		prev.Ino != cur.Ino || prev.Dev != cur.Dev {
		return false
	}
	newest := cur.ModTime
	if cur.Ctime > newest {
		newest = cur.Ctime
	}
	return prev.Hashed.Sub(time.Unix(0, newest)) > racyWindow
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
	return &Node{Path: path, Hash: errHash(err.Error()), Kind: File, Err: err.Error(), UID: -1, GID: -1}
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

	// Fields lists which parts of a MODIFIED leaf differ: any of "content",
	// "mode", "uid", "gid", "target", "error". Empty for ADDED/REMOVED.
	Fields []string
}

// changedFields compares two leaves part by part.
func changedFields(o, n *Node) []string {
	var f []string
	if o.ContentHash != n.ContentHash {
		f = append(f, "content")
	}
	if o.Mode != n.Mode {
		f = append(f, "mode")
	}
	if o.UID != n.UID {
		f = append(f, "uid")
	}
	if o.GID != n.GID {
		f = append(f, "gid")
	}
	if o.Target != n.Target {
		f = append(f, "target")
	}
	if o.Err != n.Err {
		f = append(f, "error")
	}
	return f
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
			Fields:  changedFields(old, next),
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
