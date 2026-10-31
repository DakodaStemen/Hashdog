package merkle_test

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/DakodaStemen/hashdog/internal/merkle"
)

func findLeaf(t *testing.T, n *merkle.Node, suffix string) *merkle.Node {
	t.Helper()
	var got *merkle.Node
	var walk func(*merkle.Node)
	walk = func(x *merkle.Node) {
		if x.Kind == merkle.File && filepath.Base(x.Path) == suffix {
			got = x
		}
		for _, c := range x.Children {
			walk(c)
		}
	}
	walk(n)
	if got == nil {
		t.Fatalf("leaf %s not found", suffix)
	}
	return got
}

func TestChmodChangesTree(t *testing.T) {
	root := makeTree(t, map[string]string{"bin/su": "elf"})
	f := filepath.Join(root, "bin/su")
	os.Chmod(f, 0o755)
	before, _ := merkle.Build(root)
	os.Chmod(f, os.ModeSetuid|0o755) // setuid: classic persistence
	after, _ := merkle.Build(root)
	if before.Hash == after.Hash {
		t.Fatal("chmod must change the root hash")
	}
	ch := merkle.Diff(before, after)
	if len(ch) != 1 || ch[0].Kind != merkle.Modified || !reflect.DeepEqual(ch[0].Fields, []string{"mode"}) {
		t.Fatalf("want one MODIFIED[mode], got %+v", ch)
	}
	if findLeaf(t, before, "su").ContentHash != findLeaf(t, after, "su").ContentHash {
		t.Fatal("content hash should be unchanged by chmod")
	}
}

func TestChownChangesTree(t *testing.T) {
	// Root may chown anywhere; an ordinary user may chgrp to a supplementary group.
	uid, gid := -1, -1
	if os.Getuid() == 0 {
		uid, gid = 12345, 54321
	} else {
		groups, _ := os.Getgroups()
		for _, g := range groups {
			if g != os.Getgid() {
				gid = g
				break
			}
		}
		if gid < 0 {
			t.Skip("no supplementary group to chgrp to")
		}
	}
	root := makeTree(t, map[string]string{"f": "x"})
	f := filepath.Join(root, "f")
	before, _ := merkle.Build(root)
	if err := os.Chown(f, uid, gid); err != nil {
		t.Skip(err)
	}
	after, _ := merkle.Build(root)
	ch := merkle.Diff(before, after)
	want := []string{"gid"}
	if uid >= 0 {
		want = []string{"uid", "gid"}
	}
	if len(ch) != 1 || !reflect.DeepEqual(ch[0].Fields, want) {
		t.Fatalf("got %+v want fields %v", ch, want)
	}
}

func TestOwnerRecorded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	root := makeTree(t, map[string]string{"f": "x"})
	tree, _ := merkle.Build(root)
	l := findLeaf(t, tree, "f")
	if l.UID != os.Getuid() || l.GID != os.Getgid() {
		t.Fatalf("recorded uid/gid %d/%d, process %d/%d", l.UID, l.GID, os.Getuid(), os.Getgid())
	}
}

func TestSymlinkRecordedNotFollowed(t *testing.T) {
	root := makeTree(t, map[string]string{"real": "data"})
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o644)
	link := filepath.Join(root, "ln")
	if err := os.Symlink("real", link); err != nil {
		t.Skip(err)
	}
	dirLink := filepath.Join(root, "dl")
	os.Symlink(outside, dirLink) // directory symlink must NOT be traversed
	before, err := merkle.Build(root)
	if err != nil {
		t.Fatal(err)
	}
	l := findLeaf(t, before, "ln")
	if !l.IsLink() || l.Target != "real" {
		t.Fatalf("symlink leaf wrong: %+v", l)
	}
	for _, c := range before.Children {
		if c.Path == filepath.Join(root, "dl", "secret") {
			t.Fatal("followed directory symlink")
		}
	}
	if d := findLeaf(t, before, "dl"); !d.IsLink() || d.Target != outside {
		t.Fatalf("dir symlink should be a link leaf: %+v", d)
	}

	// retarget the link to something else: must be reported as MODIFIED[target]
	os.Remove(link)
	os.Symlink("/etc/shadow", link)
	after, _ := merkle.Build(root)
	var got *merkle.Change
	for _, c := range merkle.Diff(before, after) {
		if filepath.Base(c.Path) == "ln" {
			c := c
			got = &c
		}
	}
	if got == nil || got.Kind != merkle.Modified || !reflect.DeepEqual(got.Fields, []string{"target"}) {
		t.Fatalf("retargeted symlink not reported correctly: %+v", got)
	}
}

func TestSnapshotRoundTripWithMetadata(t *testing.T) {
	root := makeTree(t, map[string]string{"a/f": "1", "a/g": "2"})
	os.Symlink("f", filepath.Join(root, "a", "ln"))
	os.Chmod(filepath.Join(root, "a/g"), 0o700)
	tree, _ := merkle.Build(root)
	back, err := merkle.FromSnapshot(root, merkle.Snapshot(tree))
	if err != nil || back.Hash != tree.Hash {
		t.Fatalf("round trip: %v", err)
	}
	if len(merkle.Diff(tree, back)) != 0 {
		t.Fatal("diff of identical trees must be empty")
	}
}

func TestSnapshotRejectsEditedMetadata(t *testing.T) {
	root := makeTree(t, map[string]string{"f": "1"})
	tree, _ := merkle.Build(root)
	mutate := map[string]func(*merkle.SnapNode){
		"mode":    func(n *merkle.SnapNode) { n.Mode ^= 0o111 },
		"uid":     func(n *merkle.SnapNode) { n.UID++ },
		"gid":     func(n *merkle.SnapNode) { n.GID++ },
		"target":  func(n *merkle.SnapNode) { n.Target = "x" },
		"content": func(n *merkle.SnapNode) { n.Content = "00" + n.Content[2:] },
		"missing": func(n *merkle.SnapNode) { n.Content = "" }, // what a v1 snapshot looks like
	}
	for name, fn := range mutate {
		s := merkle.Snapshot(tree)
		fn(s.Children[0])
		if _, err := merkle.FromSnapshot(root, s); err == nil {
			t.Errorf("%s: edited leaf accepted", name)
		}
	}
}

func TestErrorLeafSurvivesSnapshot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read everything")
	}
	root := makeTree(t, map[string]string{"f": "1", "locked": "2"})
	os.Chmod(filepath.Join(root, "locked"), 0)
	defer os.Chmod(filepath.Join(root, "locked"), 0o644)
	tree, _ := merkle.Build(root)
	if findLeaf(t, tree, "locked").Err == "" {
		t.Fatal("expected error leaf")
	}
	back, err := merkle.FromSnapshot(root, merkle.Snapshot(tree))
	if err != nil || back.Hash != tree.Hash {
		t.Fatalf("round trip of error leaf: %v", err)
	}
}

// forceTrusted marks every leaf as hashed well after its mtime/ctime so the
// racy-clean guard doesn't mask what the test is about.
func forceTrusted(n *merkle.Node) {
	if n.Kind == merkle.File {
		n.Hashed = time.Now().Add(time.Minute)
	}
	for _, c := range n.Children {
		forceTrusted(c)
	}
}

func TestStatCacheReusesAndParanoidDoesNot(t *testing.T) {
	root := makeTree(t, map[string]string{"f": "v1"})
	prev, _ := merkle.Build(root)
	forceTrusted(prev)
	findLeaf(t, prev, "f").ContentHash = [32]byte{0xAB} // poison: only visible if reused

	cached, _ := merkle.BuildWith(root, merkle.Options{Prev: prev})
	if findLeaf(t, cached, "f").ContentHash != ([32]byte{0xAB}) {
		t.Skip("platform has no ctime: cache intentionally disabled")
	}
	para, _ := merkle.BuildWith(root, merkle.Options{Prev: prev, Paranoid: true})
	if findLeaf(t, para, "f").ContentHash == ([32]byte{0xAB}) {
		t.Fatal("paranoid must rehash")
	}
}

func TestStatCacheDefeatsMtimeRestore(t *testing.T) {
	root := makeTree(t, map[string]string{"old": "v1"})
	f := filepath.Join(root, "old")
	past := time.Now().Add(-time.Hour)
	os.Chtimes(f, past, past)
	prev, _ := merkle.Build(root)
	forceTrusted(prev)

	// Same size, mtime restored: the old size+mtime cache was fooled by this.
	os.WriteFile(f, []byte("v2"), 0o644)
	os.Chtimes(f, past, past)
	cached, _ := merkle.BuildWith(root, merkle.Options{Prev: prev})
	if cached.Hash == prev.Hash {
		t.Fatal("ctime must expose the rewrite despite restored mtime")
	}
}

func TestStatCacheDetectsInodeSwap(t *testing.T) {
	root := makeTree(t, map[string]string{"f": "AAAA"})
	f := filepath.Join(root, "f")
	fi, _ := os.Stat(f)
	prev, _ := merkle.Build(root)
	forceTrusted(prev)
	l := findLeaf(t, prev, "f")
	if l.Ino == 0 {
		t.Skip("no inode on this platform")
	}

	// Replace the file by rename: new inode, same size, mtime restored.
	tmp := filepath.Join(root, ".tmp")
	os.WriteFile(tmp, []byte("BBBB"), 0o644)
	os.Chtimes(tmp, fi.ModTime(), fi.ModTime())
	os.Rename(tmp, f)
	// Also pretend ctime wasn't visible (forge it in the cached entry) to
	// isolate the inode comparison.
	cur, _ := merkle.Build(root)
	l.Ctime = findLeaf(t, cur, "f").Ctime
	cached, _ := merkle.BuildWith(root, merkle.Options{Prev: prev})
	if cached.Hash == prev.Hash {
		t.Fatal("inode change must force a rehash even if size, mtime and ctime match")
	}
}

func TestCachedScanStillSeesChmod(t *testing.T) {
	root := makeTree(t, map[string]string{"f": "v1"})
	prev, _ := merkle.Build(root)
	forceTrusted(prev)
	os.Chmod(filepath.Join(root, "f"), 0o777)
	next, _ := merkle.BuildWith(root, merkle.Options{Prev: prev})
	if ch := merkle.Diff(prev, next); len(ch) != 1 || !reflect.DeepEqual(ch[0].Fields, []string{"mode"}) {
		t.Fatalf("cached scan missed chmod: %+v", ch)
	}
}

func TestProofCoversMetadata(t *testing.T) {
	root := makeTree(t, map[string]string{"a/f": "x", "g": "y"})
	tree, _ := merkle.Build(root)
	p, err := merkle.Prove(tree, "a/f")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(tree.HexHash()); err != nil {
		t.Fatal(err)
	}
	p.Mode ^= 0o111 // claim a different mode than the one hashed into the leaf
	if err := p.Verify(tree.HexHash()); err == nil {
		t.Fatal("metadata edit in proof must be rejected")
	}
}
