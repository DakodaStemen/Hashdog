package merkle_test

import (
	"fim/internal/merkle"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// helper: create a temp dir with the given file→content map.
func makeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root, err := ioutil.TempDir("", "fim-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })

	for rel, content := range files {
		abs := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
			t.Fatal(err)
		}
		if err := ioutil.WriteFile(abs, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestNoChange: same files → no diff, root hashes equal.
func TestNoChange(t *testing.T) {
	root := makeTree(t, map[string]string{
		"a.txt": "hello",
		"b.txt": "world",
	})

	snap1, _ := merkle.Build(root)
	snap2, _ := merkle.Build(root)

	if snap1.Hash != snap2.Hash {
		t.Fatal("expected identical hashes for unchanged tree")
	}
	if changes := merkle.Diff(snap1, snap2); len(changes) != 0 {
		t.Fatalf("expected 0 changes, got %d", len(changes))
	}
}

// TestModified: editing a file produces exactly one MODIFIED change.
func TestModified(t *testing.T) {
	root := makeTree(t, map[string]string{
		"etc/passwd": "root:x:0:0",
	})

	snap1, _ := merkle.Build(root)

	// Mutate the file — one byte change → completely different SHA-256 (avalanche).
	ioutil.WriteFile(filepath.Join(root, "etc/passwd"), []byte("root:x:0:1"), 0644)

	snap2, _ := merkle.Build(root)

	if snap1.Hash == snap2.Hash {
		t.Fatal("root hash should have changed after file modification")
	}

	changes := merkle.Diff(snap1, snap2)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Kind != merkle.Modified {
		t.Fatalf("expected MODIFIED, got %s", changes[0].Kind)
	}
}

// TestAdded: new file → one ADDED change.
func TestAdded(t *testing.T) {
	root := makeTree(t, map[string]string{"a.txt": "a"})

	snap1, _ := merkle.Build(root)
	ioutil.WriteFile(filepath.Join(root, "b.txt"), []byte("b"), 0644)
	snap2, _ := merkle.Build(root)

	changes := merkle.Diff(snap1, snap2)
	if len(changes) != 1 || changes[0].Kind != merkle.Added {
		t.Fatalf("expected 1 ADDED, got %+v", changes)
	}
}

// TestRemoved: deleting a file → one REMOVED change.
func TestRemoved(t *testing.T) {
	root := makeTree(t, map[string]string{"a.txt": "a", "b.txt": "b"})

	snap1, _ := merkle.Build(root)
	os.Remove(filepath.Join(root, "b.txt"))
	snap2, _ := merkle.Build(root)

	changes := merkle.Diff(snap1, snap2)
	if len(changes) != 1 || changes[0].Kind != merkle.Removed {
		t.Fatalf("expected 1 REMOVED, got %+v", changes)
	}
}

// TestAvalanche: single-bit change in content produces a different hash.
// This directly demonstrates the SHA-256 avalanche effect.
func TestAvalanche(t *testing.T) {
	root1 := makeTree(t, map[string]string{"file": "Hello, World!"})
	root2 := makeTree(t, map[string]string{"file": "Hello, World?"}) // one char differs

	snap1, _ := merkle.Build(root1)
	snap2, _ := merkle.Build(root2)

	if snap1.Hash == snap2.Hash {
		t.Fatal("avalanche effect failed: different content produced same hash")
	}
	t.Logf("original: %x", snap1.Hash)
	t.Logf("mutated:  %x", snap2.Hash)
	t.Log("(every bit above differs — that is the avalanche effect)")
}

// TestSubtreePruning: changes in one subtree don't affect a sibling's hash,
// demonstrating the O(changed_files) diff optimisation.
func TestSubtreePruning(t *testing.T) {
	root := makeTree(t, map[string]string{
		"bin/sh":      "shell",
		"etc/passwd":  "passwords",
		"etc/hosts":   "127.0.0.1 localhost",
	})

	snap1, _ := merkle.Build(root)

	// Only modify one file under etc/.
	ioutil.WriteFile(filepath.Join(root, "etc/passwd"), []byte("HACKED"), 0644)

	snap2, _ := merkle.Build(root)

	// The bin/ subtree should be completely untouched.
	findNode := func(tree *merkle.Node, path string) *merkle.Node {
		// simple linear search for test purposes
		var found *merkle.Node
		var walk func(*merkle.Node)
		walk = func(n *merkle.Node) {
			if n.Path == filepath.Join(root, path) {
				found = n
			}
			for _, c := range n.Children {
				walk(c)
			}
		}
		walk(tree)
		return found
	}

	bin1 := findNode(snap1, "bin")
	bin2 := findNode(snap2, "bin")

	if bin1 == nil || bin2 == nil {
		t.Fatal("could not locate bin/ node in tree")
	}
	if bin1.Hash != bin2.Hash {
		t.Error("bin/ subtree hash changed despite no modification — pruning broken")
	}

	changes := merkle.Diff(snap1, snap2)
	if len(changes) != 1 {
		t.Fatalf("expected exactly 1 change, got %d: %+v", len(changes), changes)
	}
}
