package merkle_test

import (
	"testing"

	"github.com/DakodaStemen/hashdog/internal/merkle"
)

func TestProofRoundTrip(t *testing.T) {
	root := makeTree(t, map[string]string{"a/x": "1", "a/y": "2", "b/z": "3", "c": "4", "b/q/deep": "5"})
	tree, _ := merkle.Build(root)
	for _, rel := range []string{"a/x", "a/y", "b/z", "c", "b/q/deep"} {
		p, err := merkle.Prove(tree, rel)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if err := p.Verify(tree.HexHash()); err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
	}
}

func TestProofRejectsForgery(t *testing.T) {
	root := makeTree(t, map[string]string{"a/x": "1", "b/z": "3"})
	tree, _ := merkle.Build(root)
	p, _ := merkle.Prove(tree, "a/x")
	good := tree.HexHash()

	bad := *p
	bad.LeafHash = "00" + p.LeafHash[2:]
	if bad.Verify(good) == nil {
		t.Fatal("tampered leaf accepted")
	}
	if p.Verify("11"+good[2:]) == nil {
		t.Fatal("wrong root accepted")
	}
	if _, err := merkle.Prove(tree, "nope"); err == nil {
		t.Fatal("missing file should error")
	}
	if _, err := merkle.Prove(tree, "a"); err == nil {
		t.Fatal("directory should error")
	}
}

func TestSnapshotRoundTripAndTamper(t *testing.T) {
	root := makeTree(t, map[string]string{"a/x": "1", "b/z": "3"})
	tree, _ := merkle.Build(root)
	s := merkle.Snapshot(tree)
	back, err := merkle.FromSnapshot(root, s)
	if err != nil || back.Hash != tree.Hash {
		t.Fatalf("round trip: %v", err)
	}
	if len(merkle.Diff(tree, back)) != 0 {
		t.Fatal("diff of identical trees not empty")
	}
	s.Children[0].Children[0].Hash = "aa" + s.Children[0].Children[0].Hash[2:]
	if _, err := merkle.FromSnapshot(root, s); err == nil {
		t.Fatal("inconsistent snapshot accepted")
	}
}
