package merkle

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
)

// SnapNode is the serialisable form of a tree: relative names, hex hashes.
type SnapNode struct {
	Name     string      `json:"name"`
	Kind     string      `json:"kind"` // "file" or "dir"
	Hash     string      `json:"hash"`
	Children []*SnapNode `json:"children,omitempty"`
}

// Snapshot converts a tree to its serialisable form.
func Snapshot(n *Node) *SnapNode {
	s := &SnapNode{Name: filepath.Base(n.Path), Hash: n.HexHash(), Kind: "file"}
	if n.Kind == Dir {
		s.Kind = "dir"
		for _, c := range n.Children {
			s.Children = append(s.Children, Snapshot(c))
		}
	}
	return s
}

// FromSnapshot rebuilds a tree rooted at root. It recomputes every directory
// hash from its children and rejects the snapshot if any stored hash is
// inconsistent, so a hand-edited snapshot can't smuggle in a false root.
func FromSnapshot(root string, s *SnapNode) (*Node, error) {
	n, err := fromSnap(root, s)
	if err != nil {
		return nil, err
	}
	return n, nil
}

func fromSnap(path string, s *SnapNode) (*Node, error) {
	raw, err := hex.DecodeString(s.Hash)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("%s: bad hash", path)
	}
	n := &Node{Path: path}
	copy(n.Hash[:], raw)
	switch s.Kind {
	case "file":
		n.Kind = File
	case "dir":
		n.Kind = Dir
		for _, c := range s.Children {
			if c.Name == "" || c.Name != filepath.Base(c.Name) {
				return nil, errors.New("invalid name in snapshot")
			}
			cn, err := fromSnap(filepath.Join(path, c.Name), c)
			if err != nil {
				return nil, err
			}
			n.Children = append(n.Children, cn)
		}
		for i := 1; i < len(n.Children); i++ {
			if n.Children[i-1].Path >= n.Children[i].Path {
				return nil, fmt.Errorf("%s: children not sorted", path)
			}
		}
		if got := innerHash(n.Children); got != n.Hash {
			return nil, fmt.Errorf("%s: stored hash does not match children", path)
		}
	default:
		return nil, fmt.Errorf("%s: unknown kind %q", path, s.Kind)
	}
	return n, nil
}
