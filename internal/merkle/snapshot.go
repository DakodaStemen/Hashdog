package merkle

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
)

// SnapNode is the serialisable form of a tree: relative names, hex hashes.
//
// File leaves carry the inputs of their leaf hash (content, mode, uid, gid,
// target) or, for unreadable files, the error text. FromSnapshot recomputes
// the leaf hash from them, so none of these can be edited without detection.
type SnapNode struct {
	Name     string      `json:"name"`
	Kind     string      `json:"kind"` // "file" or "dir"
	Hash     string      `json:"hash"`
	Content  string      `json:"content,omitempty"` // hex SHA-256 of contents (files)
	Mode     uint32      `json:"mode,omitempty"`
	UID      int         `json:"uid,omitempty"`
	GID      int         `json:"gid,omitempty"`
	Target   string      `json:"target,omitempty"`
	Err      string      `json:"err,omitempty"`
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
		return s
	}
	s.Mode, s.UID, s.GID, s.Target, s.Err = n.Mode, n.UID, n.GID, n.Target, n.Err
	if n.Err == "" {
		s.Content = hex.EncodeToString(n.ContentHash[:])
	}
	return s
}

// FromSnapshot rebuilds a tree rooted at root. It recomputes every leaf and
// directory hash from its parts and rejects the snapshot if any stored hash is
// inconsistent, so a hand-edited snapshot can't smuggle in a false root.
func FromSnapshot(root string, s *SnapNode) (*Node, error) {
	return fromSnap(root, s)
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
		if len(s.Children) > 0 {
			return nil, fmt.Errorf("%s: file with children", path)
		}
		n.Mode, n.UID, n.GID, n.Target, n.Err = s.Mode, s.UID, s.GID, s.Target, s.Err
		if s.Err != "" {
			if s.Content != "" || n.Hash != errHash(s.Err) {
				return nil, fmt.Errorf("%s: stored hash does not match error leaf", path)
			}
			break
		}
		c, err := hex.DecodeString(s.Content)
		if err != nil || len(c) != 32 {
			return nil, fmt.Errorf("%s: missing or bad content hash (not a v2 snapshot?)", path)
		}
		copy(n.ContentHash[:], c)
		if got := LeafHash(n.ContentHash, n.Mode, n.UID, n.GID, n.Target); got != n.Hash {
			return nil, fmt.Errorf("%s: stored hash does not match leaf contents/metadata", path)
		}
	case "dir":
		n.Kind = Dir
		if s.Content != "" || s.Mode != 0 || s.UID != 0 || s.GID != 0 || s.Target != "" || s.Err != "" {
			return nil, fmt.Errorf("%s: directory with leaf fields", path)
		}
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
