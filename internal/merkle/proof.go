package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Proof shows that a file with a given hash is included in a tree with a
// given root, without needing the rest of the tree's file contents.
//
// Directories here are n-ary (not binary), so each step carries the hashes
// of all siblings to the left and right of the path node, not just one.
type Proof struct {
	Path     string      `json:"path"`      // file path relative to the watched root
	LeafHash string      `json:"leaf_hash"` // hex v2 leaf hash (see LeafHash)
	Steps    []ProofStep `json:"steps"`     // from the leaf's parent up to the root
	Root     string      `json:"root"`      // hex root hash the proof resolves to

	// Inputs of the leaf hash, so a verifier holding the file can check the
	// contents AND metadata, not just the opaque leaf hash.
	ContentHash string `json:"content_hash"`
	Mode        uint32 `json:"mode"`
	UID         int    `json:"uid"`
	GID         int    `json:"gid"`
	Target      string `json:"target,omitempty"`
}

// ProofStep is one ancestor on the path: its children, split around the
// path node. Hash(ancestor) = SHA-256(Left... || pathNodeHash || Right...).
type ProofStep struct {
	Left  []string `json:"left"`
	Right []string `json:"right"`
}

// Prove builds an inclusion proof for the file at rel (relative to root.Path).
func Prove(root *Node, rel string) (*Proof, error) {
	target := filepath.Join(root.Path, rel)
	var chain []*Node // root ... leaf
	cur := root
	chain = append(chain, cur)
	for cur.Path != target {
		if cur.Kind != Dir {
			return nil, fmt.Errorf("%s not found in tree", rel)
		}
		var next *Node
		for _, c := range cur.Children {
			if c.Path == target || strings.HasPrefix(target, c.Path+string(filepath.Separator)) {
				next = c
				break
			}
		}
		if next == nil {
			return nil, fmt.Errorf("%s not found in tree", rel)
		}
		cur = next
		chain = append(chain, cur)
	}
	if cur.Kind != File {
		return nil, errors.New("proofs are for files, not directories")
	}
	if cur.Err != "" {
		return nil, fmt.Errorf("%s: unreadable at snapshot time (%s); no proof possible", rel, cur.Err)
	}
	p := &Proof{Path: filepath.ToSlash(rel), LeafHash: hex.EncodeToString(cur.Hash[:]), Root: root.HexHash(),
		ContentHash: hex.EncodeToString(cur.ContentHash[:]), Mode: cur.Mode, UID: cur.UID, GID: cur.GID, Target: cur.Target}
	for i := len(chain) - 2; i >= 0; i-- {
		var st ProofStep
		seen := false
		for _, c := range chain[i].Children {
			switch {
			case c == chain[i+1]:
				seen = true
			case !seen:
				st.Left = append(st.Left, hex.EncodeToString(c.Hash[:]))
			default:
				st.Right = append(st.Right, hex.EncodeToString(c.Hash[:]))
			}
		}
		p.Steps = append(p.Steps, st)
	}
	return p, nil
}

// Compute folds the proof and returns the root hash it implies.
func (p *Proof) Compute() (string, error) {
	cur, err := hex.DecodeString(p.LeafHash)
	if err != nil || len(cur) != 32 {
		return "", errors.New("bad leaf hash")
	}
	for _, st := range p.Steps {
		h := sha256.New()
		for _, side := range [][]string{st.Left, {hex.EncodeToString(cur)}, st.Right} {
			for _, x := range side {
				b, err := hex.DecodeString(x)
				if err != nil || len(b) != 32 {
					return "", errors.New("bad sibling hash")
				}
				h.Write(b)
			}
		}
		cur = h.Sum(nil)
	}
	return hex.EncodeToString(cur), nil
}

// Verify reports whether the proof resolves to wantRoot (hex).
func (p *Proof) Verify(wantRoot string) error {
	if err := p.checkLeaf(); err != nil {
		return err
	}
	got, err := p.Compute()
	if err != nil {
		return err
	}
	if got != strings.ToLower(wantRoot) {
		return fmt.Errorf("proof resolves to %s, want %s", got, wantRoot)
	}
	return nil
}

// checkLeaf recomputes the leaf hash from the proof's content hash and
// metadata and requires it to equal LeafHash.
func (p *Proof) checkLeaf() error {
	c, err := hex.DecodeString(p.ContentHash)
	if err != nil || len(c) != 32 {
		return errors.New("proof has no valid content_hash (made by an older hashdog?)")
	}
	var ch [32]byte
	copy(ch[:], c)
	if got := hex.EncodeToString(func() []byte { h := LeafHash(ch, p.Mode, p.UID, p.GID, p.Target); return h[:] }()); got != p.LeafHash {
		return errors.New("leaf_hash does not match content_hash and metadata")
	}
	return nil
}
