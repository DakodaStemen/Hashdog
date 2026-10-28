// Package baseline saves and loads Merkle snapshots as ed25519-signed JSON.
//
// The signature covers the whole payload (creation time, root hash, full
// tree). Verification needs only the PUBLIC key, which must come from a
// trusted place that is not the baseline file itself.
package baseline

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/DakodaStemen/hashdog/internal/merkle"
)

// ErrTampered is returned when the signature or internal hashes don't check out.
var ErrTampered = errors.New("baseline tampered or signed by a different key")

type payload struct {
	Version  int              `json:"version"`
	Alg      string           `json:"alg"`
	Created  string           `json:"created"`
	RootHash string           `json:"root_hash"`
	Tree     *merkle.SnapNode `json:"tree"`
}

// File is the on-disk format.
type File struct {
	payload
	Signature string `json:"signature"`
}

func (f File) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		payload
		Signature string `json:"signature"`
	}{f.payload, f.Signature})
}

// RootHash returns the hex root hash recorded in the baseline.
func (f *File) RootHash() string { return f.payload.RootHash }

// Created returns the creation timestamp string.
func (f *File) Created() string { return f.payload.Created }

func (p payload) bytes() []byte {
	b, _ := json.Marshal(p)
	return b
}

// GenerateKey returns a fresh ed25519 keypair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// WriteKeys writes hex-encoded keys to prefix.key (0600) and prefix.pub.
func WriteKeys(prefix string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	if err := os.WriteFile(prefix+".key", []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(prefix+".pub", []byte(hex.EncodeToString(pub)+"\n"), 0o644)
}

func readHex(path string, size int) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != size {
		return nil, fmt.Errorf("%s: not a valid hex key of %d bytes", path, size)
	}
	return raw, nil
}

func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	return readHex(path, ed25519.PrivateKeySize)
}

func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	return readHex(path, ed25519.PublicKeySize)
}

// Sign builds a signed baseline for a tree.
func Sign(tree *merkle.Node, priv ed25519.PrivateKey, now time.Time) *File {
	p := payload{
		Version:  1,
		Alg:      "ed25519",
		Created:  now.UTC().Format(time.RFC3339),
		RootHash: tree.HexHash(),
		Tree:     merkle.Snapshot(tree),
	}
	return &File{payload: p, Signature: hex.EncodeToString(ed25519.Sign(priv, p.bytes()))}
}

// Save writes the baseline as indented JSON.
func Save(path string, f *File) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// Load reads and verifies a baseline against pub, returning the file and the
// reconstructed tree rooted at root. Any failure to authenticate returns an
// error wrapping ErrTampered.
func Load(path string, pub ed25519.PublicKey, root string) (*File, *merkle.Node, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var f File
	var raw struct {
		payload
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, nil, fmt.Errorf("%w: unreadable JSON: %v", ErrTampered, err)
	}
	f.payload, f.Signature = raw.payload, raw.Signature
	sig, err := hex.DecodeString(f.Signature)
	if err != nil || f.Alg != "ed25519" || f.Tree == nil || !ed25519.Verify(pub, f.payload.bytes(), sig) {
		return nil, nil, ErrTampered
	}
	tree, err := merkle.FromSnapshot(root, f.Tree)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrTampered, err)
	}
	if tree.HexHash() != f.payload.RootHash {
		return nil, nil, fmt.Errorf("%w: root hash mismatch", ErrTampered)
	}
	return &f, tree, nil
}
