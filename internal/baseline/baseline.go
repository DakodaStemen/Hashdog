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

	"github.com/DakodaStemen/hashdog/internal/filter"
	"github.com/DakodaStemen/hashdog/internal/merkle"
)

// Version is the baseline format this build writes and reads.
//
//	v1  leaf hash = SHA-256(contents)                      (no longer readable)
//	v2  leaf hash = SHA-256(domain || contents-hash || mode || uid || gid || symlink target);
//	    symlinks are recorded as leaves; leaves store their hash inputs
const Version = 2

// ErrTampered is returned when the signature or internal hashes don't check out.
var ErrTampered = errors.New("baseline tampered or signed by a different key")

// ErrLegacyFormat is returned for an authentic baseline in an older format.
// v1 trees hash contents only, so they cannot be compared against v2 scans
// (every leaf would differ); silently "upgrading" one would also mean trusting
// whatever is on disk now. The operator must re-baseline from a trusted state.
var ErrLegacyFormat = errors.New("baseline uses a legacy format")

// ErrUnsupportedVersion is returned for a baseline newer than this build understands.
var ErrUnsupportedVersion = errors.New("baseline format version not supported by this hashdog")

type payload struct {
	Version  int              `json:"version"`
	Alg      string           `json:"alg"`
	Created  string           `json:"created"`
	RootHash string           `json:"root_hash"`
	Tree     *merkle.SnapNode `json:"tree"`
	// Rules are the include/exclude globs the tree was built with. They are
	// signed, so a verifier scans with exactly the same rules and an attacker
	// cannot widen the exclusions by editing a config file.
	Rules *RuleSet `json:"rules,omitempty"`
}

// RuleSet is the serialised form of filter.Rules.
type RuleSet struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
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

// Rules compiles the include/exclude rules recorded in the baseline (nil if none).
func (f *File) Rules() (*filter.Rules, error) {
	if f.payload.Rules == nil {
		return nil, nil
	}
	return filter.New(f.payload.Rules.Include, f.payload.Rules.Exclude)
}

// FormatVersion returns the baseline format version recorded in the file.
func (f *File) FormatVersion() int { return f.payload.Version }

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

// Sign builds a signed baseline for a tree built without include/exclude rules.
func Sign(tree *merkle.Node, priv ed25519.PrivateKey, now time.Time) *File {
	return SignWith(tree, priv, now, nil)
}

// SignWith is Sign, recording the rules the tree was built with.
func SignWith(tree *merkle.Node, priv ed25519.PrivateKey, now time.Time, rules *filter.Rules) *File {
	p := payload{
		Version:  Version,
		Alg:      "ed25519",
		Created:  now.UTC().Format(time.RFC3339),
		RootHash: tree.HexHash(),
		Tree:     merkle.Snapshot(tree),
	}
	if in, ex := rules.Lists(); len(in)+len(ex) > 0 {
		p.Rules = &RuleSet{Include: in, Exclude: ex}
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
	switch {
	case f.Version == 1:
		return nil, nil, fmt.Errorf("%w: %s is a validly signed v1 baseline (content-only hashes). "+
			"This hashdog uses format v%d, which also covers mode, uid/gid and symlink targets, so the two "+
			"cannot be compared. Re-create it with `hashdog baseline` from a trusted state; v1 baselines are not auto-upgraded",
			ErrLegacyFormat, path, Version)
	case f.Version != Version:
		return nil, nil, fmt.Errorf("%w: file is v%d, this build reads v%d", ErrUnsupportedVersion, f.Version, Version)
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
