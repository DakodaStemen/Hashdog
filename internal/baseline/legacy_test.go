package baseline

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DakodaStemen/hashdog/internal/merkle"
)

// writeVersioned signs and writes a baseline claiming the given version.
func writeVersioned(t *testing.T, path string, priv ed25519.PrivateKey, tree *merkle.Node, version int) {
	t.Helper()
	p := payload{Version: version, Alg: "ed25519", Created: time.Now().UTC().Format(time.RFC3339),
		RootHash: tree.HexHash(), Tree: merkle.Snapshot(tree)}
	f := &File{payload: p, Signature: hex.EncodeToString(ed25519.Sign(priv, p.bytes()))}
	b, _ := json.Marshal(f)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyV1Rejected(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644)
	tree, _ := merkle.Build(root)
	pub, priv, _ := GenerateKey()
	bl := filepath.Join(t.TempDir(), "b.json")
	writeVersioned(t, bl, priv, tree, 1)

	_, _, err := Load(bl, pub, root)
	if !errors.Is(err, ErrLegacyFormat) {
		t.Fatalf("want ErrLegacyFormat, got %v", err)
	}
	if errors.Is(err, ErrTampered) {
		t.Fatal("an authentic v1 baseline is not 'tampered'")
	}
	for _, want := range []string{"v1", "hashdog baseline", "not auto-upgraded"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message should mention %q: %v", want, err)
		}
	}

	// A v1 file with a bad signature must still be reported as tampered, not legacy.
	otherPub, _, _ := GenerateKey()
	if _, _, err := Load(bl, otherPub, root); !errors.Is(err, ErrTampered) {
		t.Fatalf("wrong key on v1 file: want ErrTampered, got %v", err)
	}
}

func TestFutureVersionRejected(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644)
	tree, _ := merkle.Build(root)
	pub, priv, _ := GenerateKey()
	bl := filepath.Join(t.TempDir(), "b.json")
	writeVersioned(t, bl, priv, tree, Version+1)
	if _, _, err := Load(bl, pub, root); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
}

func TestRealV1ShapedFileRejected(t *testing.T) {
	// Byte-for-byte shape of a baseline written by the previous release
	// (no content/mode fields), signed validly. Must be reported as legacy.
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644)
	tree, _ := merkle.Build(root)
	pub, priv, _ := GenerateKey()
	snap := merkle.Snapshot(tree)
	for _, c := range snap.Children {
		c.Content, c.Mode, c.UID, c.GID = "", 0, 0, 0
	}
	p := payload{Version: 1, Alg: "ed25519", Created: "2026-01-01T00:00:00Z", RootHash: tree.HexHash(), Tree: snap}
	f := &File{payload: p, Signature: hex.EncodeToString(ed25519.Sign(priv, p.bytes()))}
	bl := filepath.Join(t.TempDir(), "b.json")
	if err := Save(bl, f); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(bl, pub, root); !errors.Is(err, ErrLegacyFormat) {
		t.Fatalf("got %v", err)
	}
}

func TestCurrentVersionWritten(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644)
	tree, _ := merkle.Build(root)
	_, priv, _ := GenerateKey()
	if v := Sign(tree, priv, time.Now()).FormatVersion(); v != 2 {
		t.Fatalf("version %d", v)
	}
}
