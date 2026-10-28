package baseline_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DakodaStemen/hashdog/internal/baseline"
	"github.com/DakodaStemen/hashdog/internal/filter"
	"github.com/DakodaStemen/hashdog/internal/merkle"
)

func setup(t *testing.T) (root, bl string, tree *merkle.Node) {
	t.Helper()
	root = t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("root:x:0:0"), 0o644)
	os.WriteFile(filepath.Join(root, "hosts"), []byte("127.0.0.1"), 0o644)
	tree, err := merkle.Build(root)
	if err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(t.TempDir(), "b.json"), tree
}

func TestSaveLoad(t *testing.T) {
	root, bl, tree := setup(t)
	pub, priv, _ := baseline.GenerateKey()
	if err := baseline.Save(bl, baseline.Sign(tree, priv, time.Now())); err != nil {
		t.Fatal(err)
	}
	f, got, err := baseline.Load(bl, pub, root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash != tree.Hash || f.RootHash() != tree.HexHash() {
		t.Fatal("loaded tree differs")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	root, bl, tree := setup(t)
	_, priv, _ := baseline.GenerateKey()
	otherPub, _, _ := baseline.GenerateKey()
	baseline.Save(bl, baseline.Sign(tree, priv, time.Now()))
	if _, _, err := baseline.Load(bl, otherPub, root); !errors.Is(err, baseline.ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	root, bl, tree := setup(t)
	pub, priv, _ := baseline.GenerateKey()
	baseline.Save(bl, baseline.Sign(tree, priv, time.Now()))
	b, _ := os.ReadFile(bl)

	// 1. flip one hex digit of a leaf hash (also breaks parent consistency)
	// 2. change the creation time (only the signature can catch this)
	// 3. truncate / garble the file
	leaf := tree.Children[0].Children[0].HexHash() // etc/passwd
	cases := map[string]string{
		"leaf hash":    strings.Replace(string(b), leaf, "ff"+leaf[2:], 1),
		"timestamp":    strings.Replace(string(b), `"created": "`, `"created": "1999`, 1),
		"garbled":      string(b[:len(b)/2]),
		"sig stripped": strings.Replace(string(b), `"signature": "`, `"signature": "00`, 1),
	}
	for name, mutated := range cases {
		if mutated == string(b) {
			t.Fatalf("%s: mutation did not change file", name)
		}
		os.WriteFile(bl, []byte(mutated), 0o644)
		if _, _, err := baseline.Load(bl, pub, root); !errors.Is(err, baseline.ErrTampered) {
			t.Errorf("%s: want ErrTampered, got %v", name, err)
		}
	}
}

func TestKeyFiles(t *testing.T) {
	pub, priv, _ := baseline.GenerateKey()
	p := filepath.Join(t.TempDir(), "k")
	if err := baseline.WriteKeys(p, pub, priv); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p + ".key"); fi.Mode().Perm() != 0o600 {
		t.Fatal("private key must be 0600")
	}
	rp, err := baseline.ReadPublicKey(p + ".pub")
	if err != nil || !pub.Equal(rp) {
		t.Fatal("public key round trip")
	}
	rk, err := baseline.ReadPrivateKey(p + ".key")
	if err != nil || !priv.Equal(rk) {
		t.Fatal("private key round trip")
	}
}

func TestRulesAreSigned(t *testing.T) {
	root, bl, _ := setup(t)
	rules, _ := filter.New([]string{"etc/**"}, []string{"*.log"})
	tree, _ := merkle.BuildWith(root, merkle.Options{Rules: rules})
	pub, priv, _ := baseline.GenerateKey()
	if err := baseline.Save(bl, baseline.SignWith(tree, priv, time.Now(), rules)); err != nil {
		t.Fatal(err)
	}
	f, _, err := baseline.Load(bl, pub, root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.Rules()
	if err != nil || !filter.Equal(got, rules) {
		t.Fatalf("rules did not round-trip: %v", err)
	}
	// Widening the exclusions in the file must break the signature.
	b, _ := os.ReadFile(bl)
	mut := strings.Replace(string(b), `"*.log"`, `"*.log", "*"`, 1)
	if mut == string(b) {
		t.Fatal("mutation did not apply")
	}
	os.WriteFile(bl, []byte(mut), 0o644)
	if _, _, err := baseline.Load(bl, pub, root); !errors.Is(err, baseline.ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
}
