package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DakodaStemen/hashdog/internal/baseline"
)

func TestCLIFlow(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "tree")
	os.MkdirAll(root, 0o755)
	os.WriteFile(filepath.Join(root, "f"), []byte("one"), 0o644)
	key, bl := filepath.Join(d, "k"), filepath.Join(d, "b.json")

	for name, err := range map[string]error{
		"keygen":   cmdKeygen([]string{"-out", key}),
		"baseline": cmdBaseline([]string{"-dir", root, "-key", key + ".key", "-out", bl}),
		"check":    cmdCheck([]string{"-dir", root, "-baseline", bl, "-pub", key + ".pub"}),
	} {
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	os.WriteFile(filepath.Join(root, "f"), []byte("two"), 0o644)
	if err := cmdCheck([]string{"-dir", root, "-baseline", bl, "-pub", key + ".pub", "-json"}); !errors.Is(err, errChanges) {
		t.Fatalf("want errChanges, got %v", err)
	}

	b, _ := os.ReadFile(bl)
	os.WriteFile(bl, append([]byte(" "), b[:len(b)-3]...), 0o644)
	if err := cmdCheck([]string{"-dir", root, "-baseline", bl, "-pub", key + ".pub"}); !errors.Is(err, baseline.ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
}

func TestCLIProof(t *testing.T) {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "a"), 0o755)
	os.WriteFile(filepath.Join(d, "a", "f"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(d, "g"), []byte("y"), 0o644)
	pf := filepath.Join(t.TempDir(), "p.json")
	if err := cmdProof([]string{"-dir", d, "-file", "a/f", "-out", pf}); err != nil {
		t.Fatal(err)
	}
	if err := cmdVerifyProof([]string{"-proof", pf, "-root", "00", "-content", filepath.Join(d, "a", "f")}); err == nil {
		t.Fatal("wrong root must fail")
	}
	if err := cmdVerifyProof([]string{"-proof", pf, "-root", "00", "-content", filepath.Join(d, "g")}); err == nil {
		t.Fatal("wrong content must fail")
	}
}
