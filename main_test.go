package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestCLIRejectsLegacyBaselineClearly(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "tree")
	os.MkdirAll(root, 0o755)
	os.WriteFile(filepath.Join(root, "f"), []byte("one"), 0o644)
	key, bl := filepath.Join(d, "k"), filepath.Join(d, "b.json")
	cmdKeygen([]string{"-out", key})
	if err := cmdBaseline([]string{"-dir", root, "-key", key + ".key", "-out", bl}); err != nil {
		t.Fatal(err)
	}
	// A v2 baseline with its version field edited is simply tampered (signature covers it).
	b, _ := os.ReadFile(bl)
	os.WriteFile(bl, []byte(strings.Replace(string(b), `"version": 2`, `"version": 1`, 1)), 0o644)
	if err := cmdCheck([]string{"-dir", root, "-baseline", bl, "-pub", key + ".pub"}); !errors.Is(err, baseline.ErrTampered) {
		t.Fatalf("downgraded version field must fail signature check, got %v", err)
	}
}

func setupRuleTree(t *testing.T) (root, key, bl string) {
	d := t.TempDir()
	root = filepath.Join(d, "tree")
	os.MkdirAll(filepath.Join(root, "var"), 0o755)
	os.WriteFile(filepath.Join(root, "conf"), []byte("c"), 0o644)
	os.WriteFile(filepath.Join(root, "var", "app.log"), []byte("l1"), 0o644)
	key, bl = filepath.Join(d, "k"), filepath.Join(d, "b.json")
	if err := cmdKeygen([]string{"-out", key}); err != nil {
		t.Fatal(err)
	}
	return
}

func TestCLIExcludeFlagSignedAndEnforced(t *testing.T) {
	root, key, bl := setupRuleTree(t)
	if err := cmdBaseline([]string{"-dir", root, "-key", key + ".key", "-out", bl, "-exclude", "*.log"}); err != nil {
		t.Fatal(err)
	}
	chk := func(extra ...string) error {
		return cmdCheck(append([]string{"-dir", root, "-baseline", bl, "-pub", key + ".pub"}, extra...))
	}
	// Excluded file changes + a new excluded file: still clean, with no flags
	// given at check time (rules come from the signed baseline).
	os.WriteFile(filepath.Join(root, "var", "app.log"), []byte("bigger log"), 0o644)
	os.WriteFile(filepath.Join(root, "var", "new.log"), []byte("x"), 0o644)
	if err := chk(); err != nil {
		t.Fatalf("excluded changes flagged: %v", err)
	}
	if err := chk("-exclude", "*.log"); err != nil {
		t.Fatalf("matching rules must be accepted: %v", err)
	}
	// Different rules than signed: refused (can't hide changes via flags).
	if err := chk("-exclude", "*.log", "-exclude", "conf"); err == nil || errors.Is(err, errChanges) {
		t.Fatalf("mismatched rules must be refused, got %v", err)
	}
	// A real change is still caught.
	os.WriteFile(filepath.Join(root, "conf"), []byte("evil"), 0o644)
	if err := chk(); !errors.Is(err, errChanges) {
		t.Fatalf("want errChanges, got %v", err)
	}
}

func TestCLIConfigFileYAMLAndJSON(t *testing.T) {
	for name, body := range map[string]string{
		"r.yaml": "exclude:\n  - '*.log'\n",
		"r.json": `{"exclude": ["*.log"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			root, key, bl := setupRuleTree(t)
			cfg := filepath.Join(t.TempDir(), name)
			os.WriteFile(cfg, []byte(body), 0o644)
			if err := cmdBaseline([]string{"-dir", root, "-key", key + ".key", "-out", bl, "-config", cfg}); err != nil {
				t.Fatal(err)
			}
			os.WriteFile(filepath.Join(root, "var", "app.log"), []byte("changed"), 0o644)
			if err := cmdCheck([]string{"-dir", root, "-baseline", bl, "-pub", key + ".pub", "-config", cfg}); err != nil {
				t.Fatalf("config rules not applied: %v", err)
			}
		})
	}
}

func TestCLIIncludeAndFlagPlusConfigMerge(t *testing.T) {
	root, key, bl := setupRuleTree(t)
	cfg := filepath.Join(t.TempDir(), "r.yaml")
	os.WriteFile(cfg, []byte("exclude: ['*.log']\n"), 0o644)
	// config excludes *.log, flag includes only "conf"
	if err := cmdBaseline([]string{"-dir", root, "-key", key + ".key", "-out", bl, "-config", cfg, "-include", "conf"}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "other"), []byte("new file outside the allow-list"), 0o644)
	if err := cmdCheck([]string{"-dir", root, "-baseline", bl, "-pub", key + ".pub"}); err != nil {
		t.Fatalf("file outside include list flagged: %v", err)
	}
}

func TestCLIBadRuleRejected(t *testing.T) {
	root, key, bl := setupRuleTree(t)
	if err := cmdBaseline([]string{"-dir", root, "-key", key + ".key", "-out", bl, "-exclude", "["}); err == nil {
		t.Fatal("bad glob accepted")
	}
}

func TestVersionString(t *testing.T) {
	if v := versionString(); !strings.Contains(v, "hashdog dev") || !strings.Contains(v, "baseline format v2") {
		t.Fatal(v)
	}
}
