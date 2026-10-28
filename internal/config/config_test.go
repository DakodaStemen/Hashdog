package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func write(t *testing.T, name, body string) string {
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestYAMLAndJSONEquivalent(t *testing.T) {
	y, err := Load(write(t, "c.yaml", "exclude:\n  - '*.log'\n  - var/cache/**\ninclude:\n  - etc/**\n"))
	if err != nil {
		t.Fatal(err)
	}
	j, err := Load(write(t, "c.json", `{"exclude":["*.log","var/cache/**"],"include":["etc/**"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(y, j) || len(y.Exclude) != 2 || len(y.Include) != 1 {
		t.Fatalf("yaml=%+v json=%+v", y, j)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"unknown.yaml":  "excludes: [a]\n",
		"unknown.json":  `{"excludes":["a"]}`,
		"badglob.yaml":  "exclude: ['[']\n",
		"badyaml.yaml":  "exclude: [\n",
		"wrongtype.yml": "exclude: nope\n",
		"c.toml":        "exclude = []\n",
	}
	for name, body := range cases {
		if _, err := Load(write(t, name, body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file accepted")
	}
}

func TestEmptyYAMLOK(t *testing.T) {
	f, err := Load(write(t, "e.yaml", ""))
	if err != nil || len(f.Exclude) != 0 {
		t.Fatalf("%v %+v", err, f)
	}
}
