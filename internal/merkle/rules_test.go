package merkle_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DakodaStemen/hashdog/internal/filter"
	"github.com/DakodaStemen/hashdog/internal/merkle"
)

func TestExcludedPathsDoNotAffectRoot(t *testing.T) {
	root := makeTree(t, map[string]string{"etc/passwd": "p", "var/log/a.log": "1", "var/cache/x/y": "c"})
	rules, err := filter.New(nil, []string{"*.log", "var/cache"})
	if err != nil {
		t.Fatal(err)
	}
	opt := merkle.Options{Rules: rules}
	before, _ := merkle.BuildWith(root, opt)
	os.WriteFile(filepath.Join(root, "var/log/a.log"), []byte("changed"), 0o644)
	os.WriteFile(filepath.Join(root, "var/log/b.log"), []byte("new"), 0o644)
	os.WriteFile(filepath.Join(root, "var/cache/x/y"), []byte("changed"), 0o644)
	os.WriteFile(filepath.Join(root, "var/cache/z"), []byte("new"), 0o644)
	after, _ := merkle.BuildWith(root, opt)
	if before.Hash != after.Hash {
		t.Fatalf("excluded changes altered root: %+v", merkle.Diff(before, after))
	}
	// a non-excluded change is still seen
	os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("evil"), 0o644)
	after, _ = merkle.BuildWith(root, opt)
	if ch := merkle.Diff(before, after); len(ch) != 1 || filepath.Base(ch[0].Path) != "passwd" {
		t.Fatalf("got %+v", ch)
	}
	// and without rules the excluded files are present
	full, _ := merkle.Build(root)
	if full.Hash == after.Hash {
		t.Fatal("rules had no effect")
	}
}

func TestIncludeAllowList(t *testing.T) {
	root := makeTree(t, map[string]string{"etc/passwd": "p", "etc/hosts": "h", "tmp/junk": "j", "README": "r"})
	rules, _ := filter.New([]string{"etc/**"}, nil)
	tree, _ := merkle.BuildWith(root, merkle.Options{Rules: rules})
	var files []string
	var walk func(*merkle.Node)
	walk = func(n *merkle.Node) {
		if n.Kind == merkle.File {
			rel, _ := filepath.Rel(root, n.Path)
			files = append(files, rel)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(tree)
	if len(files) != 2 || files[0] != "etc/hosts" || files[1] != "etc/passwd" {
		t.Fatalf("got %v", files)
	}
}
