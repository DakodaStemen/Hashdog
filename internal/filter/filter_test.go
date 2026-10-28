package filter

import "testing"

func TestSkip(t *testing.T) {
	r, err := New(nil, []string{"*.log", "tmp/", "/var/cache/*", "**/node_modules", "home/**/.cache", "etc/ssh/ssh_host_?_key"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		rel   string
		isDir bool
		skip  bool
	}{
		{"app.log", false, true},
		{"a/b/app.log", false, true},
		{"a/b/app.txt", false, false},
		{"tmp", true, true},
		{"tmp", false, false}, // trailing / means directories only
		{"a/tmp", true, true},
		{"var/cache/x", false, true},
		{"var/cache", true, false},
		{"var/other/cache/x", false, false},
		{"node_modules", true, true},
		{"a/b/node_modules", true, true},
		{"home/u/.cache", true, true},
		{"home/.cache", true, true}, // ** matches zero segments
		{"home/u/x/.cache", true, true},
		{"homes/u/.cache", true, false},
		{"etc/ssh/ssh_host_a_key", false, true},
		{"etc/ssh/ssh_host_ab_key", false, false},
	}
	for _, c := range cases {
		if got := r.Skip(c.rel, c.isDir); got != c.skip {
			t.Errorf("Skip(%q,dir=%v)=%v want %v", c.rel, c.isDir, got, c.skip)
		}
	}
}

func TestIncludeAndExcludeWins(t *testing.T) {
	r, err := New([]string{"etc/**", "*.conf"}, []string{"etc/secret/**"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		rel   string
		isDir bool
		skip  bool
	}{
		{"etc/passwd", false, false},
		{"opt/app.conf", false, false},
		{"opt/app.bin", false, true},
		{"opt", true, false}, // directories are never filtered by include
		{"etc/secret/k", false, true},
	}
	for _, c := range cases {
		if got := r.Skip(c.rel, c.isDir); got != c.skip {
			t.Errorf("Skip(%q)=%v want %v", c.rel, got, c.skip)
		}
	}
}

func TestBadPatterns(t *testing.T) {
	for _, p := range []string{"", "[", "a**b", "a//b", "/"} {
		if _, err := New(nil, []string{p}); err == nil {
			t.Errorf("pattern %q should be rejected", p)
		}
	}
}

func TestNilAndEqual(t *testing.T) {
	var r *Rules
	if r.Skip("x", false) {
		t.Fatal("nil rules skip nothing")
	}
	a, _ := New(nil, []string{"b", "a", "a"})
	b, _ := New(nil, []string{"a", "b"})
	c, _ := New(nil, []string{"a"})
	if !Equal(a, b) || Equal(a, c) || !Equal(nil, nil) || Equal(a, nil) {
		t.Fatal("Equal broken")
	}
}

func TestMatch(t *testing.T) {
	if !Match("/etc/cron.d/*", "/etc/cron.d/job") || Match("/etc/cron.d/*", "/etc/cron.d/a/b") {
		t.Fatal("anchored match")
	}
	if !Match("/home/*/.ssh/authorized_keys", "/home/bob/.ssh/authorized_keys") {
		t.Fatal("home match")
	}
}
