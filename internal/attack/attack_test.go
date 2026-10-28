package attack

import (
	"reflect"
	"regexp"
	"testing"
)

func TestLookup(t *testing.T) {
	cases := map[string][]string{
		"/etc/passwd":                                           {"T1098", "T1136.001"},
		"/etc/sudoers.d/90-evil":                                {"T1548.003"},
		"/home/bob/.ssh/authorized_keys":                        {"T1098.004"},
		"/root/.ssh/authorized_keys2":                           {"T1098.004"},
		"/etc/cron.daily/backup":                                {"T1053.003"},
		"/etc/systemd/system/multi-user.target.wants/x.service": {"T1543.002"},
		"/etc/systemd/system/x.service":                         {"T1543.002"},
		"/etc/ld.so.preload":                                    {"T1574.006"},
		"/usr/bin/ssh":                                          {"T1554"},
		"/lib/x86_64-linux-gnu/security/pam_unix.so":            {"T1556.003"},
		"/etc/pam.d/sshd":                                       {"T1556.003"},
		"/lib/modules/6.1.0/kernel/x.ko.xz":                     {"T1547.006"},
		"/etc/hostname":                                         nil,
		"/home/bob/notes.txt":                                   nil,
		"/tmp/etc/passwd":                                       nil, // anchored: only the real /etc
	}
	for p, want := range cases {
		if got := Lookup(p); !reflect.DeepEqual(got, want) {
			t.Errorf("Lookup(%q)=%v want %v", p, got, want)
		}
	}
}

func TestRelativePathsAreAbsolutised(t *testing.T) {
	if Lookup("passwd") != nil { // cwd is not /etc
		t.Fatal("relative path must not match absolute globs by accident")
	}
}

func TestRuleTableWellFormed(t *testing.T) {
	id := regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	for _, r := range Rules {
		if r.Glob == "" || r.Glob[0] != '/' || len(r.Techniques) == 0 {
			t.Errorf("bad rule %+v", r)
		}
		for _, tech := range r.Techniques {
			if !id.MatchString(tech) {
				t.Errorf("%s: bad technique id %q", r.Glob, tech)
			}
		}
	}
}
