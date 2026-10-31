// Package attack maps file paths to MITRE ATT&CK (Enterprise, Linux) technique
// IDs that an unexpected change to that path is commonly associated with.
//
// This is a triage hint, NOT a detection verdict: a package upgrade also edits
// /usr/bin/*. The map is deliberately small and conservative; it only covers
// well-known persistence / credential / defence-evasion locations. Patterns
// use the glob syntax of package filter and are matched against the absolute
// path, so they only fire when the monitored tree is the real filesystem
// location (e.g. -dir /etc), not a copy under another prefix.
package attack

import (
	"path/filepath"
	"sort"

	"github.com/DakodaStemen/hashdog/internal/filter"
)

// Rule ties a path glob to technique IDs.
type Rule struct {
	Glob       string
	Techniques []string
}

// Rules is the built-in map, in no particular priority; all matches are merged.
//
// Technique IDs (https://attack.mitre.org/techniques/):
//
//	T1136.001 Create Account: Local Account      T1098     Account Manipulation
//	T1098.004 SSH Authorized Keys                T1548.003 Sudo and Sudo Caching
//	T1053.003 Scheduled Task/Job: Cron           T1053.006 Systemd Timers
//	T1543.002 Systemd Service                    T1574.006 Dynamic Linker Hijacking
//	T1546.004 Unix Shell Configuration Mod.      T1037.004 RC Scripts
//	T1556.003 Pluggable Authentication Modules   T1554     Compromise Host Software Binary
//	T1547.006 Kernel Modules and Extensions      T1562.004 Disable or Modify System Firewall
var Rules = []Rule{
	{"/etc/passwd", []string{"T1136.001", "T1098"}},
	{"/etc/shadow", []string{"T1136.001", "T1098"}},
	{"/etc/group", []string{"T1098"}},
	{"/etc/sudoers", []string{"T1548.003"}},
	{"/etc/sudoers.d/**", []string{"T1548.003"}},
	{"/root/.ssh/authorized_keys*", []string{"T1098.004"}},
	{"/home/*/.ssh/authorized_keys*", []string{"T1098.004"}},
	{"/etc/crontab", []string{"T1053.003"}},
	{"/etc/cron.*/**", []string{"T1053.003"}},
	{"/var/spool/cron/**", []string{"T1053.003"}},
	{"/etc/systemd/system/**/*.service", []string{"T1543.002"}},
	{"/usr/lib/systemd/system/*.service", []string{"T1543.002"}},
	{"/lib/systemd/system/*.service", []string{"T1543.002"}},
	{"/etc/systemd/system/**/*.timer", []string{"T1053.006"}},
	{"/usr/lib/systemd/system/*.timer", []string{"T1053.006"}},
	{"/lib/systemd/system/*.timer", []string{"T1053.006"}},
	{"/etc/ld.so.preload", []string{"T1574.006"}},
	{"/etc/ld.so.conf", []string{"T1574.006"}},
	{"/etc/ld.so.conf.d/**", []string{"T1574.006"}},
	{"/etc/profile", []string{"T1546.004"}},
	{"/etc/profile.d/**", []string{"T1546.004"}},
	{"/etc/bash.bashrc", []string{"T1546.004"}},
	{"/etc/bashrc", []string{"T1546.004"}},
	{"/root/.bashrc", []string{"T1546.004"}},
	{"/root/.bash_profile", []string{"T1546.004"}},
	{"/root/.profile", []string{"T1546.004"}},
	{"/home/*/.bashrc", []string{"T1546.004"}},
	{"/home/*/.bash_profile", []string{"T1546.004"}},
	{"/home/*/.profile", []string{"T1546.004"}},
	{"/etc/rc.local", []string{"T1037.004"}},
	{"/etc/init.d/**", []string{"T1037.004"}},
	{"/etc/pam.d/**", []string{"T1556.003"}},
	{"/lib/security/**", []string{"T1556.003"}},
	{"/lib/*/security/**", []string{"T1556.003"}},
	{"/usr/lib/security/**", []string{"T1556.003"}},
	{"/usr/lib/*/security/**", []string{"T1556.003"}},
	{"/bin/**", []string{"T1554"}},
	{"/sbin/**", []string{"T1554"}},
	{"/usr/bin/**", []string{"T1554"}},
	{"/usr/sbin/**", []string{"T1554"}},
	{"/usr/local/bin/**", []string{"T1554"}},
	{"/usr/local/sbin/**", []string{"T1554"}},
	{"/lib/modules/**/*.ko*", []string{"T1547.006"}},
	{"/usr/lib/modules/**/*.ko*", []string{"T1547.006"}},
	{"/etc/modules", []string{"T1547.006"}},
	{"/etc/modules-load.d/**", []string{"T1547.006"}},
	{"/etc/iptables/**", []string{"T1562.004"}},
	{"/etc/nftables.conf", []string{"T1562.004"}},
}

// Lookup returns the sorted, de-duplicated technique IDs for path, or nil.
// Relative paths are made absolute first.
func Lookup(path string) []string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil
	}
	abs = filepath.ToSlash(abs)
	seen := map[string]bool{}
	for _, r := range Rules {
		if filter.Match(r.Glob, abs) {
			for _, t := range r.Techniques {
				seen[t] = true
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
