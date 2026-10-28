//go:build unix && !linux && !darwin && !freebsd && !netbsd

package merkle

import "syscall"

// No portable ctime here: the stat cache is disabled (every scan rehashes).
func ctimeNanos(*syscall.Stat_t) (int64, bool) { return 0, false }
