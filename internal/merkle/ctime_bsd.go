//go:build darwin || freebsd || netbsd

package merkle

import "syscall"

func ctimeNanos(st *syscall.Stat_t) (int64, bool) {
	return int64(st.Ctimespec.Sec)*1e9 + int64(st.Ctimespec.Nsec), true
}
