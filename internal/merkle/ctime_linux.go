//go:build linux

package merkle

import "syscall"

func ctimeNanos(st *syscall.Stat_t) (int64, bool) {
	return int64(st.Ctim.Sec)*1e9 + int64(st.Ctim.Nsec), true
}
