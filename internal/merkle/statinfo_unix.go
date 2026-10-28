//go:build unix

package merkle

import (
	"os"
	"syscall"
)

// statInfo extracts the identity/ownership fields Go's os.FileInfo hides.
// ok is false when the platform could not provide them.
type statInfo struct {
	uid, gid int
	ino, dev uint64
	ctime    int64 // UnixNano; 0 when the platform has no usable ctime
	hasOwner bool
	hasCtime bool
}

func statOf(fi os.FileInfo) statInfo {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return statInfo{uid: -1, gid: -1}
	}
	s := statInfo{uid: int(st.Uid), gid: int(st.Gid), ino: uint64(st.Ino), dev: uint64(st.Dev), hasOwner: true}
	s.ctime, s.hasCtime = ctimeNanos(st)
	return s
}
