//go:build !unix

package merkle

import "os"

type statInfo struct {
	uid, gid int
	ino, dev uint64
	ctime    int64
	hasOwner bool
	hasCtime bool
}

// Non-unix: no uid/gid/inode/ctime; owner is recorded as -1 and the stat
// cache is disabled (every scan rehashes).
func statOf(os.FileInfo) statInfo { return statInfo{uid: -1, gid: -1} }
