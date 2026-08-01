//go:build unix && !openbsd

package fsmodel

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/plan"
	"golang.org/x/sys/unix"
)

func xattrName() string {
	// Linux requires a user.* namespace for unprivileged setxattr.
	if runtime.GOOS == "linux" {
		return "user.integris.probe"
	}
	return "integris.probe"
}

// probeSparse detects holey files via SEEK_HOLE / SEEK_DATA on a gapped write.
func probeSparse(dir string) Fact {
	path := filepath.Join(dir, "sparse-probe")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Fact{ID: plan.CapSparse, Result: plan.ResultUnknown}
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(path)
	}()
	const gap int64 = 1 << 20 // 1 MiB hole between extents
	if _, err := f.WriteAt([]byte("head"), 0); err != nil {
		return Fact{ID: plan.CapSparse, Result: plan.ResultUnknown}
	}
	if _, err := f.WriteAt([]byte("tail"), gap); err != nil {
		return Fact{ID: plan.CapSparse, Result: plan.ResultUnknown}
	}
	hole, err := f.Seek(0, unix.SEEK_HOLE)
	if err != nil {
		return Fact{ID: plan.CapSparse, Result: plan.ResultUnrepresentable, DetailDigest: codec.SHA256([]byte("seek-hole"))}
	}
	if hole > 0 && hole < gap {
		return Fact{ID: plan.CapSparse, Result: plan.ResultLossless, DetailDigest: codec.SHA256([]byte("seek-hole"))}
	}
	// Some filesystems only report EOF as a hole; SEEK_DATA from mid-gap
	// should jump to the second extent if sparse.
	data, err := f.Seek(4096, unix.SEEK_DATA)
	if err == nil && data == gap {
		return Fact{ID: plan.CapSparse, Result: plan.ResultLossless, DetailDigest: codec.SHA256([]byte("seek-data"))}
	}
	return Fact{ID: plan.CapSparse, Result: plan.ResultUnrepresentable, DetailDigest: codec.SHA256([]byte("no-hole"))}
}

// probeXattr round-trips an extended attribute on a scratch file.
func probeXattr(dir string) Fact {
	path := filepath.Join(dir, "xattr-probe")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		return Fact{ID: plan.CapXattr, Result: plan.ResultUnknown}
	}
	defer os.Remove(path)
	key := xattrName()
	want := []byte("1")
	if err := unix.Setxattr(path, key, want, 0); err != nil {
		return Fact{ID: plan.CapXattr, Result: plan.ResultUnrepresentable, DetailDigest: codec.SHA256([]byte(key))}
	}
	buf := make([]byte, 64)
	n, err := unix.Getxattr(path, key, buf)
	if err != nil || n != len(want) || string(buf[:n]) != string(want) {
		return Fact{ID: plan.CapXattr, Result: plan.ResultUnrepresentable, DetailDigest: codec.SHA256([]byte(key))}
	}
	_ = unix.Removexattr(path, key)
	return Fact{ID: plan.CapXattr, Result: plan.ResultLossless, DetailDigest: codec.SHA256([]byte(key))}
}
