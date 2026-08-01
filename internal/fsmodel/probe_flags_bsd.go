//go:build darwin || freebsd || openbsd

package fsmodel

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/plan"
	"golang.org/x/sys/unix"
)

// probeBSDFlags exercises chflags on a scratch file (Darwin/FreeBSD/OpenBSD).
func probeBSDFlags(dir string) Fact {
	path := filepath.Join(dir, "flags-probe")
	if err := os.WriteFile(path, []byte("f"), 0o600); err != nil {
		return Fact{ID: plan.CapBSDFlags, Result: plan.ResultUnknown}
	}
	defer os.Remove(path)
	flags := 0
	if runtime.GOOS == "darwin" {
		flags = unix.UF_NODUMP
	}
	if err := unix.Chflags(path, flags); err != nil {
		return Fact{ID: plan.CapBSDFlags, Result: plan.ResultUnrepresentable, DetailDigest: codec.SHA256([]byte("chflags"))}
	}
	if flags != 0 {
		_ = unix.Chflags(path, 0)
	}
	return Fact{ID: plan.CapBSDFlags, Result: plan.ResultLossless, DetailDigest: codec.SHA256([]byte("chflags"))}
}
