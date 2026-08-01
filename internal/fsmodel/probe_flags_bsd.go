//go:build freebsd || openbsd

package fsmodel

import (
	"os"
	"path/filepath"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/plan"
	"golang.org/x/sys/unix"
)

// probeBSDFlags exercises chflags(2) on FreeBSD/OpenBSD (x/sys lacks UF_NODUMP there).
func probeBSDFlags(dir string) Fact {
	path := filepath.Join(dir, "flags-probe")
	if err := os.WriteFile(path, []byte("f"), 0o600); err != nil {
		return Fact{ID: plan.CapBSDFlags, Result: plan.ResultUnknown}
	}
	defer os.Remove(path)
	// flags=0 still exercises the syscall; NODUMP constant is Darwin-only in x/sys.
	if err := unix.Chflags(path, 0); err != nil {
		return Fact{ID: plan.CapBSDFlags, Result: plan.ResultUnrepresentable, DetailDigest: codec.SHA256([]byte("chflags"))}
	}
	return Fact{ID: plan.CapBSDFlags, Result: plan.ResultLossless, DetailDigest: codec.SHA256([]byte("chflags"))}
}
