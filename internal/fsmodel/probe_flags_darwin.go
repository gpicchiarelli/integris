//go:build darwin

package fsmodel

import (
	"os"
	"path/filepath"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/plan"
	"golang.org/x/sys/unix"
)

// probeBSDFlags exercises chflags on a scratch file (Darwin).
func probeBSDFlags(dir string) Fact {
	path := filepath.Join(dir, "flags-probe")
	if err := os.WriteFile(path, []byte("f"), 0o600); err != nil {
		return Fact{ID: plan.CapBSDFlags, Result: plan.ResultUnknown}
	}
	defer os.Remove(path)
	if err := unix.Chflags(path, unix.UF_NODUMP); err != nil {
		return Fact{ID: plan.CapBSDFlags, Result: plan.ResultUnrepresentable, DetailDigest: codec.SHA256([]byte("chflags"))}
	}
	_ = unix.Chflags(path, 0)
	return Fact{ID: plan.CapBSDFlags, Result: plan.ResultLossless, DetailDigest: codec.SHA256([]byte("chflags"))}
}
