//go:build unix && !(darwin || freebsd || openbsd)

package fsmodel

import (
	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/plan"
)

// probeBSDFlags reports BSD file flags unavailable on this Unix port.
func probeBSDFlags(dir string) Fact {
	_ = dir
	return Fact{
		ID:           plan.CapBSDFlags,
		Result:       plan.ResultUnrepresentable,
		DetailDigest: codec.SHA256([]byte("chflags-unavailable")),
	}
}
