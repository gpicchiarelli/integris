//go:build openbsd

package fsmodel

import (
	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/plan"
)

// OpenBSD x/sys lacks SEEK_DATA/SEEK_HOLE and Linux-style xattr helpers.
func probeSparse(dir string) Fact {
	_ = dir
	return Fact{ID: plan.CapSparse, Result: plan.ResultUnrepresentable, DetailDigest: codec.SHA256([]byte("openbsd-no-seek-hole"))}
}

func probeXattr(dir string) Fact {
	_ = dir
	return Fact{ID: plan.CapXattr, Result: plan.ResultUnrepresentable, DetailDigest: codec.SHA256([]byte("openbsd-no-xattr-api"))}
}
