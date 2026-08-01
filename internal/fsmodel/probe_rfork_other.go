//go:build unix && !darwin

package fsmodel

import (
	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/plan"
)

// probeResourceFork reports HFS+/APFS resource forks unavailable off Darwin.
func probeResourceFork(dir string) Fact {
	_ = dir
	return Fact{
		ID:           plan.CapResourceFork,
		Result:       plan.ResultUnrepresentable,
		DetailDigest: codec.SHA256([]byte("namedfork-unavailable")),
	}
}
