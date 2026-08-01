//go:build darwin

package fsmodel

import (
	"os"
	"path/filepath"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/plan"
)

// probeResourceFork round-trips bytes through path/..namedfork/rsrc.
func probeResourceFork(dir string) Fact {
	path := filepath.Join(dir, "rfork-probe")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		return Fact{ID: plan.CapResourceFork, Result: plan.ResultUnknown}
	}
	defer os.Remove(path)
	rf := path + "/..namedfork/rsrc"
	want := []byte("rfork")
	if err := os.WriteFile(rf, want, 0o600); err != nil {
		return Fact{ID: plan.CapResourceFork, Result: plan.ResultUnrepresentable, DetailDigest: codec.SHA256([]byte("namedfork"))}
	}
	got, err := os.ReadFile(rf)
	if err != nil || string(got) != string(want) {
		return Fact{ID: plan.CapResourceFork, Result: plan.ResultUnrepresentable, DetailDigest: codec.SHA256([]byte("namedfork"))}
	}
	return Fact{ID: plan.CapResourceFork, Result: plan.ResultLossless, DetailDigest: codec.SHA256([]byte("namedfork"))}
}
