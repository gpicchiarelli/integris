//go:build unix

package e2e_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/deletion"
	"github.com/gpicchiarelli/integris/internal/path"
	"github.com/gpicchiarelli/integris/internal/session"
)

func TestM1SessionThenPathOS(t *testing.T) {
	s := session.New([]session.Version{2, 3})
	for _, step := range []error{
		s.Negotiate(), s.Authenticate(), s.AuthorizeArchive(), s.Activate(),
	} {
		if step != nil {
			t.Fatal(step)
		}
	}
	if err := s.Invariants(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, ident, err := path.OpenOSRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	chain, err := path.Resolve(context.Background(), root, [][]byte{[]byte("f")}, path.ResolveOpts{
		Root: ident, ExpectFinal: path.TypeFile,
	}, path.DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
}

func TestM1DeletionGateWithQuarantineAT(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "obj"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	th := deletion.Thresholds{
		MaxObjectCount: 10, MaxPercentBPS: 5000, MaxLogicalBytes: 1 << 20,
		MaxPhysicalBytes: 1 << 20, MaxPathClassCount: 10, RequireCompleteSrc: true,
	}
	obs := deletion.Observation{
		ObjectCount: 1, ArchiveObjectCount: 10, LogicalBytes: 4, PhysicalBytes: 4,
		PathClassCount: 1, SourceComplete: true, SameVolume: true,
		QuarantineCapacity: 1 << 20, RootSentinelOK: true, VolumeAuthorized: true,
	}
	auth := deletion.Authorization{
		PlanDigest: dig("p"), ConfigDigest: dig("c"), CapabilityDigest: dig("k"),
		DestructiveAuth: dig("d"),
	}
	d, err := deletion.Evaluate(th, obs, auth)
	if err != nil {
		t.Fatal(err)
	}
	qp, err := deletion.BuildQuarantinePlan([]byte("obj"), []byte("q-obj"), dig("o"), dig("p"), dig("a"))
	if err != nil {
		t.Fatal(err)
	}
	if err := deletion.ExecuteQuarantineMoveAT(root, d, qp); err != nil {
		t.Fatal(err)
	}
}
