//go:build darwin && cgo

package confine_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
)

func TestSeatbeltAllowRootAndDeniesAmbient(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	root := launcher.CapEnterTempDir(t)
	norm, err := confine.NormalizeAllowRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	root = norm[0]
	marker := filepath.Join(root, "marker.txt")
	if err := os.WriteFile(marker, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := confine.ApplyOptions{AllowRoots: []string{root}}
	fsReadExisted := confine.AmbientFSReadProbeExisted()
	r := confine.ApplyEngineeringOpts(authority.RoleApply, opts)
	if len(r.Findings) == 0 || r.Findings[0].Status != confine.StatusAvailable {
		t.Fatalf("apply: %+v", r.Findings)
	}
	f, err := os.Open(marker)
	if err != nil {
		t.Fatalf("allow-root open: %v", err)
	}
	_ = f.Close()

	neg := confine.NegativeFSOpen()
	if neg.Status != confine.StatusDeniedExpected {
		t.Fatalf("NEG-FS outside root: %+v", neg)
	}
	if err := confine.RequireAmbientFSOpenDenied(); err != nil {
		t.Fatal(err)
	}
	if !fsReadExisted {
		t.Fatal("NEG-FS-READ probe path missing before Seatbelt")
	}
	rd := confine.NegativeFSRead(fsReadExisted)
	if rd.Status != confine.StatusDeniedExpected {
		t.Fatalf("NEG-FS-READ: %+v", rd)
	}
	path := confine.NegativeFSPath(authority.RoleApply, opts)
	if path.Status != confine.StatusAvailable {
		t.Fatalf("NEG-FS-PATH: %+v", path)
	}
	wr := confine.NegativeFSPathWrite(authority.RoleApply, opts)
	if wr.Status != confine.StatusAvailable {
		t.Fatalf("NEG-FS-WRITE apply: %+v", wr)
	}
	ex := confine.NegativeExec()
	if ex.Status != confine.StatusDeniedExpected {
		t.Fatalf("NEG-EXEC: %+v", ex)
	}
	net := confine.NegativeRoleNet(authority.RoleApply)
	if net.Status != confine.StatusDeniedExpected {
		t.Fatalf("NEG-ROLE-NET: %+v", net)
	}
	if err := confine.RequireAmbientRoleNetDenied(authority.RoleApply); err != nil {
		t.Fatal(err)
	}
	if err := confine.RequireAmbientExecDenied(); err != nil {
		t.Fatal(err)
	}
}

func TestSeatbeltIndexDeniesAllowRootWrite(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	root := launcher.CapEnterTempDir(t)
	norm, err := confine.NormalizeAllowRoots([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	opts := confine.ApplyOptions{AllowRoots: norm}
	r := confine.ApplyEngineeringOpts(authority.RoleIndex, opts)
	if len(r.Findings) == 0 || r.Findings[0].Status != confine.StatusAvailable {
		t.Fatalf("apply: %+v", r.Findings)
	}
	wr := confine.NegativeFSPathWrite(authority.RoleIndex, opts)
	if wr.Status != confine.StatusDeniedExpected {
		t.Fatalf("NEG-FS-WRITE index: %+v", wr)
	}
	if err := confine.RequireArchiveFSWriteDenied(authority.RoleIndex, opts); err != nil {
		t.Fatal(err)
	}
}
