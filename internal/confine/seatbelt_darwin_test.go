//go:build darwin && cgo

package confine_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestSeatbeltDeniesCreateAndExec(t *testing.T) {
	r := confine.ApplyEngineering(authority.RoleParser)
	if len(r.Findings) == 0 || r.Findings[0].Status != confine.StatusAvailable {
		t.Fatalf("apply: %+v", r.Findings)
	}
	p := filepath.Join(os.TempDir(), "integris-sb-probe-unit")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err == nil {
		_ = f.Close()
		_ = os.Remove(p)
		t.Fatal("expected create deny after seatbelt")
	}
	t.Logf("create denied: %v", err)
	neg := confine.NegativeFSOpen()
	if neg.Status != confine.StatusDeniedExpected {
		t.Fatalf("NEG-FS: %+v", neg)
	}
	rd := confine.NegativeFSRead()
	if rd.Status != confine.StatusDeniedExpected {
		t.Fatalf("NEG-FS-READ: %+v", rd)
	}
	ex := confine.NegativeExec()
	if ex.Status != confine.StatusDeniedExpected {
		t.Fatalf("NEG-EXEC: %+v", ex)
	}
	net := confine.NegativeRoleNet(authority.RoleParser)
	if net.Status != confine.StatusDeniedExpected {
		t.Fatalf("NEG-ROLE-NET: %+v", net)
	}
}
