package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireArchiveFSPathFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "NEG-FS-PATH", Status: confine.StatusAvailable, Detail: "open ok",
	}
	if err := confine.RequireArchiveFSPathFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "NEG-FS-PATH", Status: confine.StatusSkipped, Detail: "no roots",
	}
	if err := confine.RequireArchiveFSPathFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "NEG-FS-PATH", Status: confine.StatusUnavailable, Detail: "open failed",
	}
	if err := confine.RequireArchiveFSPathFinding(bad); err == nil {
		t.Fatal("expected unavailable refusal")
	}

	wrong := confine.Finding{ID: "NEG-FS-WRITE", Status: confine.StatusAvailable}
	if err := confine.RequireArchiveFSPathFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}
}

func TestRequireArchiveFSPathAvailableNonArchive(t *testing.T) {
	if err := confine.RequireArchiveFSPathAvailable(authority.RoleAuth, confine.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
}
