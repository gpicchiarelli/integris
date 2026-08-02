package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireArchiveFSWriteFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "NEG-FS-WRITE", Status: confine.StatusDeniedExpected, Detail: "denied",
	}
	if err := confine.RequireArchiveFSWriteFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "NEG-FS-WRITE", Status: confine.StatusSkipped, Detail: "no roots",
	}
	if err := confine.RequireArchiveFSWriteFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "NEG-FS-WRITE", Status: confine.StatusUnexpectedAllow, Detail: "wrote",
	}
	if err := confine.RequireArchiveFSWriteFinding(bad); err == nil {
		t.Fatal("expected unexpected_allow refusal")
	}

	available := confine.Finding{
		ID: "NEG-FS-WRITE", Status: confine.StatusAvailable, Detail: "wrote",
	}
	if err := confine.RequireArchiveFSWriteFinding(available); err == nil {
		t.Fatal("expected available refusal for readonly require")
	}

	wrong := confine.Finding{ID: "NEG-FS-OPEN", Status: confine.StatusDeniedExpected}
	if err := confine.RequireArchiveFSWriteFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}

	unavailable := confine.Finding{
		ID: "NEG-FS-WRITE", Status: confine.StatusUnavailable, Detail: "probe path exists",
	}
	if err := confine.RequireArchiveFSWriteFinding(unavailable); err == nil {
		t.Fatal("expected unavailable refusal")
	}
}

func TestRequireArchiveFSWriteDeniedNonReadonly(t *testing.T) {
	// Apply is ArchiveFSReadWrite — Require is a no-op without probing.
	if err := confine.RequireArchiveFSWriteDenied(authority.RoleApply, confine.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := confine.RequireArchiveFSWriteDenied(authority.RoleAuth, confine.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestRequireArchiveFSWriteAvailableFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "NEG-FS-WRITE", Status: confine.StatusAvailable, Detail: "wrote",
	}
	if err := confine.RequireArchiveFSWriteAvailableFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "NEG-FS-WRITE", Status: confine.StatusSkipped, Detail: "no roots",
	}
	if err := confine.RequireArchiveFSWriteAvailableFinding(skip); err != nil {
		t.Fatal(err)
	}

	denied := confine.Finding{
		ID: "NEG-FS-WRITE", Status: confine.StatusDeniedExpected, Detail: "denied",
	}
	if err := confine.RequireArchiveFSWriteAvailableFinding(denied); err == nil {
		t.Fatal("expected denied refusal for readwrite require")
	}

	unavailable := confine.Finding{
		ID: "NEG-FS-WRITE", Status: confine.StatusUnavailable, Detail: "failed",
	}
	if err := confine.RequireArchiveFSWriteAvailableFinding(unavailable); err == nil {
		t.Fatal("expected unavailable refusal")
	}

	wrong := confine.Finding{ID: "NEG-FS-PATH", Status: confine.StatusAvailable}
	if err := confine.RequireArchiveFSWriteAvailableFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}
}

func TestRequireArchiveFSWriteAvailableNonReadWrite(t *testing.T) {
	if err := confine.RequireArchiveFSWriteAvailable(authority.RoleIndex, confine.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := confine.RequireArchiveFSWriteAvailable(authority.RoleAuth, confine.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
}
