package recovery_test

import (
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/recovery"
)

func TestFilePersistQuarantineAndConfirm(t *testing.T) {
	root := t.TempDir()
	fp, err := recovery.NewFilePersist(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := fp.SeedStaging("obj", []byte("payload")); err != nil {
		t.Fatal(err)
	}

	p := prefixWithAuthChain(t, false)
	obs := obsOK()
	obs.StagingPresent = true
	obs.PublicationStarted = true

	out, err := recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, fp)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != recovery.StateQuarantined {
		t.Fatalf("state=%s", out.State)
	}
	empty, err := fp.StagingEmpty()
	if err != nil || !empty {
		t.Fatalf("staging empty=%v err=%v", empty, err)
	}
	has, err := fp.QuarantineHas("obj")
	if err != nil || !has {
		t.Fatalf("quarantine has=%v err=%v", has, err)
	}
}

func TestFilePersistConfirmOnRealFS(t *testing.T) {
	root := t.TempDir()
	fp, err := recovery.NewFilePersist(root)
	if err != nil {
		t.Fatal(err)
	}
	p := prefixWithAuthChain(t, false)
	obs := obsOK()
	obs.PublicationLinearized = true
	obs.PublishedContentMatches = true
	obs.PublicationStarted = true

	out, err := recovery.Recover(p, obs, recovery.Policy{AllowConfirm: true, AllowStagingCleanup: true}, fp)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != recovery.StateConfirmed || fp.Confirms != 1 {
		t.Fatalf("state=%s confirms=%d", out.State, fp.Confirms)
	}
	info, err := filepath.Glob(filepath.Join(root, "confirm.log"))
	if err != nil || len(info) != 1 {
		t.Fatalf("confirm.log missing: %v %v", info, err)
	}

	// Idempotent re-entry with journal confirmation present.
	p2 := prefixWithAuthChain(t, true)
	out2, err := recovery.RecoverAgain(p2, obs, recovery.Policy{AllowConfirm: true}, fp)
	if err != nil {
		t.Fatal(err)
	}
	if !out2.IdempotentNoop || fp.Confirms != 1 {
		t.Fatalf("idempotent fail: %+v confirms=%d", out2, fp.Confirms)
	}
}

func TestFilePersistFaultBeforeQuarantine(t *testing.T) {
	root := t.TempDir()
	fp, err := recovery.NewFilePersist(root)
	if err != nil {
		t.Fatal(err)
	}
	fp.FailAt = recovery.LabelPPublishRename
	if err := fp.SeedStaging("obj", []byte("x")); err != nil {
		t.Fatal(err)
	}
	p := prefixWithAuthChain(t, false)
	obs := obsOK()
	obs.StagingPresent = true
	obs.PublicationStarted = true
	_, err = recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, fp)
	if err == nil || !recovery.AsKind(err, recovery.KindIO) {
		t.Fatalf("want IO fault, got %v", err)
	}
	has, err := fp.QuarantineHas("obj")
	if err != nil || has {
		t.Fatalf("quarantine must be empty after pre-rename fault: has=%v err=%v", has, err)
	}
}
