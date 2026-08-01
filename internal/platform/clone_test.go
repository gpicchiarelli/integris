package platform_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/platform"
)

func TestCloneFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	payload := []byte("clone-payload-v1")
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	mech, err := platform.CloneFile(dst, src)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q want %q", got, payload)
	}
	if mech != platform.PreferredCloneMechanism() && mech != platform.CloneMechanismCopy {
		t.Fatalf("unexpected mechanism %q", mech)
	}
	switch runtime.GOOS {
	case "darwin":
		if mech != platform.CloneMechanismClonefile {
			t.Fatalf("darwin tempdir should clonefile, got %q", mech)
		}
	case "linux":
		// Btrfs/XFS reflink → ficlone; ext4 and others degrade to copy.
		if mech != platform.CloneMechanismFiclone && mech != platform.CloneMechanismCopy {
			t.Fatalf("linux unexpected mechanism %q", mech)
		}
	}
}

func TestCloneFileRejectsExistingDst(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := platform.CloneFile(dst, src); err == nil {
		t.Fatal("expected error for existing dst")
	}
}
