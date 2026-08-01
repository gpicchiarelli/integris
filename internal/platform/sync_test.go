package platform_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/platform"
)

func TestSyncFileAndDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob")
	if err := os.WriteFile(path, []byte("durable"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := platform.SyncFile(f); err != nil {
		t.Fatal(err)
	}
	if err := platform.SyncDir(dir); err != nil {
		t.Fatal(err)
	}
	if platform.DurabilityMechanism() == "" {
		t.Fatal("empty durability mechanism")
	}
	if runtime.GOOS == "darwin" && platform.DurabilityMechanism() != "F_FULLFSYNC" {
		t.Fatalf("darwin want F_FULLFSYNC, got %q", platform.DurabilityMechanism())
	}
}

func TestSyncFileNil(t *testing.T) {
	if err := platform.SyncFile(nil); err == nil {
		t.Fatal("expected error")
	}
}
