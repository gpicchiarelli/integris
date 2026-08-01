//go:build openbsd || !unix

package platform_test

import (
	"os"
	"testing"

	"github.com/gpicchiarelli/integris/internal/platform"
)

func TestSendFileUnsupported(t *testing.T) {
	if platform.SendFileSupported() {
		t.Fatal("expected sendfile unsupported")
	}
	if platform.SendFileMechanism() != "" {
		t.Fatalf("mechanism=%q", platform.SendFileMechanism())
	}
	f, err := os.CreateTemp(t.TempDir(), "sf")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, _, err := platform.SendFile(f, f, 0, 1); err == nil {
		t.Fatal("expected unavailable error")
	}
}
