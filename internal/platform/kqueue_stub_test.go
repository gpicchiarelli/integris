//go:build !(darwin || freebsd || openbsd || netbsd || dragonfly)

package platform_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/platform"
)

func TestVNodeWatchUnsupported(t *testing.T) {
	if platform.VNodeWatchSupported() {
		t.Fatal("expected unsupported")
	}
	if platform.VNodeWatchMechanism() != "" {
		t.Fatalf("mechanism=%q", platform.VNodeWatchMechanism())
	}
	if _, err := platform.OpenVNodeWatch("/tmp", platform.VNodeNoteWrite); err == nil {
		t.Fatal("expected unavailable error")
	}
}
