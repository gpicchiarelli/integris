//go:build freebsd

package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"golang.org/x/sys/unix"
)

func TestRequireAmbientFSReadDeniedAfterCapEnter(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	if confine.NegativeCapMode().Status != confine.StatusAvailable {
		if err := confine.RequireAmbientFSReadDenied(); err == nil {
			t.Fatal("expected refuse before CapEnter")
		}
		if err := unix.CapEnter(); err != nil {
			t.Fatal(err)
		}
	}
	if err := confine.RequireAmbientFSReadDenied(); err != nil {
		t.Fatal(err)
	}
}

func TestRequireAmbientFSOpenDeniedAfterCapEnter(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	if confine.NegativeCapMode().Status != confine.StatusAvailable {
		if err := confine.RequireAmbientFSOpenDenied(); err == nil {
			t.Fatal("expected refuse before CapEnter")
		}
		if err := unix.CapEnter(); err != nil {
			t.Fatal(err)
		}
	}
	if err := confine.RequireAmbientFSOpenDenied(); err != nil {
		t.Fatal(err)
	}
}
