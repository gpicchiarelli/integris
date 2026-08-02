//go:build freebsd

package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
	"golang.org/x/sys/unix"
)

func TestRequireAmbientFSReadDeniedAfterCapEnter(t *testing.T) {
	// CapEnter is process-wide; earlier freebsd CapEnter tests may have entered.
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
