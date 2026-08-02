//go:build freebsd

package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"golang.org/x/sys/unix"
)

func TestRequireAmbientExecDeniedAfterCapEnter(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	// Unlike NEG-FS-READ, a successful ambient exec replaces the process image,
	// so there is no in-process UnexpectedAllow observation before CapEnter.
	if confine.NegativeCapMode().Status != confine.StatusAvailable {
		if err := unix.CapEnter(); err != nil {
			t.Fatal(err)
		}
	}
	if err := confine.RequireAmbientExecDenied(); err != nil {
		t.Fatal(err)
	}
}
