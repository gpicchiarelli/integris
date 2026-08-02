//go:build freebsd

package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"golang.org/x/sys/unix"
)

func TestNegativeCapModeAfterCapEnter(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	before := confine.NegativeCapMode()
	if before.Status != confine.StatusUnexpectedAllow {
		t.Fatalf("before CapEnter: %+v", before)
	}
	if err := unix.CapEnter(); err != nil {
		t.Fatal(err)
	}
	after := confine.NegativeCapMode()
	if after.Status != confine.StatusAvailable {
		t.Fatalf("after CapEnter: %+v", after)
	}
}
