//go:build freebsd

package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
	"golang.org/x/sys/unix"
)

func TestRequireCapModeAvailableAfterCapEnter(t *testing.T) {
	if err := confine.RequireCapModeAvailable(); err == nil {
		t.Fatal("expected refuse before CapEnter")
	}
	if err := unix.CapEnter(); err != nil {
		t.Fatal(err)
	}
	if err := confine.RequireCapModeAvailable(); err != nil {
		t.Fatal(err)
	}
}
