//go:build !freebsd

package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestNegativeCapModeSkipped(t *testing.T) {
	f := confine.NegativeCapMode()
	if f.Status != confine.StatusSkipped {
		t.Fatalf("%+v", f)
	}
}
