package launcher_test

import (
	"os"
	"testing"

	"github.com/gpicchiarelli/integris/internal/launcher"
)

func TestInTestSubprocess(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	if os.Getenv("INTEGRIS_TEST_CHILD") != "1" {
		t.Fatal("expected child env in subprocess")
	}
}
