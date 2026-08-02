//go:build unix

package launcher_test

import (
	"os"
	"strconv"
	"testing"

	"github.com/gpicchiarelli/integris/internal/launcher"
)

func TestClaimAllowRootFDsEmpty(t *testing.T) {
	if got := launcher.ClaimAllowRootFDs(""); got != nil {
		t.Fatalf("got %#v", got)
	}
	if got := launcher.ClaimAllowRootFDs("  , ,"); len(got) != 0 {
		t.Fatalf("got %#v", got)
	}
}

func TestClaimAllowRootFDsAdopts(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	files := launcher.ClaimAllowRootFDs(strconv.Itoa(int(r.Fd())))
	if len(files) != 1 || files[0] == nil {
		t.Fatalf("got %#v", files)
	}
	// Same underlying fd as r; leave ownership with the original *os.File.
}
