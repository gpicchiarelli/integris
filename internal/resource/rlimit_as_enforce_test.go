//go:build unix && !darwin

package resource_test

import (
	"errors"
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/resource"
	"golang.org/x/sys/unix"
)

func TestASSaturationHarness(t *testing.T) {
	if runtime.GOOS == "openbsd" {
		// RLIMIT_DATA soft limits do not reliably deny oversized PROT_NONE
		// anonymous mmap on OpenBSD CI (lazy reservation).
		t.Skip("RLIMIT_DATA soft mmap deny not reliable on OpenBSD")
	}
	var before unix.Rlimit
	if err := unix.Getrlimit(asLimitResource(), &before); err != nil {
		t.Fatal(err)
	}
	// Soft ceiling must leave headroom for the Go runtime (a 256MiB ceiling
	// OOMs the harness itself on CI). Keep it above typical test RSS but
	// below a deliberate oversized anonymous mapping.
	const soft = 1 << 30 // 1 GiB
	const want = 4 << 30 // 4 GiB
	err := resource.WithSoftAS(soft, func() error {
		b, err := unix.Mmap(-1, 0, want, unix.PROT_NONE, unix.MAP_ANON|unix.MAP_PRIVATE)
		if err == nil {
			_ = unix.Munmap(b)
			return errors.New("expected mmap failure under lowered address/data soft limit")
		}
		if !errors.Is(err, unix.ENOMEM) {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var after unix.Rlimit
	if err := unix.Getrlimit(asLimitResource(), &after); err != nil {
		t.Fatal(err)
	}
	if after.Cur != before.Cur || after.Max != before.Max {
		t.Fatalf("rlimit not restored: before=%+v after=%+v", before, after)
	}
}
