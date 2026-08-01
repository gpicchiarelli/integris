//go:build unix && !darwin

package resource_test

import (
	"errors"
	"testing"

	"github.com/gpicchiarelli/integris/internal/resource"
	"golang.org/x/sys/unix"
)

func TestASSaturationHarness(t *testing.T) {
	var before unix.Rlimit
	if err := unix.Getrlimit(asLimitResource(), &before); err != nil {
		t.Fatal(err)
	}
	// Soft ceiling well above typical Go test RSS but below a deliberate 1GiB mmap.
	const soft = 256 << 20
	const want = 1 << 30
	err := resource.WithSoftAS(soft, func() error {
		b, err := unix.Mmap(-1, 0, want, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
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
