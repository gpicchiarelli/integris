//go:build unix

package resource_test

import (
	"errors"
	"os"
	"testing"

	"github.com/gpicchiarelli/integris/internal/resource"
	"golang.org/x/sys/unix"
)

func TestNOFILESaturationHarness(t *testing.T) {
	var before unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &before); err != nil {
		t.Fatal(err)
	}
	const soft = 64
	err := resource.WithSoftNOFILE(soft, func() error {
		var fds []*os.File
		defer func() {
			for _, f := range fds {
				_ = f.Close()
			}
		}()
		sawEMFILE := false
		for i := 0; i < int(soft)+64; i++ {
			f, err := os.Open(os.DevNull)
			if err != nil {
				if errors.Is(err, unix.EMFILE) || errors.Is(err, unix.ENFILE) {
					sawEMFILE = true
					break
				}
				return err
			}
			fds = append(fds, f)
		}
		if !sawEMFILE {
			return errors.New("expected EMFILE/ENFILE under lowered NOFILE soft limit")
		}
		if len(fds) == 0 {
			return errors.New("EMFILE with zero successful opens")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var after unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &after); err != nil {
		t.Fatal(err)
	}
	if after.Cur != before.Cur || after.Max != before.Max {
		t.Fatalf("rlimit not restored: before=%+v after=%+v", before, after)
	}
}

func TestWithSoftNOFILERejectsZero(t *testing.T) {
	if err := resource.WithSoftNOFILE(0, func() error { return nil }); err == nil {
		t.Fatal("expected error for soft=0")
	}
}
