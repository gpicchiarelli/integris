//go:build freebsd

package confine

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// verifyCapRightsLimited fails closed unless CapRightsGet shows all want
// rights present and every right in absent cleared (M5y). CapRightsIsSet alone
// only proves a subset; without absent sentinels, an unlimited FD would still
// pass IsSet(want).
func verifyCapRightsLimited(fd uintptr, want, absent []uint64) error {
	got, err := unix.CapRightsGet(fd)
	if err != nil {
		return fmt.Errorf("CapRightsGet: %w", err)
	}
	ok, err := unix.CapRightsIsSet(got, want)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("CapRightsLimit missing expected rights")
	}
	for _, right := range absent {
		set, err := unix.CapRightsIsSet(got, []uint64{right})
		if err != nil {
			return err
		}
		if set {
			return fmt.Errorf("CapRightsLimit left unexpected right 0x%x", right)
		}
	}
	return nil
}
