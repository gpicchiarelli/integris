//go:build unix

package localsync

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isNoSpace(err error) bool {
	return errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EDQUOT)
}
