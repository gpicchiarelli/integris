//go:build !linux

package platform

import (
	"fmt"
	"os"
)

func copyFileRangeAll(dst, src *os.File) error {
	_, _ = dst, src
	return fmt.Errorf("platform: copy_file_range unavailable")
}
