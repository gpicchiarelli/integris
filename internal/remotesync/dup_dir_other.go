//go:build !unix

package remotesync

import (
	"fmt"
	"os"
)

func dupDirFile(dirfd int, name string) (*os.File, error) {
	_ = dirfd
	_ = name
	return nil, fmt.Errorf("dup dirfd requires unix")
}
