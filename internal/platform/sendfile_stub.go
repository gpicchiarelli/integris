//go:build openbsd || !unix

package platform

import (
	"fmt"
	"os"
)

func sendFileSupported() bool { return false }

func sendFile(out, in *os.File, offset int64, count int) (int, int64, error) {
	_ = out
	_ = in
	_ = count
	return 0, offset, fmt.Errorf("platform: sendfile unavailable on this OS")
}
