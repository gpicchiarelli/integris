//go:build !unix

package platform

import (
	"io"
	"os"
)

func copySparseContents(dst, src *os.File) error {
	_, err := io.Copy(dst, src)
	return err
}
