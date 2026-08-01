//go:build !freebsd

package launcher

import "os"

func openAllowRootDirs(roots []string) (files []*os.File, childFDs []int, err error) {
	_ = roots
	return nil, nil, nil
}

func allowRootFDEnv(extraStartIndex int, n int) string {
	_ = extraStartIndex
	_ = n
	return ""
}

func closeFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}
