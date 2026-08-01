//go:build !(darwin || freebsd || openbsd || netbsd || dragonfly)

package platform

import "fmt"

func vnodeWatchSupported() bool { return false }

func openVNodeWatch(path string, notes int) (vnodeWatch, error) {
	_ = path
	_ = notes
	return nil, fmt.Errorf("platform: kqueue VNODE unavailable on this OS")
}
