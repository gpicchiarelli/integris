//go:build !(darwin || freebsd || openbsd || netbsd || dragonfly || linux)

package platform

import "fmt"

func vnodeWatchSupported() bool { return false }

func vnodeWatchMechanism() string { return "" }

func openVNodeWatch(path string, notes int) (vnodeWatch, error) {
	_ = path
	_ = notes
	return nil, fmt.Errorf("platform: VNodeWatch unavailable on this OS")
}
