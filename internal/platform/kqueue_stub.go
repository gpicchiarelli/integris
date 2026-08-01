//go:build !(darwin || freebsd || openbsd || netbsd || dragonfly)

package platform

import (
	"context"
	"fmt"
)

func vnodeWatchSupported() bool { return false }

type stubVNodeWatch struct{}

func openVNodeWatch(path string, notes int) (vnodeWatch, error) {
	_ = path
	_ = notes
	return nil, fmt.Errorf("platform: kqueue VNODE unavailable on this OS")
}

func (stubVNodeWatch) wait(ctx context.Context) (VNodeEvent, error) {
	_ = ctx
	return VNodeEvent{}, fmt.Errorf("platform: kqueue VNODE unavailable on this OS")
}

func (stubVNodeWatch) close() error { return nil }
