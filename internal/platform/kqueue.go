package platform

import (
	"context"
	"fmt"
)

// VNodeWatchMechanismKqueue is reported when EVFILT_VNODE watches are native.
const VNodeWatchMechanismKqueue = "kqueue"

// VNodeWatchMechanismInotify is reported when Linux inotify watches are native.
const VNodeWatchMechanismInotify = "inotify"

// VNode note flags (subset of NOTE_*). Combined with bitwise OR.
const (
	VNodeNoteDelete = 1 << iota
	VNodeNoteWrite
)

// VNodeEvent is one delivered vnode notification.
type VNodeEvent struct {
	Notes int
}

type vnodeWatch interface {
	wait(ctx context.Context) (VNodeEvent, error)
	close() error
}

// VNodeWatch is an open native watch on a single path (INT-IC4-0001
// notification class): kqueue EVFILT_VNODE on BSD/Darwin, inotify on Linux.
// Close releases the watch descriptors.
type VNodeWatch struct {
	impl vnodeWatch
}

// OpenVNodeWatch opens path and registers native vnode notes for the requested
// notes (VNodeNoteWrite and/or VNodeNoteDelete). notes must be non-zero. On
// platforms without a native adapter, returns an error.
func OpenVNodeWatch(path string, notes int) (*VNodeWatch, error) {
	if path == "" {
		return nil, fmt.Errorf("platform: empty VNodeWatch path")
	}
	if notes == 0 {
		return nil, fmt.Errorf("platform: VNodeWatch notes must be non-zero")
	}
	impl, err := openVNodeWatch(path, notes)
	if err != nil {
		return nil, err
	}
	return &VNodeWatch{impl: impl}, nil
}

// Wait blocks until a matching vnode event, ctx cancellation, or error.
func (w *VNodeWatch) Wait(ctx context.Context) (VNodeEvent, error) {
	if w == nil {
		return VNodeEvent{}, fmt.Errorf("platform: nil VNodeWatch")
	}
	return w.impl.wait(ctx)
}

// Close releases watch resources.
func (w *VNodeWatch) Close() error {
	if w == nil {
		return nil
	}
	return w.impl.close()
}

// VNodeWatchSupported reports whether this port exposes native vnode watches.
func VNodeWatchSupported() bool {
	return vnodeWatchSupported()
}

// VNodeWatchMechanism names the native notifier, or empty when unsupported.
func VNodeWatchMechanism() string {
	return vnodeWatchMechanism()
}
