//go:build linux

package platform

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func vnodeWatchSupported() bool { return true }

func vnodeWatchMechanism() string { return VNodeWatchMechanismInotify }

type inotifyVNodeWatch struct {
	fd     int
	wd     int
	want   int
	closed bool
}

func openVNodeWatch(path string, notes int) (vnodeWatch, error) {
	mask := inotifyMask(notes)
	if mask == 0 {
		return nil, fmt.Errorf("platform: unsupported VNodeWatch notes %d", notes)
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("platform: inotify_init1: %w", err)
	}
	wd, err := unix.InotifyAddWatch(fd, path, mask)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("platform: inotify_add_watch: %w", err)
	}
	return &inotifyVNodeWatch{fd: fd, wd: wd, want: notes}, nil
}

func inotifyMask(notes int) uint32 {
	var m uint32
	if notes&VNodeNoteWrite != 0 {
		m |= unix.IN_MODIFY | unix.IN_CLOSE_WRITE
	}
	if notes&VNodeNoteDelete != 0 {
		m |= unix.IN_DELETE_SELF | unix.IN_MOVE_SELF
	}
	return m
}

func notesFromInotify(mask uint32) int {
	var n int
	if mask&(unix.IN_MODIFY|unix.IN_CLOSE_WRITE) != 0 {
		n |= VNodeNoteWrite
	}
	if mask&(unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_IGNORED) != 0 {
		n |= VNodeNoteDelete
	}
	return n
}

func (w *inotifyVNodeWatch) wait(ctx context.Context) (VNodeEvent, error) {
	if w == nil || w.closed || w.fd < 0 {
		return VNodeEvent{}, fmt.Errorf("platform: closed VNodeWatch")
	}
	buf := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return VNodeEvent{}, err
		}
		pfd := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pfd, pollTimeoutMs(ctx))
		if err != nil && err != unix.EINTR {
			return VNodeEvent{}, err
		}
		if n <= 0 {
			continue
		}
		nr, err := unix.Read(w.fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			return VNodeEvent{}, err
		}
		if ev, ok := parseInotifyEvents(buf[:nr], w.want); ok {
			return ev, nil
		}
	}
}

func parseInotifyEvents(buf []byte, want int) (VNodeEvent, bool) {
	var combined int
	offset := 0
	for offset+unix.SizeofInotifyEvent <= len(buf) {
		raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
		nameLen := int(raw.Len)
		offset += unix.SizeofInotifyEvent + nameLen
		if offset > len(buf) {
			break
		}
		n := notesFromInotify(raw.Mask) & want
		if n == 0 && raw.Mask&unix.IN_IGNORED != 0 && want&VNodeNoteDelete != 0 {
			n = VNodeNoteDelete
		}
		combined |= n
	}
	if combined == 0 {
		return VNodeEvent{}, false
	}
	return VNodeEvent{Notes: combined}, true
}

func pollTimeoutMs(ctx context.Context) int {
	const slice = 50
	if dl, ok := ctx.Deadline(); ok {
		rem := time.Until(dl)
		if rem <= 0 {
			return 0
		}
		ms := int(rem / time.Millisecond)
		if ms > slice {
			return slice
		}
		if ms < 1 {
			return 0
		}
		return ms
	}
	return slice
}

func (w *inotifyVNodeWatch) close() error {
	if w == nil || w.closed {
		return nil
	}
	w.closed = true
	var first error
	if w.fd >= 0 {
		if w.wd >= 0 {
			_, _ = unix.InotifyRmWatch(w.fd, uint32(w.wd))
			w.wd = -1
		}
		if err := unix.Close(w.fd); err != nil {
			first = err
		}
		w.fd = -1
	}
	return first
}
