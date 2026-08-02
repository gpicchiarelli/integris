//go:build darwin || freebsd || openbsd || netbsd || dragonfly

package platform

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

func vnodeWatchSupported() bool { return true }

func vnodeWatchMechanism() string { return VNodeWatchMechanismKqueue }

type kqueueVNodeWatch struct {
	kq   int
	file *os.File
}

func openVNodeWatch(path string, notes int) (vnodeWatch, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	kq, err := unix.Kqueue()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("platform: kqueue: %w", err)
	}
	var change unix.Kevent_t
	unix.SetKevent(&change, int(f.Fd()), unix.EVFILT_VNODE, unix.EV_ADD|unix.EV_CLEAR|unix.EV_ENABLE)
	change.Fflags = noteFlags(notes)
	if change.Fflags == 0 {
		_ = unix.Close(kq)
		_ = f.Close()
		return nil, fmt.Errorf("platform: unsupported VNodeWatch notes %d", notes)
	}
	if _, err := unix.Kevent(kq, []unix.Kevent_t{change}, nil, nil); err != nil {
		_ = unix.Close(kq)
		_ = f.Close()
		return nil, fmt.Errorf("platform: kevent register: %w", err)
	}
	runtime.KeepAlive(f)
	return &kqueueVNodeWatch{kq: kq, file: f}, nil
}

func noteFlags(notes int) uint32 {
	var f uint32
	if notes&VNodeNoteWrite != 0 {
		f |= unix.NOTE_WRITE
	}
	if notes&VNodeNoteDelete != 0 {
		f |= unix.NOTE_DELETE
	}
	return f
}

func notesFromFflags(fflags uint32) int {
	var n int
	if fflags&unix.NOTE_WRITE != 0 {
		n |= VNodeNoteWrite
	}
	if fflags&unix.NOTE_DELETE != 0 {
		n |= VNodeNoteDelete
	}
	return n
}

func (w *kqueueVNodeWatch) wait(ctx context.Context) (VNodeEvent, error) {
	if w == nil || w.kq < 0 {
		return VNodeEvent{}, fmt.Errorf("platform: closed VNodeWatch")
	}
	for {
		if err := ctx.Err(); err != nil {
			return VNodeEvent{}, err
		}
		timeout := pollTimeout(ctx)
		var out [1]unix.Kevent_t
		n, err := unix.Kevent(w.kq, nil, out[:], timeout)
		runtime.KeepAlive(w.file)
		if n > 0 {
			return VNodeEvent{Notes: notesFromFflags(out[0].Fflags)}, nil
		}
		if err != nil && err != unix.EINTR {
			return VNodeEvent{}, err
		}
	}
}

func pollTimeout(ctx context.Context) *unix.Timespec {
	const slice = 50 * time.Millisecond
	rem := slice
	if dl, ok := ctx.Deadline(); ok {
		rem = time.Until(dl)
		if rem <= 0 {
			ts := unix.NsecToTimespec(0)
			return &ts
		}
		if rem > slice {
			rem = slice
		}
	}
	ts := unix.NsecToTimespec(rem.Nanoseconds())
	return &ts
}

func (w *kqueueVNodeWatch) close() error {
	if w == nil {
		return nil
	}
	var first error
	if w.kq >= 0 {
		if err := unix.Close(w.kq); err != nil && first == nil {
			first = err
		}
		w.kq = -1
	}
	if w.file != nil {
		if err := w.file.Close(); err != nil && first == nil {
			first = err
		}
		w.file = nil
	}
	return first
}
