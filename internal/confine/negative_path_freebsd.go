//go:build freebsd

package confine

import "golang.org/x/sys/unix"

func probeAllowRootReadable(opts ApplyOptions) error {
	if len(opts.AllowRootFDs) == 0 || opts.AllowRootFDs[0] == nil {
		return errNoAllowRootFD
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(opts.AllowRootFDs[0].Fd()), &st); err != nil {
		return err
	}
	return nil
}

func probeAllowRootCreate(opts ApplyOptions) (cleanup func(), err error) {
	if len(opts.AllowRootFDs) == 0 || opts.AllowRootFDs[0] == nil {
		return nil, errNoAllowRootFD
	}
	dirfd := int(opts.AllowRootFDs[0].Fd())
	const name = "integris-neg-fs-write"
	fd, err := unix.Openat(dirfd, name, unix.O_CREAT|unix.O_WRONLY|unix.O_EXCL|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	_ = unix.Close(fd)
	return func() {
		_ = unix.Unlinkat(dirfd, name, 0)
	}, nil
}

var errNoAllowRootFD = errString("missing conferred allow-root directory fd")

type errString string

func (e errString) Error() string { return string(e) }
