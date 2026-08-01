//go:build linux

package launcher

import (
	"os"

	"golang.org/x/sys/unix"
)

// CreateKeyFD writes key into a sealed memfd and returns a readable *os.File
// positioned at offset 0 for ExtraFiles conferral.
func CreateKeyFD(key []byte) (*os.File, KeyTransport, error) {
	if len(key) < 16 || len(key) > 256 {
		return nil, "", fail("key", "MAC key length out of range")
	}
	fd, err := unix.MemfdCreate("integris-mac-key", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, "", fail("keyfd", err.Error())
	}
	f := os.NewFile(uintptr(fd), "integris-mac-key")
	if f == nil {
		_ = unix.Close(fd)
		return nil, "", fail("keyfd", "NewFile failed")
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		return nil, "", fail("keyfd", err.Error())
	}
	seals := unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		_ = f.Close()
		return nil, "", fail("keyfd", "seal: "+err.Error())
	}
	if _, err := f.Seek(0, 0); err != nil {
		_ = f.Close()
		return nil, "", fail("keyfd", err.Error())
	}
	return f, KeyTransportMemfd, nil
}
