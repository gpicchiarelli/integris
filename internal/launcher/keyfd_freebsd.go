//go:build freebsd

package launcher

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FreeBSD memfd_create(3) is libc-only; golang.org/x/sys exposes MemfdCreate on
// Linux only. Replicate libc: shm_open2(SHM_ANON, …, SHM_ALLOW_SEALING|…) then
// F_ADD_SEALS. SYS_shm_open2 / F_*_SEALS are not fully wired in x/sys for
// amd64/arm64 yet (CGO_ENABLED=0 CI must stay pure Go).
const (
	sysShmOpen2     = 571 // SYS_shm_open2 (FreeBSD 13+)
	shmAnon         = 1   // SHM_ANON as (char *)1
	shmAllowSealing = 0x1
	shmGrowOnWrite  = 0x2
	fAddSeals       = 19 // F_ADD_SEALS
	fSealSeal       = 0x1
	fSealShrink     = 0x2
	fSealGrow       = 0x4
	fSealWrite      = 0x8
)

// CreateKeyFD writes key into a sealed anonymous shared-memory FD (memfd
// equivalent) and returns a readable *os.File at offset 0 for ExtraFiles /
// SCM_RIGHTS conferral.
func CreateKeyFD(key []byte) (*os.File, KeyTransport, error) {
	// 16..256: MAC keys. Up to 8KiB: M2i peer keyring blobs on RootKey FD.
	if len(key) < 16 || len(key) > 8<<10 {
		return nil, "", fail("key", "key material length out of range")
	}
	name, err := unix.BytePtrFromString("memfd:integris-mac-key")
	if err != nil {
		return nil, "", fail("keyfd", err.Error())
	}
	fd, _, errno := unix.Syscall6( // nosemgrep: go.lang.security.audit.unsafe.use-of-unsafe-block
		sysShmOpen2,
		uintptr(shmAnon),
		uintptr(unix.O_RDWR|unix.O_CLOEXEC),
		0,
		uintptr(shmAllowSealing|shmGrowOnWrite),
		uintptr(unsafe.Pointer(name)),
		0,
	)
	if errno != 0 {
		return nil, "", fail("keyfd", "shm_open2: "+errno.Error())
	}
	f := os.NewFile(fd, "integris-mac-key")
	if f == nil {
		_ = unix.Close(int(fd))
		return nil, "", fail("keyfd", "NewFile failed")
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		return nil, "", fail("keyfd", err.Error())
	}
	seals := fSealShrink | fSealGrow | fSealWrite | fSealSeal
	if _, err := unix.FcntlInt(f.Fd(), fAddSeals, seals); err != nil {
		_ = f.Close()
		return nil, "", fail("keyfd", "seal: "+err.Error())
	}
	if _, err := f.Seek(0, 0); err != nil {
		_ = f.Close()
		return nil, "", fail("keyfd", err.Error())
	}
	return f, KeyTransportMemfd, nil
}
