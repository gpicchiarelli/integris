//go:build unix && !linux && !freebsd

package launcher

import (
	"os"

	"github.com/gpicchiarelli/integris/internal/platform"
)

// CreateKeyFD materializes key bytes in an unlinked anonymous file opened
// read-only. Not as strong as Linux/FreeBSD memfd seals; residual for
// Darwin/OpenBSD until a sealed anonymous FD path lands.
func CreateKeyFD(key []byte) (*os.File, KeyTransport, error) {
	// 16..256: MAC keys. Up to 8KiB: M2i peer keyring blobs on RootKey FD.
	if len(key) < 16 || len(key) > 8<<10 {
		return nil, "", fail("key", "key material length out of range")
	}
	wf, err := os.CreateTemp("", "integris-mackey-*")
	if err != nil {
		return nil, "", fail("keyfd", err.Error())
	}
	path := wf.Name()
	cleanup := func() {
		_ = wf.Close()
		_ = os.Remove(path)
	}
	if _, err := wf.Write(key); err != nil {
		cleanup()
		return nil, "", fail("keyfd", err.Error())
	}
	if err := platform.SyncFile(wf); err != nil {
		cleanup()
		return nil, "", fail("keyfd", err.Error())
	}
	if err := wf.Close(); err != nil {
		_ = os.Remove(path)
		return nil, "", fail("keyfd", err.Error())
	}
	rf, err := os.Open(path)
	_ = os.Remove(path) // unlink; rf remains valid
	if err != nil {
		return nil, "", fail("keyfd", err.Error())
	}
	return rf, KeyTransportAnonFile, nil
}
