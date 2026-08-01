package platform

import (
	"fmt"
	"os"
)

// SendFileMechanismSendfile is reported when the native sendfile path is used.
const SendFileMechanismSendfile = "sendfile"

// SendFile copies up to count bytes from in starting at offset into out using
// the native sendfile facility when available (INT-IC4-0001). Returns the
// number of bytes written and the next file offset. out must be a connected
// socket on Darwin/BSD; Linux also accepts sockets (and some file-to-file
// cases). count must be > 0. Partial writes may return a non-nil error
// (for example EAGAIN). On platforms without a working sendfile (OpenBSD
// returns ENOSYS in x/sys), SendFile returns an error.
func SendFile(out, in *os.File, offset int64, count int) (written int, newOffset int64, err error) {
	if out == nil || in == nil {
		return 0, offset, fmt.Errorf("platform: nil SendFile file")
	}
	if count <= 0 {
		return 0, offset, fmt.Errorf("platform: SendFile count must be > 0")
	}
	if offset < 0 {
		return 0, offset, fmt.Errorf("platform: SendFile offset must be >= 0")
	}
	return sendFile(out, in, offset, count)
}

// SendFileSupported reports whether this port exposes a working native
// sendfile adapter (false on OpenBSD and non-Unix stubs).
func SendFileSupported() bool {
	return sendFileSupported()
}

// SendFileMechanism names the native bulk-transfer path, or empty when
// unsupported.
func SendFileMechanism() string {
	if !sendFileSupported() {
		return ""
	}
	return SendFileMechanismSendfile
}
