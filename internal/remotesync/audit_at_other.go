//go:build !unix

package remotesync

import (
	"os"
	"path/filepath"

	"github.com/gpicchiarelli/integris/internal/localsync"
)

// AuditSinkFileName is the append-only redacted event sink under .integris/.
const AuditSinkFileName = "audit.events"

// OpenAuditSinkAt falls back to ambient open using destFD.Name() as the root label.
func OpenAuditSinkAt(destFD *os.File) (*os.File, error) {
	if destFD == nil {
		return nil, fail(KindInvalidArgument, "nil dest fd for audit sink")
	}
	root := destFD.Name()
	integrisDir := filepath.Join(root, localsync.MetaDirName)
	if err := os.MkdirAll(integrisDir, 0o700); err != nil {
		return nil, wrap(KindInternal, "audit meta", err)
	}
	return os.OpenFile(filepath.Join(integrisDir, AuditSinkFileName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
}
