//go:build !unix

package remotesync

import (
	"os"
	"path/filepath"

	"github.com/gpicchiarelli/integris/internal/localsync"
)

// BootstrapJournalAt falls back to ambient create using destFD.Name() as root.
func BootstrapJournalAt(destFD *os.File) error {
	if destFD == nil {
		return fail(KindInvalidArgument, "nil dest fd for journal bootstrap")
	}
	integrisDir := filepath.Join(destFD.Name(), localsync.MetaDirName)
	if err := os.MkdirAll(integrisDir, 0o700); err != nil {
		return wrap(KindInternal, "journal meta", err)
	}
	f, err := os.OpenFile(filepath.Join(integrisDir, localsync.JournalFileName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return wrap(KindInternal, "journal bootstrap", err)
	}
	return f.Close()
}
