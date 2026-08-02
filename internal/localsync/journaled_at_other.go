//go:build !unix

package localsync

import (
	"fmt"
	"os"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
)

func openJournalAt(destFD *os.File, path string) (*journal.FileSegment, *journal.Writer, journal.Prefix, error) {
	_ = destFD
	return openJournal(path)
}

func writePlanSnapshotAt(destFD *os.File, raw []byte) error {
	_ = destFD
	_ = raw
	return wrap(KindInternal, "journal", "", fmt.Errorf("plan snapshot openat requires unix"))
}

func loadPlanSnapshotAt(destFD *os.File) (Plan, codec.Digest, error) {
	_ = destFD
	return Plan{}, codec.Digest{}, wrap(KindInternal, "journal", "", fmt.Errorf("plan snapshot openat requires unix"))
}
