package localsync

import (
	"os"
	"path/filepath"
	"strings"
)

// MetaDirName is the destination-side metadata directory (journal, plan snapshot).
// It is never treated as sync content.
const MetaDirName = ".integris"

// JournalFileName is the append-only journal segment under MetaDirName.
const JournalFileName = "local.jrn"

// PlanFileName is the last durable plan JSON snapshot under MetaDirName.
const PlanFileName = "last-plan.json"

func metaDir(destRoot string) string {
	return filepath.Join(destRoot, MetaDirName)
}

func defaultJournalPath(destRoot string) string {
	return filepath.Join(metaDir(destRoot), JournalFileName)
}

func planSnapshotPath(destRoot string) string {
	return filepath.Join(metaDir(destRoot), PlanFileName)
}

func ensureMetaDir(destRoot string) error {
	return os.MkdirAll(metaDir(destRoot), 0o700)
}

// isMetaRel reports whether a slash-separated relative path is Integris metadata.
func isMetaRel(rel string) bool {
	rel = filepath.ToSlash(rel)
	return rel == MetaDirName || strings.HasPrefix(rel, MetaDirName+"/")
}
