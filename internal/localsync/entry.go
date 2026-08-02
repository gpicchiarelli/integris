package localsync

import (
	"encoding/hex"

	"github.com/gpicchiarelli/integris/internal/codec"
)

// EntryType is a scanned filesystem object class supported or refused by v1.
type EntryType string

const (
	EntryDir  EntryType = "dir"
	EntryFile EntryType = "file"
)

// Entry is one deterministic scan record. Rel is slash-separated logical path
// relative to the sync root (never absolute, never "..").
type Entry struct {
	Rel       string
	Type      EntryType
	Size      int64
	Mode      uint32 // permission bits only (0o7777 mask applied at scan)
	Digest    codec.Digest
	HasDigest bool
}

// DigestHex returns the lowercase hex digest, or empty if none.
func (e Entry) DigestHex() string {
	if !e.HasDigest {
		return ""
	}
	return hex.EncodeToString(e.Digest[:])
}
