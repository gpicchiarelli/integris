package journal

import (
	"errors"

	"github.com/gpicchiarelli/integris/internal/platform"
)

// Crash-point labels matching recovery.CrashLabel / IP-S-0003 (stringly typed
// here to avoid a journal→recovery import cycle).
const (
	CrashJAppendPre  = "J-APPEND-PRE"
	CrashJAppendMid  = "J-APPEND-MID"
	CrashJAppendPost = "J-APPEND-POST"
	CrashJMetaPost   = "J-META-POST"
)

// CrashSegment wraps a Segment with FailAt / KillAt injection at journal append
// persistence boundaries (IP-S-0003 J-* catalog).
type CrashSegment struct {
	Inner  Segment
	FailAt string
	// KillAt, when set, SIGKILLs the current process at that catalog label
	// (unix; takes precedence over FailAt). Used by integris-crash-stub.
	KillAt string
	// Dir is the journal parent directory; used for J-META-POST dirsync.
	Dir  string
	Hits []string
}

type injectedCrash struct{ label string }

func (e injectedCrash) Error() string { return "injected crash at " + e.label }

// IsInjectedCrash reports whether err is a CrashSegment FailAt fault.
func IsInjectedCrash(err error) bool {
	var ic injectedCrash
	return errors.As(err, &ic)
}

// Size implements Segment.
func (c *CrashSegment) Size() int64 {
	if c == nil || c.Inner == nil {
		return 0
	}
	return c.Inner.Size()
}

// ReadAt implements Segment.
func (c *CrashSegment) ReadAt(p []byte, off int64) (int, error) {
	return c.Inner.ReadAt(p, off)
}

func (c *CrashSegment) armed(label string) bool {
	if c == nil {
		return false
	}
	return (c.KillAt != "" && c.KillAt == label) || (c.FailAt != "" && c.FailAt == label)
}

// stopAt records a hit and returns KillAt (SIGKILL) or FailAt fault.
// KillAt takes precedence when both match the same label.
func (c *CrashSegment) stopAt(label string) error {
	if !c.armed(label) {
		return nil
	}
	c.Hits = append(c.Hits, label)
	if c.KillAt != "" && c.KillAt == label {
		return killSelfAt(label)
	}
	return injectedCrash{label}
}

// Append implements Segment with J-APPEND-PRE / J-APPEND-MID injection.
func (c *CrashSegment) Append(p []byte) error {
	if err := c.stopAt(CrashJAppendPre); err != nil {
		return err
	}
	if c.armed(CrashJAppendMid) {
		n := len(p) / 2
		if n < 1 && len(p) > 0 {
			n = 1
		}
		if n > 0 {
			if err := c.Inner.Append(p[:n]); err != nil {
				return err
			}
		}
		return c.stopAt(CrashJAppendMid)
	}
	return c.Inner.Append(p)
}

// Sync implements Segment with J-APPEND-POST / J-META-POST injection.
// POST fails after the inner file sync (record bytes durable) and before
// directory sync. META fails after directory sync exposes the record.
func (c *CrashSegment) Sync() error {
	if c.armed(CrashJAppendPost) {
		if err := c.Inner.Sync(); err != nil {
			return err
		}
		return c.stopAt(CrashJAppendPost)
	}
	if c.armed(CrashJMetaPost) {
		if err := c.Inner.Sync(); err != nil {
			return err
		}
		if c.Dir != "" {
			if err := platform.SyncDir(c.Dir); err != nil {
				return err
			}
		}
		return c.stopAt(CrashJMetaPost)
	}
	return c.Inner.Sync()
}
