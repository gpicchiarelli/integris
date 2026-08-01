package journal

import (
	"errors"
	"os"
)

// Crash-point labels matching recovery.CrashLabel / IP-S-0003 (stringly typed
// here to avoid a journal→recovery import cycle).
const (
	CrashJAppendPre  = "J-APPEND-PRE"
	CrashJAppendMid  = "J-APPEND-MID"
	CrashJAppendPost = "J-APPEND-POST"
	CrashJMetaPost   = "J-META-POST"
)

// CrashSegment wraps a Segment with FailAt fault injection at journal append
// persistence boundaries (IP-S-0003 J-* catalog).
type CrashSegment struct {
	Inner  Segment
	FailAt string
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

// Append implements Segment with J-APPEND-PRE / J-APPEND-MID injection.
func (c *CrashSegment) Append(p []byte) error {
	switch c.FailAt {
	case CrashJAppendPre:
		c.Hits = append(c.Hits, CrashJAppendPre)
		return injectedCrash{CrashJAppendPre}
	case CrashJAppendMid:
		c.Hits = append(c.Hits, CrashJAppendMid)
		n := len(p) / 2
		if n < 1 && len(p) > 0 {
			n = 1
		}
		if n > 0 {
			if err := c.Inner.Append(p[:n]); err != nil {
				return err
			}
		}
		return injectedCrash{CrashJAppendMid}
	default:
		return c.Inner.Append(p)
	}
}

// Sync implements Segment with J-APPEND-POST / J-META-POST injection.
// POST fails after the inner file sync (record bytes durable) and before
// directory sync. META fails after directory sync exposes the record.
func (c *CrashSegment) Sync() error {
	switch c.FailAt {
	case CrashJAppendPost:
		if err := c.Inner.Sync(); err != nil {
			return err
		}
		c.Hits = append(c.Hits, CrashJAppendPost)
		return injectedCrash{CrashJAppendPost}
	case CrashJMetaPost:
		if err := c.Inner.Sync(); err != nil {
			return err
		}
		if c.Dir != "" {
			d, err := os.Open(c.Dir)
			if err != nil {
				return err
			}
			err = d.Sync()
			_ = d.Close()
			if err != nil {
				return err
			}
		}
		c.Hits = append(c.Hits, CrashJMetaPost)
		return injectedCrash{CrashJMetaPost}
	default:
		return c.Inner.Sync()
	}
}
