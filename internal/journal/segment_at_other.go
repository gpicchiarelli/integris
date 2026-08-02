//go:build !unix

package journal

import "fmt"

// OpenFileSegmentAt is unavailable off unix; callers should use OpenFileSegment.
func OpenFileSegmentAt(dirfd int, name string) (*FileSegment, error) {
	_ = dirfd
	_ = name
	return nil, fmt.Errorf("journal: openat segment requires unix")
}
