package journal

import (
	"fmt"
	"io"
	"os"

	"github.com/gpicchiarelli/integris/internal/platform"
)

// Segment is an injectable append-only byte sequence used for fault testing.
// Implementations must never overwrite committed prefix bytes on Append.
type Segment interface {
	io.ReaderAt
	// Size returns the number of durable bytes visible to readers.
	Size() int64
	// Append writes p at the current end without overwriting prior bytes.
	Append(p []byte) error
	// Sync persists appended bytes according to the publication profile.
	Sync() error
}

// MemSegment is an in-memory Segment for tests and harnesses.
type MemSegment struct {
	buf []byte
}

// NewMemSegment returns an empty memory segment.
func NewMemSegment() *MemSegment {
	return &MemSegment{}
}

// Size implements Segment.
func (m *MemSegment) Size() int64 { return int64(len(m.buf)) }

// ReadAt implements io.ReaderAt.
func (m *MemSegment) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("journal: negative offset")
	}
	if off >= int64(len(m.buf)) {
		return 0, io.EOF
	}
	n := copy(p, m.buf[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// Append implements Segment.
func (m *MemSegment) Append(p []byte) error {
	m.buf = append(m.buf, p...)
	return nil
}

// Sync implements Segment.
func (m *MemSegment) Sync() error { return nil }

// Bytes returns a copy of the segment contents.
func (m *MemSegment) Bytes() []byte {
	out := make([]byte, len(m.buf))
	copy(out, m.buf)
	return out
}

// Truncate shrinks the visible prefix for fault-injection tests.
func (m *MemSegment) Truncate(n int64) {
	if n < 0 {
		n = 0
	}
	if n > int64(len(m.buf)) {
		n = int64(len(m.buf))
	}
	m.buf = m.buf[:n]
}

// Corrupt flips a byte at off for fault-injection tests.
func (m *MemSegment) Corrupt(off int64, xor byte) {
	if off >= 0 && off < int64(len(m.buf)) {
		m.buf[off] ^= xor
	}
}

// FileSegment wraps an os.File opened for append-only journal use.
type FileSegment struct {
	f    *os.File
	size int64
}

// OpenFileSegment opens path for read/write append, creating it if needed.
func OpenFileSegment(path string) (*FileSegment, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &FileSegment{f: f, size: st.Size()}, nil
}

// Size implements Segment.
func (s *FileSegment) Size() int64 { return s.size }

// ReadAt implements io.ReaderAt.
func (s *FileSegment) ReadAt(p []byte, off int64) (int, error) {
	return s.f.ReadAt(p, off)
}

// Append implements Segment.
func (s *FileSegment) Append(p []byte) error {
	n, err := s.f.WriteAt(p, s.size)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	s.size += int64(n)
	return nil
}

// Sync implements Segment using the platform durability barrier (Darwin
// F_FULLFSYNC; fsync elsewhere).
func (s *FileSegment) Sync() error { return platform.SyncFile(s.f) }

// Truncate shrinks the durable prefix for fault-injection / quarantine repair.
func (s *FileSegment) Truncate(n int64) error {
	if s == nil || s.f == nil {
		return fmt.Errorf("journal: nil file segment")
	}
	if n < 0 {
		n = 0
	}
	if err := s.f.Truncate(n); err != nil {
		return err
	}
	if _, err := s.f.Seek(n, 0); err != nil {
		return err
	}
	s.size = n
	return nil
}

// Close closes the underlying file.
func (s *FileSegment) Close() error { return s.f.Close() }
