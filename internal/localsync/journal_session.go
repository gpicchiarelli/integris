package localsync

import (
	"io"
	"os"
	"path/filepath"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
)

// JournalSession is a privilege-separated or local journal append session.
// Open recovers/truncates a torn tail and returns the accepted prefix; Append
// is durable before return; Close releases the underlying resources.
type JournalSession interface {
	Open() (journal.Prefix, error)
	Append(id codec.TransactionID, t codec.RecordType, payload []byte) error
	Close() error
}

// fileJournalSession owns a local FileSegment + Writer (integris sync / tests).
type fileJournalSession struct {
	path   string
	destFD *os.File // optional conferred destination root (M3f openat reopen)
	seg    *journal.FileSegment
	w      *journal.Writer
}

// OpenFileJournal prepares a local journal session for path (not yet Open'd).
func OpenFileJournal(path string) JournalSession {
	return &fileJournalSession{path: path}
}

// OpenFileJournalAt prepares a journal session that reopens via openat on
// destFD when non-nil (CapEnter-safe). path remains the ambient label/fallback.
func OpenFileJournalAt(path string, destFD *os.File) JournalSession {
	if destFD == nil {
		return OpenFileJournal(path)
	}
	return &fileJournalSession{path: path, destFD: destFD}
}

func (s *fileJournalSession) Open() (journal.Prefix, error) {
	if s == nil {
		return journal.Prefix{}, wrap(KindInternal, "journal", "", errNilJournal())
	}
	if s.w != nil {
		return journal.Prefix{}, wrap(KindInternal, "journal", "", errJournalOpen())
	}
	if s.destFD == nil {
		if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
			return journal.Prefix{}, wrap(KindWrite, "journal", "", err)
		}
	}
	seg, w, prefix, err := openJournalAt(s.destFD, s.path)
	if err != nil {
		return journal.Prefix{}, err
	}
	s.seg = seg
	s.w = w
	return prefix, nil
}

// AcceptedPrefixBytes returns the first n durable bytes of an open file journal.
func AcceptedPrefixBytes(sess JournalSession, n int64) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	s, ok := sess.(*fileJournalSession)
	if !ok || s == nil || s.seg == nil {
		return nil, wrap(KindInternal, "journal", "", errJournalClosed())
	}
	buf := make([]byte, int(n))
	if _, err := io.ReadFull(io.NewSectionReader(s.seg, 0, n), buf); err != nil {
		return nil, wrap(KindInternal, "journal", "", err)
	}
	return buf, nil
}

func (s *fileJournalSession) Append(id codec.TransactionID, t codec.RecordType, payload []byte) error {
	if s == nil || s.w == nil {
		return wrap(KindInternal, "journal", "", errJournalClosed())
	}
	return appendRec(s.w, id, t, payload)
}

func (s *fileJournalSession) Close() error {
	if s == nil {
		return nil
	}
	var first error
	if s.w != nil {
		if err := s.w.Close(); err != nil && first == nil {
			first = err
		}
		s.w = nil
	}
	if s.seg != nil {
		if err := s.seg.Close(); err != nil && first == nil {
			first = err
		}
		s.seg = nil
	}
	return first
}

type journalSentinel string

func (e journalSentinel) Error() string { return string(e) }

func errNilJournal() error    { return journalSentinel("nil journal session") }
func errJournalOpen() error   { return journalSentinel("journal already open") }
func errJournalClosed() error { return journalSentinel("journal not open") }
