package remotesync

import (
	"io"
	"os"
	"path/filepath"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/localsync"
	"github.com/gpicchiarelli/integris/internal/platform"
)

// localStore stages inbound push content under destination/.integris/.
type localStore struct {
	dest    string
	stage   string
	partial string

	// M3e/M3g: conferred destination directory FD + openat'd stage/partial dirs.
	// When destFD != nil, staging and Sync publish use openat (CapEnter-safe).
	destFD    *os.File
	stageFD   int // -1 when ambient
	partialFD int // -1 when ambient

	// active chunked receive
	active    bool
	begin     fileBegin
	lastBegin fileBegin // set on begin (including already-complete)
	partPath  string
	pf        *os.File
	off       uint64

	// destMan is an optional readonly index snapshot (M2h) used at commit.
	destMan *localsync.Manifest
}

func (s *localStore) useAt() bool {
	return s != nil && s.destFD != nil && s.stageFD >= 0 && s.partialFD >= 0
}

func openLocalStore(destination string) (*localStore, error) {
	return openLocalStoreAmbient(destination)
}

func openLocalStoreAmbient(destination string) (*localStore, error) {
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return nil, wrap(KindApply, "destination", err)
	}
	stage, partial, err := ensureRecvStage(destination)
	if err != nil {
		return nil, err
	}
	return &localStore{
		dest: destination, stage: stage, partial: partial,
		stageFD: -1, partialFD: -1,
	}, nil
}

func (s *localStore) prepareDirs(entries []localsync.Entry) error {
	if s.useAt() {
		return s.prepareDirsAt(entries)
	}
	for _, e := range entries {
		if e.Type != localsync.EntryDir {
			continue
		}
		native := filepath.Join(s.stage, filepath.FromSlash(e.Rel))
		mode := os.FileMode(e.Mode)
		if mode == 0 {
			mode = 0o755
		}
		if err := os.MkdirAll(native, mode); err != nil {
			return wrap(KindApply, "mkdir", err)
		}
	}
	return nil
}

func (s *localStore) stageLegacy(fw fileWire) error {
	if s.useAt() {
		return s.stageLegacyAt(fw)
	}
	native := filepath.Join(s.stage, filepath.FromSlash(fw.Rel))
	if err := os.MkdirAll(filepath.Dir(native), 0o755); err != nil {
		return wrap(KindApply, "mkdir parent", err)
	}
	mode := os.FileMode(fw.Mode)
	if mode == 0 {
		mode = 0o644
	}
	if err := os.WriteFile(native, fw.Data, mode); err != nil {
		return wrap(KindApply, "write", err)
	}
	dig, _, err := localsync.HashFile(native)
	if err != nil || dig != fw.Digest {
		return failf(KindApply, "staged digest mismatch for %s", fw.Rel)
	}
	return nil
}

// beginFile opens/resumes a partial and returns the ack offset.
func (s *localStore) beginFile(begin fileBegin) (uint64, error) {
	if s.useAt() {
		return s.beginFileAt(begin)
	}
	if s.active {
		return 0, fail(KindProtocol, "file already active")
	}
	nativeFinal := finalStagePath(s.stage, begin.Rel)
	s.lastBegin = begin
	if fi, err := os.Lstat(nativeFinal); err == nil && fi.Mode().IsRegular() && fi.Size() == int64(begin.Size) {
		dig, _, err := localsync.HashFile(nativeFinal)
		if err == nil && dig == begin.Digest {
			clearPartial(s.partial, begin.Rel)
			return begin.Size, nil
		}
	}

	var start uint64
	meta, ok, err := loadPartialMeta(s.partial, begin.Rel)
	if err != nil {
		return 0, err
	}
	partPath := partialDataPath(s.partial, begin.Rel)
	if ok && meta.Digest == begin.Digest && meta.Size == int64(begin.Size) && meta.Rel == begin.Rel {
		if st, err := os.Lstat(partPath); err == nil && st.Size() == meta.Offset {
			start = uint64(meta.Offset)
		} else {
			clearPartial(s.partial, begin.Rel)
			start = 0
		}
	} else {
		clearPartial(s.partial, begin.Rel)
		start = 0
	}

	if err := os.MkdirAll(filepath.Dir(partPath), 0o700); err != nil {
		return 0, wrap(KindApply, "partial dir", err)
	}
	flags := os.O_RDWR | os.O_CREATE
	if start == 0 {
		flags |= os.O_TRUNC
	}
	pf, err := os.OpenFile(partPath, flags, 0o600)
	if err != nil {
		return 0, wrap(KindApply, "partial open", err)
	}
	if start > 0 {
		if _, err := pf.Seek(int64(start), io.SeekStart); err != nil {
			_ = pf.Close()
			return 0, wrap(KindApply, "partial seek", err)
		}
	}
	s.active = true
	s.begin = begin
	s.partPath = partPath
	s.pf = pf
	s.off = start
	return start, nil
}

func (s *localStore) writeChunk(coff uint64, data []byte) error {
	if !s.active || s.pf == nil {
		return fail(KindProtocol, "chunk without begin")
	}
	if coff != s.off {
		return failf(KindProtocol, "chunk offset %d want %d", coff, s.off)
	}
	if _, err := s.pf.Write(data); err != nil {
		return wrap(KindApply, "partial write", err)
	}
	s.off += uint64(len(data))
	if s.off%uint64(DefaultChunkSize*4) == 0 {
		_ = platform.SyncFile(s.pf)
		if s.useAt() {
			_ = writePartialMetaAt(s.partialFD, s.begin.Rel, partialMeta{
				Rel: s.begin.Rel, Mode: s.begin.Mode, Size: int64(s.begin.Size),
				Digest: s.begin.Digest, Offset: int64(s.off),
			})
		} else {
			_ = writePartialMeta(s.partial, s.begin.Rel, partialMeta{
				Rel: s.begin.Rel, Mode: s.begin.Mode, Size: int64(s.begin.Size),
				Digest: s.begin.Digest, Offset: int64(s.off),
			})
		}
	}
	return nil
}

func (s *localStore) persistActive() {
	if !s.active || s.pf == nil {
		return
	}
	if s.useAt() {
		s.persistActiveAt()
		return
	}
	_ = writePartialMeta(s.partial, s.begin.Rel, partialMeta{
		Rel: s.begin.Rel, Mode: s.begin.Mode, Size: int64(s.begin.Size),
		Digest: s.begin.Digest, Offset: int64(s.off),
	})
	_ = platform.SyncFile(s.pf)
}

func (s *localStore) endFile(rel string, dig codec.Digest) error {
	if s.useAt() {
		return s.endFileAt(rel, dig)
	}
	if !s.active || s.pf == nil {
		return fail(KindProtocol, "end without begin")
	}
	if rel != s.begin.Rel || dig != s.begin.Digest {
		return fail(KindProtocol, "file end mismatch")
	}
	if s.off != s.begin.Size {
		return fail(KindProtocol, "unexpected file end before size complete")
	}
	if err := platform.SyncFile(s.pf); err != nil {
		return wrap(KindApply, "partial sync", err)
	}
	if err := s.pf.Close(); err != nil {
		return wrap(KindApply, "partial close", err)
	}
	s.pf = nil

	got, _, err := localsync.HashFile(s.partPath)
	if err != nil || got != s.begin.Digest {
		return failf(KindApply, "chunked digest mismatch for %s", s.begin.Rel)
	}

	final := finalStagePath(s.stage, s.begin.Rel)
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return wrap(KindApply, "final mkdir", err)
	}
	mode := os.FileMode(s.begin.Mode)
	if mode == 0 {
		mode = 0o644
	}
	if err := os.Rename(s.partPath, final); err != nil {
		data, err := os.ReadFile(s.partPath)
		if err != nil {
			return wrap(KindApply, "finalize read", err)
		}
		// final is under staging root + validated relative path (safeName).
		if err := os.WriteFile(final, data, mode); err != nil { // #nosec G703 -- validated stage-relative path
			return wrap(KindApply, "finalize write", err)
		}
		_ = os.Remove(s.partPath)
	} else if err := os.Chmod(final, mode); err != nil {
		return wrap(KindApply, "chmod", err)
	}
	clearPartial(s.partial, s.begin.Rel)
	_ = platform.SyncDir(filepath.Dir(final))
	s.active = false
	s.partPath = ""
	return nil
}

func (s *localStore) commit(j localsync.JournalSession) error {
	if s.active {
		return fail(KindProtocol, "commit with active file")
	}
	opts := localsync.Options{
		Source:       s.stage,
		Destination:  s.dest,
		Journal:      j,
		DestManifest: s.destMan,
	}
	if s.useAt() {
		// Dup stageFD so Sync/ApplyAt can borrow an *os.File without owning store FDs.
		stageFile, err := dupDirFile(s.stageFD, s.stage)
		if err != nil {
			return wrap(KindApply, "stage fd", err)
		}
		defer stageFile.Close()
		opts.SourceFD = stageFile
		opts.DestFD = s.destFD
	}
	_, err := localsync.Sync(opts)
	if err != nil {
		return wrap(KindApply, "localsync", err)
	}
	s.destMan = nil
	if s.useAt() {
		return s.resetStageAt()
	}
	_ = os.RemoveAll(s.stage)
	_ = os.MkdirAll(s.stage, 0o700)
	return nil
}

func (s *localStore) setDestManifest(entries []localsync.Entry) {
	s.destMan = &localsync.Manifest{Root: s.dest, Entries: entries}
}

func (s *localStore) close() {
	if s.pf != nil {
		_ = s.pf.Close()
		s.pf = nil
	}
	s.active = false
	if s.useAt() {
		s.closeAt()
	}
}
