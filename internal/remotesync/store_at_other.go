//go:build !unix

package remotesync

import (
	"os"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/localsync"
)

func openLocalStoreAt(destination string, destFD *os.File) (*localStore, error) {
	_ = destFD
	return openLocalStoreAmbient(destination)
}

func (s *localStore) prepareDirsAt(entries []localsync.Entry) error {
	_ = entries
	return fail(KindApply, "openat staging requires unix")
}

func (s *localStore) stageLegacyAt(fw fileWire) error {
	_ = fw
	return fail(KindApply, "openat staging requires unix")
}

func (s *localStore) beginFileAt(begin fileBegin) (uint64, error) {
	_ = begin
	return 0, fail(KindApply, "openat staging requires unix")
}

func (s *localStore) endFileAt(rel string, dig codec.Digest) error {
	_ = rel
	_ = dig
	return fail(KindApply, "openat staging requires unix")
}

func (s *localStore) persistActiveAt() {}

func (s *localStore) closeAt() {}

func (s *localStore) resetStageAt() error {
	return fail(KindApply, "openat staging requires unix")
}

func writePartialMetaAt(partialFD int, rel string, m partialMeta) error {
	_ = partialFD
	_ = rel
	_ = m
	return fail(KindApply, "openat staging requires unix")
}
