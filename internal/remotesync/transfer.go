package remotesync

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/localsync"
)

// DefaultChunkSize is the default application-level chunk size (under MaxBodyBytes).
const DefaultChunkSize = 256 << 10

type partialMeta struct {
	Rel    string       `json:"rel"`
	Mode   uint32       `json:"mode"`
	Size   int64        `json:"size"`
	Digest codec.Digest `json:"digest"`
	Offset int64        `json:"offset"`
}

func recvStageDir(destRoot string) string {
	return filepath.Join(destRoot, localsync.MetaDirName, "recv-stage")
}

func recvPartialDir(destRoot string) string {
	return filepath.Join(destRoot, localsync.MetaDirName, "recv-partial")
}

func partialMetaPath(partialRoot, rel string) string {
	return filepath.Join(partialRoot, filepath.FromSlash(rel)+".meta.json")
}

func partialDataPath(partialRoot, rel string) string {
	return filepath.Join(partialRoot, filepath.FromSlash(rel)+".part")
}

func finalStagePath(stageRoot, rel string) string {
	return filepath.Join(stageRoot, filepath.FromSlash(rel))
}

func ensureRecvStage(destRoot string) (stage, partial string, err error) {
	stage = recvStageDir(destRoot)
	partial = recvPartialDir(destRoot)
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return "", "", wrap(KindApply, "recv-stage", err)
	}
	if err := os.MkdirAll(partial, 0o700); err != nil {
		return "", "", wrap(KindApply, "recv-partial", err)
	}
	return stage, partial, nil
}

func writePartialMeta(partialRoot, rel string, m partialMeta) error {
	path := partialMetaPath(partialRoot, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadPartialMeta(partialRoot, rel string) (partialMeta, bool, error) {
	var zero partialMeta
	raw, err := os.ReadFile(partialMetaPath(partialRoot, rel))
	if err != nil {
		if os.IsNotExist(err) {
			return zero, false, nil
		}
		return zero, false, err
	}
	if err := json.Unmarshal(raw, &zero); err != nil {
		return partialMeta{}, false, err
	}
	return zero, true, nil
}

func clearPartial(partialRoot, rel string) {
	_ = os.Remove(partialMetaPath(partialRoot, rel))
	_ = os.Remove(partialDataPath(partialRoot, rel))
}

// sendFileChunked pushes one file using begin/ack/chunk/end.
func sendFileChunked(sess *Session, srcRoot string, e localsync.Entry, chunkSize int, hooks *PushHooks) (int64, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	native := filepath.Join(srcRoot, filepath.FromSlash(e.Rel))
	f, err := os.Open(native)
	if err != nil {
		return 0, wrap(KindApply, "open "+e.Rel, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return 0, wrap(KindApply, "stat "+e.Rel, err)
	}
	if st.Size() != e.Size {
		return 0, failf(KindApply, "size changed for %s", e.Rel)
	}
	dig, _, err := localsync.HashFile(native)
	if err != nil {
		return 0, wrap(KindApply, "hash "+e.Rel, err)
	}
	if dig != e.Digest {
		return 0, failf(KindApply, "content changed for %s", e.Rel)
	}

	begin, err := encodeFileBegin(e.Rel, e.Mode, e.Digest, uint64(e.Size))
	if err != nil {
		return 0, err
	}
	if err := sess.sendData(begin); err != nil {
		return 0, err
	}
	ackRaw, err := sess.recvData()
	if err != nil {
		return 0, err
	}
	offset, err := decodeFileAck(ackRaw)
	if err != nil {
		return 0, err
	}
	if offset > uint64(e.Size) {
		return 0, failf(KindProtocol, "resume offset beyond size for %s", e.Rel)
	}
	if _, err := f.Seek(int64(offset), io.SeekStart); err != nil {
		return 0, wrap(KindApply, "seek "+e.Rel, err)
	}

	buf := make([]byte, chunkSize)
	off := offset
	var sent int64
	for off < uint64(e.Size) {
		n, err := f.Read(buf)
		if n > 0 {
			chunk, err := encodeFileChunk(off, buf[:n])
			if err != nil {
				return sent, err
			}
			if err := sess.sendData(chunk); err != nil {
				return sent, err
			}
			off += uint64(n)
			sent += int64(n)
			if hooks != nil && hooks.AfterChunk != nil {
				if err := hooks.AfterChunk(e.Rel, off); err != nil {
					return sent, err
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return sent, wrap(KindApply, "read "+e.Rel, err)
		}
	}
	if off != uint64(e.Size) {
		return sent, failf(KindApply, "short read for %s", e.Rel)
	}
	end, err := encodeFileEnd(e.Rel, e.Digest)
	if err != nil {
		return sent, err
	}
	if err := sess.sendData(end); err != nil {
		return sent, err
	}
	return sent, nil
}

// recvFileChunked receives one file into store with resume support.
func recvFileChunked(sess *Session, store *localStore, begin fileBegin) error {
	start, err := store.beginFile(begin)
	if err != nil {
		return err
	}
	if err := sess.sendData(encodeFileAck(start)); err != nil {
		store.persistActive()
		return err
	}
	// Already complete in stage: still consume FileEnd from the peer.
	if !store.active {
		raw, err := sess.recvData()
		if err != nil {
			return err
		}
		endRel, endDig, err := decodeFileEnd(raw)
		if err != nil {
			return err
		}
		if endRel != begin.Rel || endDig != begin.Digest {
			return fail(KindProtocol, "file end mismatch")
		}
		return nil
	}
	for store.off < begin.Size {
		raw, err := sess.recvData()
		if err != nil {
			store.persistActive()
			return err
		}
		if len(raw) > 0 && raw[0] == msgFileEnd {
			return fail(KindProtocol, "unexpected file end before size complete")
		}
		coff, data, err := decodeFileChunk(raw)
		if err != nil {
			return err
		}
		if err := store.writeChunk(coff, data); err != nil {
			return err
		}
	}
	raw, err := sess.recvData()
	if err != nil {
		store.persistActive()
		return err
	}
	endRel, endDig, err := decodeFileEnd(raw)
	if err != nil {
		return err
	}
	return store.endFile(endRel, endDig)
}
