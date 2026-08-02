package remotesync

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/localsync"
)

const (
	msgManifest   byte = 1
	msgManifestOK byte = 2
	msgFile       byte = 3 // legacy single-frame (decode kept for tests)
	msgCommit     byte = 4
	msgResult     byte = 5
	msgFileBegin  byte = 6
	msgFileAck    byte = 7
	msgFileChunk  byte = 8
	msgFileEnd    byte = 9
)

// Leave headroom under protocol.MaxBodyBytes for AEAD/MAC overhead in body field.
const protocolMaxBodyUseful = (1 << 20) - 256

type fileWire struct {
	Rel    string
	Mode   uint32
	Digest codec.Digest
	Data   []byte
}

func encodeManifest(entries []localsync.Entry) ([]byte, error) {
	b := []byte{msgManifest}
	b = appendU32(b, uint32(len(entries)))
	for _, e := range entries {
		if e.Type != localsync.EntryFile && e.Type != localsync.EntryDir {
			return nil, failf(KindProtocol, "unsupported entry type %s", e.Type)
		}
		var t byte
		if e.Type == localsync.EntryDir {
			t = 1
		} else {
			t = 2
		}
		b = append(b, t)
		var err error
		if b, err = appendString(b, e.Rel); err != nil {
			return nil, err
		}
		b = appendU32(b, e.Mode)
		b = appendU64(b, uint64(e.Size))
		if e.Type == localsync.EntryFile {
			if !e.HasDigest {
				return nil, fail(KindProtocol, "file missing digest")
			}
			b = append(b, e.Digest[:]...)
		}
	}
	if len(b) > protocolMaxBodyUseful {
		return nil, fail(KindProtocol, "manifest too large for one frame")
	}
	return b, nil
}

func decodeManifest(p []byte) ([]localsync.Entry, error) {
	if len(p) < 5 || p[0] != msgManifest {
		return nil, fail(KindProtocol, "bad manifest")
	}
	n, rest, err := takeU32(p[1:])
	if err != nil {
		return nil, err
	}
	out := make([]localsync.Entry, 0, n)
	for i := uint32(0); i < n; i++ {
		if len(rest) < 1 {
			return nil, fail(KindProtocol, "short manifest entry")
		}
		t := rest[0]
		rest = rest[1:]
		var rel string
		rel, rest, err = takeString(rest)
		if err != nil {
			return nil, err
		}
		var mode uint32
		mode, rest, err = takeU32(rest)
		if err != nil {
			return nil, err
		}
		var size uint64
		size, rest, err = takeU64(rest)
		if err != nil {
			return nil, err
		}
		e := localsync.Entry{Rel: rel, Mode: mode, Size: int64(size)}
		switch t {
		case 1:
			e.Type = localsync.EntryDir
		case 2:
			e.Type = localsync.EntryFile
			if len(rest) < 32 {
				return nil, fail(KindProtocol, "short digest")
			}
			copy(e.Digest[:], rest[:32])
			e.HasDigest = true
			rest = rest[32:]
		default:
			return nil, failf(KindProtocol, "bad entry type %d", t)
		}
		out = append(out, e)
	}
	if len(rest) != 0 {
		return nil, fail(KindProtocol, "trailing manifest bytes")
	}
	return out, nil
}

func encodeManifestOK() []byte { return []byte{msgManifestOK} }

func encodeFile(f fileWire) ([]byte, error) {
	b := []byte{msgFile}
	var err error
	if b, err = appendString(b, f.Rel); err != nil {
		return nil, err
	}
	b = appendU32(b, f.Mode)
	b = append(b, f.Digest[:]...)
	b = appendU32(b, uint32(len(f.Data)))
	b = append(b, f.Data...)
	if len(b) > protocolMaxBodyUseful {
		return nil, failf(KindProtocol, "file %s too large for single-frame transfer", f.Rel)
	}
	return b, nil
}

func decodeFile(p []byte) (fileWire, error) {
	var zero fileWire
	if len(p) < 1 || p[0] != msgFile {
		return zero, fail(KindProtocol, "bad file msg")
	}
	rest := p[1:]
	rel, rest, err := takeString(rest)
	if err != nil {
		return zero, err
	}
	mode, rest, err := takeU32(rest)
	if err != nil {
		return zero, err
	}
	if len(rest) < 32 {
		return zero, fail(KindProtocol, "short file digest")
	}
	var dig codec.Digest
	copy(dig[:], rest[:32])
	rest = rest[32:]
	n, rest, err := takeU32(rest)
	if err != nil {
		return zero, err
	}
	if uint32(len(rest)) != n {
		return zero, fail(KindProtocol, "file data length mismatch")
	}
	return fileWire{Rel: rel, Mode: mode, Digest: dig, Data: append([]byte{}, rest...)}, nil
}

type fileBegin struct {
	Rel    string
	Mode   uint32
	Digest codec.Digest
	Size   uint64
}

func encodeFileBegin(rel string, mode uint32, dig codec.Digest, size uint64) ([]byte, error) {
	b := []byte{msgFileBegin}
	var err error
	if b, err = appendString(b, rel); err != nil {
		return nil, err
	}
	b = appendU32(b, mode)
	b = append(b, dig[:]...)
	b = appendU64(b, size)
	return b, nil
}

func decodeFileBegin(p []byte) (fileBegin, error) {
	var zero fileBegin
	if len(p) < 1 || p[0] != msgFileBegin {
		return zero, fail(KindProtocol, "bad file begin")
	}
	rest := p[1:]
	rel, rest, err := takeString(rest)
	if err != nil {
		return zero, err
	}
	mode, rest, err := takeU32(rest)
	if err != nil {
		return zero, err
	}
	if len(rest) != 32+8 {
		return zero, fail(KindProtocol, "bad file begin length")
	}
	var dig codec.Digest
	copy(dig[:], rest[:32])
	size := binary.LittleEndian.Uint64(rest[32:40])
	return fileBegin{Rel: rel, Mode: mode, Digest: dig, Size: size}, nil
}

func encodeFileAck(offset uint64) []byte {
	b := []byte{msgFileAck}
	return appendU64(b, offset)
}

func decodeFileAck(p []byte) (uint64, error) {
	if len(p) != 1+8 || p[0] != msgFileAck {
		return 0, fail(KindProtocol, "bad file ack")
	}
	return binary.LittleEndian.Uint64(p[1:9]), nil
}

func encodeFileChunk(offset uint64, data []byte) ([]byte, error) {
	// msg + u64 offset + u32 len + data; must fit protocolMaxBodyUseful
	overhead := 1 + 8 + 4
	if overhead+len(data) > protocolMaxBodyUseful {
		return nil, fail(KindProtocol, "chunk too large")
	}
	b := []byte{msgFileChunk}
	b = appendU64(b, offset)
	b = appendU32(b, uint32(len(data)))
	return append(b, data...), nil
}

func decodeFileChunk(p []byte) (offset uint64, data []byte, err error) {
	if len(p) < 1+8+4 || p[0] != msgFileChunk {
		return 0, nil, fail(KindProtocol, "bad file chunk")
	}
	offset = binary.LittleEndian.Uint64(p[1:9])
	n := binary.LittleEndian.Uint32(p[9:13])
	if 13+int(n) != len(p) {
		return 0, nil, fail(KindProtocol, "chunk length mismatch")
	}
	return offset, append([]byte{}, p[13:]...), nil
}

func encodeFileEnd(rel string, dig codec.Digest) ([]byte, error) {
	b := []byte{msgFileEnd}
	var err error
	if b, err = appendString(b, rel); err != nil {
		return nil, err
	}
	return append(b, dig[:]...), nil
}

func decodeFileEnd(p []byte) (rel string, dig codec.Digest, err error) {
	if len(p) < 1 || p[0] != msgFileEnd {
		return "", dig, fail(KindProtocol, "bad file end")
	}
	rel, rest, err := takeString(p[1:])
	if err != nil {
		return "", dig, err
	}
	if len(rest) != 32 {
		return "", dig, fail(KindProtocol, "file end digest length")
	}
	copy(dig[:], rest)
	return rel, dig, nil
}

func encodeCommit() []byte { return []byte{msgCommit} }

func encodeResult(ok bool, msg string) ([]byte, error) {
	b := []byte{msgResult}
	if ok {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	return appendString(b, msg)
}

func decodeResult(p []byte) (bool, string, error) {
	if len(p) < 2 || p[0] != msgResult {
		return false, "", fail(KindProtocol, "bad result")
	}
	ok := p[1] == 1
	msg, rest, err := takeString(p[2:])
	if err != nil {
		return false, "", err
	}
	if len(rest) != 0 {
		return false, "", fail(KindProtocol, "trailing result")
	}
	return ok, msg, nil
}

func appendU32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

func appendU64(b []byte, v uint64) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	return append(b, tmp[:]...)
}

func appendString(b []byte, s string) ([]byte, error) {
	if len(s) > 65535 {
		return nil, fail(KindProtocol, "string too long")
	}
	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], uint16(len(s)))
	b = append(b, tmp[:]...)
	return append(b, s...), nil
}

func takeU32(b []byte) (uint32, []byte, error) {
	if len(b) < 4 {
		return 0, nil, fail(KindProtocol, "short u32")
	}
	return binary.LittleEndian.Uint32(b[:4]), b[4:], nil
}

func takeU64(b []byte) (uint64, []byte, error) {
	if len(b) < 8 {
		return 0, nil, fail(KindProtocol, "short u64")
	}
	return binary.LittleEndian.Uint64(b[:8]), b[8:], nil
}

func takeString(b []byte) (string, []byte, error) {
	if len(b) < 2 {
		return "", nil, fail(KindProtocol, "short string")
	}
	n := int(binary.LittleEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < n {
		return "", nil, fail(KindProtocol, "short string body")
	}
	return string(b[:n]), b[n:], nil
}

func digestHex(d codec.Digest) string { return hex.EncodeToString(d[:]) }
