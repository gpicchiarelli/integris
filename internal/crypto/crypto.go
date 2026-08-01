// Package crypto provides provisional M1/M2 engineering primitives per
// IP-C-0001 (SHA-256, HMAC-SHA256, HKDF-SHA256) and IP-C-0002
// (ChaCha20-Poly1305 session AEAD).
//
// Nothing here is a release cryptographic claim. Independent review is required
// before promoting EVD-PROTO or release signing evidence.
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/gpicchiarelli/integris/internal/codec"
)

// Error is a typed crypto-helper failure.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Code + ": " + e.Message
}

func fail(code, msg string) error { return &Error{Code: code, Message: msg} }

// HMACSHA256 returns HMAC-SHA256(key, msg).
func HMACSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(msg)
	return m.Sum(nil)
}

// HKDFSHA256 implements RFC 5869 extract+expand with SHA-256.
// salt may be nil (then treated as HashLen zeros). length must be in 1..255*32.
func HKDFSHA256(ikm, salt, info []byte, length int) ([]byte, error) {
	if length <= 0 || length > 255*sha256.Size {
		return nil, fail("length", fmt.Sprintf("invalid HKDF length %d", length))
	}
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	extractor := hmac.New(sha256.New, salt)
	_, _ = extractor.Write(ikm)
	prk := extractor.Sum(nil)

	var out []byte
	var prev []byte
	var counter byte = 1
	for len(out) < length {
		expander := hmac.New(sha256.New, prk)
		_, _ = expander.Write(prev)
		_, _ = expander.Write(info)
		_, _ = expander.Write([]byte{counter})
		prev = expander.Sum(nil)
		out = append(out, prev...)
		counter++
		if counter == 0 {
			return nil, fail("expand", "HKDF counter overflow")
		}
	}
	return out[:length], nil
}

// ChannelMACKey derives a 32-byte provisional IPC MAC key for an unordered
// peer pair. Roles are sorted so both endpoints derive the same key.
// Domain: info = "integris-ipc-mac-v1" || 0x00 || roleLo || 0x00 || roleHi
func ChannelMACKey(rootKey []byte, roleA, roleB string) ([]byte, error) {
	if len(rootKey) < 16 {
		return nil, fail("key", "root key must be at least 16 bytes")
	}
	if roleA == "" || roleB == "" {
		return nil, fail("role", "empty role")
	}
	if roleA == roleB {
		return nil, fail("role", "roles must differ")
	}
	lo, hi := roleA, roleB
	if lo > hi {
		lo, hi = hi, lo
	}
	info := make([]byte, 0, 64+len(lo)+len(hi))
	info = append(info, []byte("integris-ipc-mac-v1")...)
	info = append(info, 0)
	info = append(info, lo...)
	info = append(info, 0)
	info = append(info, hi...)
	return HKDFSHA256(rootKey, nil, info, 32)
}

// Transcript accumulates length-prefixed labeled fields for negotiation binding.
type Transcript struct {
	h hash.Hash
}

// NewTranscript starts an empty SHA-256 transcript.
func NewTranscript() *Transcript {
	return &Transcript{h: sha256.New()}
}

// Append adds one labeled field. Labels and data are length-prefixed (u32 LE)
// to avoid ambiguity. Empty label is rejected.
func (t *Transcript) Append(label string, data []byte) error {
	if t == nil || t.h == nil {
		return fail("state", "nil transcript")
	}
	if label == "" {
		return fail("label", "empty label")
	}
	if len(label) > 65535 || len(data) > 1<<20 {
		return fail("limit", "label or data too large")
	}
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(label)))
	_, _ = t.h.Write(tmp[:])
	_, _ = t.h.Write([]byte(label))
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(data)))
	_, _ = t.h.Write(tmp[:])
	_, _ = t.h.Write(data)
	return nil
}

// Digest returns the current transcript commitment.
func (t *Transcript) Digest() codec.Digest {
	if t == nil || t.h == nil {
		return codec.Digest{}
	}
	sum := t.h.Sum(nil)
	var d codec.Digest
	copy(d[:], sum)
	return d
}
