package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// SuiteIDAEAD is the provisional engineering suite label (IP-C-0002).
const SuiteIDAEAD = "integris-session-aead-chacha20poly1305-v1"

// AEADNonceSize is the ChaCha20-Poly1305 nonce length.
const AEADNonceSize = chacha20poly1305.NonceSize

// AEADKeySize is the ChaCha20-Poly1305 key length.
const AEADKeySize = chacha20poly1305.KeySize

// SessionAEADKey derives a 32-byte session traffic key.
// Domain: info = SuiteIDAEAD || 0x00 || sessionID
func SessionAEADKey(rootKey []byte, sessionID [16]byte) ([]byte, error) {
	if len(rootKey) < 16 {
		return nil, fail("key", "root key must be at least 16 bytes")
	}
	info := make([]byte, 0, len(SuiteIDAEAD)+1+16)
	info = append(info, []byte(SuiteIDAEAD)...)
	info = append(info, 0)
	info = append(info, sessionID[:]...)
	return HKDFSHA256(rootKey, nil, info, AEADKeySize)
}

// SequenceNonce builds a 12-byte nonce: 4 zero bytes || seq (big-endian u64).
// Callers must never reuse (key, nonce) for distinct plaintexts.
func SequenceNonce(seq uint64) []byte {
	out := make([]byte, AEADNonceSize)
	binary.BigEndian.PutUint64(out[4:], seq)
	return out
}

// Seal encrypts plaintext with ChaCha20-Poly1305. Returns ciphertext||tag.
func Seal(key, nonce, aad, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fail("nonce", fmt.Sprintf("want %d bytes", aead.NonceSize()))
	}
	if len(plaintext) > 1<<20 {
		return nil, fail("limit", "plaintext too large")
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts ciphertext||tag produced by Seal.
func Open(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fail("nonce", fmt.Sprintf("want %d bytes", aead.NonceSize()))
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fail("auth", "AEAD open failed")
	}
	return pt, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != AEADKeySize {
		return nil, fail("key", fmt.Sprintf("AEAD key must be %d bytes", AEADKeySize))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fail("aead", err.Error())
	}
	return aead, nil
}
