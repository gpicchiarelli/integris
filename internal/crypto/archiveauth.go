package crypto

import (
	"crypto/subtle"

	"github.com/gpicchiarelli/integris/internal/codec"
)

// SuiteIDArchiveAuth is the provisional archive-authorization proof label (IP-C-0002).
const SuiteIDArchiveAuth = "integris-archive-auth-hmac-sha256-v1"

// ArchiveAuthKey derives a 32-byte key for archive-authorization HMAC proofs.
func ArchiveAuthKey(rootKey []byte, sessionID [16]byte) ([]byte, error) {
	if len(rootKey) < 16 {
		return nil, fail("key", "root key must be at least 16 bytes")
	}
	info := make([]byte, 0, len(SuiteIDArchiveAuth)+1+16)
	info = append(info, []byte(SuiteIDArchiveAuth)...)
	info = append(info, 0)
	info = append(info, sessionID[:]...)
	return HKDFSHA256(rootKey, nil, info, 32)
}

// ArchiveAuthProof returns HMAC-SHA256(key, suite || 0x00 || sessionID || transcript).
func ArchiveAuthProof(authKey []byte, transcriptDig codec.Digest, sessionID [16]byte) ([]byte, error) {
	if len(authKey) < 16 {
		return nil, fail("key", "auth key too short")
	}
	msg := make([]byte, 0, len(SuiteIDArchiveAuth)+1+16+32)
	msg = append(msg, []byte(SuiteIDArchiveAuth)...)
	msg = append(msg, 0)
	msg = append(msg, sessionID[:]...)
	msg = append(msg, transcriptDig[:]...)
	return HMACSHA256(authKey, msg), nil
}

// VerifyArchiveAuthProof compares proof to the expected HMAC in constant time.
func VerifyArchiveAuthProof(authKey []byte, transcriptDig codec.Digest, sessionID [16]byte, proof []byte) error {
	want, err := ArchiveAuthProof(authKey, transcriptDig, sessionID)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(want, proof) != 1 {
		return fail("auth", "archive auth proof mismatch")
	}
	return nil
}
