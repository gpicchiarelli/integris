package crypto

import (
	"crypto/subtle"

	"github.com/gpicchiarelli/integris/internal/codec"
)

// SuiteIDPeerAuth is the provisional peer-auth proof label (IP-C-0002).
const SuiteIDPeerAuth = "integris-peer-auth-hmac-sha256-v1"

// PeerAuthKey derives a 32-byte key for transcript HMAC proofs.
func PeerAuthKey(rootKey []byte, sessionID [16]byte) ([]byte, error) {
	if len(rootKey) < 16 {
		return nil, fail("key", "root key must be at least 16 bytes")
	}
	info := make([]byte, 0, len(SuiteIDPeerAuth)+1+16)
	info = append(info, []byte(SuiteIDPeerAuth)...)
	info = append(info, 0)
	info = append(info, sessionID[:]...)
	return HKDFSHA256(rootKey, nil, info, 32)
}

// PeerAuthProof returns HMAC-SHA256(authKey, suite || 0x00 || sessionID || transcript || direction).
// direction distinguishes initiator→responder ("i2r") vs responder→initiator ("r2i").
func PeerAuthProof(authKey []byte, transcriptDig codec.Digest, sessionID [16]byte, direction string) ([]byte, error) {
	if len(authKey) < 16 {
		return nil, fail("key", "auth key too short")
	}
	if direction != "i2r" && direction != "r2i" {
		return nil, fail("direction", "direction must be i2r or r2i")
	}
	msg := make([]byte, 0, len(SuiteIDPeerAuth)+1+16+32+len(direction))
	msg = append(msg, []byte(SuiteIDPeerAuth)...)
	msg = append(msg, 0)
	msg = append(msg, sessionID[:]...)
	msg = append(msg, transcriptDig[:]...)
	msg = append(msg, []byte(direction)...)
	return HMACSHA256(authKey, msg), nil
}

// VerifyPeerAuthProof compares proof to the expected HMAC in constant time.
func VerifyPeerAuthProof(authKey []byte, transcriptDig codec.Digest, sessionID [16]byte, direction string, proof []byte) error {
	want, err := PeerAuthProof(authKey, transcriptDig, sessionID, direction)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(want, proof) != 1 {
		return fail("auth", "peer auth proof mismatch")
	}
	return nil
}
