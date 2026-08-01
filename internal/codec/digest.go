package codec

import "crypto/sha256"

// DigestSize is the SHA-256 output length used by provisional journal commitments.
const DigestSize = 32

// Digest is a fixed-size cryptographic digest.
type Digest = [DigestSize]byte

// SHA256 returns SHA-256(data). Provisional per IP-F-0001 pending IP-C.
func SHA256(data []byte) Digest {
	return sha256.Sum256(data)
}

// GenesisCommitment is the previous_commitment for sequence == 1.
func GenesisCommitment() Digest {
	return Digest{}
}
