package remotesync

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"

	"github.com/gpicchiarelli/integris/internal/crypto"
)

// RootKeySize is the required shared root key length.
const RootKeySize = 32

// ParseRootKey accepts raw 32 bytes or a hex string (64 hex chars).
func ParseRootKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fail(KindInvalidArgument, "empty root key")
	}
	if len(s) == RootKeySize {
		return []byte(s), nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, wrap(KindInvalidArgument, "key hex", err)
	}
	if len(b) != RootKeySize {
		return nil, failf(KindInvalidArgument, "root key must be %d bytes", RootKeySize)
	}
	return b, nil
}

// LoadRootKeyFile reads a root key from path (hex or raw 32 bytes).
func LoadRootKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, wrap(KindInvalidArgument, "key file", err)
	}
	return ParseRootKey(string(data))
}

func deriveMACKey(root []byte, peerID string) ([]byte, error) {
	base, err := crypto.ChannelMACKey(root, "push", "serve")
	if err != nil {
		return nil, err
	}
	if peerID == "" {
		return base, nil
	}
	// Bind the peer selector into the channel MAC key so prologue spoofing fails closed.
	return crypto.HKDFSHA256(base, nil, []byte("integris-peer-id|"+peerID), 32)
}

func newSessionID() ([16]byte, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, wrap(KindInternal, "session id", err)
	}
	return id, nil
}
