package remotesync

import (
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	maxPeerIDLen      = 64
	maxPeerKeyring    = 32
	peerPrologueMagic = "INTPID01"
	peerKeyringMagic  = "INTPEER1"
)

// PeerKeyring maps peer IDs to 32-byte PSKs (engineering admission allow-list).
type PeerKeyring map[string][]byte

// ValidatePeerID checks a bounded printable peer selector.
func ValidatePeerID(id string) error {
	if id == "" {
		return fail(KindInvalidArgument, "empty peer id")
	}
	if len(id) > maxPeerIDLen {
		return fail(KindInvalidArgument, "peer id too long")
	}
	for _, c := range id {
		if c < 0x21 || c > 0x7e || c == '=' {
			return fail(KindInvalidArgument, "peer id must be printable ASCII without '='")
		}
	}
	return nil
}

// ValidateKeyring checks bounds and key lengths.
func ValidateKeyring(kr PeerKeyring) error {
	if len(kr) == 0 {
		return fail(KindInvalidArgument, "empty peer keyring")
	}
	if len(kr) > maxPeerKeyring {
		return failf(KindInvalidArgument, "peer keyring exceeds %d entries", maxPeerKeyring)
	}
	for id, key := range kr {
		if err := ValidatePeerID(id); err != nil {
			return err
		}
		if len(key) != RootKeySize {
			return failf(KindInvalidArgument, "peer %s key must be %d bytes", id, RootKeySize)
		}
	}
	return nil
}

// EncodeKeyring packs a keyring for the auth-role root-key FD.
func EncodeKeyring(kr PeerKeyring) ([]byte, error) {
	if err := ValidateKeyring(kr); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(kr))
	for id := range kr {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := []byte(peerKeyringMagic)
	out = append(out, byte(len(ids)))
	for _, id := range ids {
		out = append(out, byte(len(id)))
		out = append(out, id...)
		out = append(out, kr[id]...)
	}
	return out, nil
}

// DecodeRootMaterial accepts a legacy 32-byte root key or an INTPEER1 keyring blob.
func DecodeRootMaterial(blob []byte) (single []byte, kr PeerKeyring, err error) {
	if len(blob) == RootKeySize {
		return append([]byte{}, blob...), nil, nil
	}
	if len(blob) < len(peerKeyringMagic)+1 || string(blob[:len(peerKeyringMagic)]) != peerKeyringMagic {
		return nil, nil, fail(KindInvalidArgument, "bad root key material")
	}
	n := int(blob[len(peerKeyringMagic)])
	if n == 0 || n > maxPeerKeyring {
		return nil, nil, fail(KindInvalidArgument, "bad keyring count")
	}
	off := len(peerKeyringMagic) + 1
	kr = make(PeerKeyring, n)
	for i := 0; i < n; i++ {
		if off >= len(blob) {
			return nil, nil, fail(KindInvalidArgument, "truncated keyring")
		}
		idLen := int(blob[off])
		off++
		if idLen == 0 || idLen > maxPeerIDLen || off+idLen+RootKeySize > len(blob) {
			return nil, nil, fail(KindInvalidArgument, "bad keyring entry")
		}
		id := string(blob[off : off+idLen])
		off += idLen
		key := append([]byte{}, blob[off:off+RootKeySize]...)
		off += RootKeySize
		if err := ValidatePeerID(id); err != nil {
			return nil, nil, err
		}
		if _, dup := kr[id]; dup {
			return nil, nil, failf(KindInvalidArgument, "duplicate peer id %s", id)
		}
		kr[id] = key
	}
	if off != len(blob) {
		return nil, nil, fail(KindInvalidArgument, "trailing keyring bytes")
	}
	return nil, kr, nil
}

// WritePeerPrologue writes an unauthenticated peer-id selector before negotiate.
func WritePeerPrologue(w io.Writer, peerID string) error {
	if err := ValidatePeerID(peerID); err != nil {
		return err
	}
	buf := make([]byte, 0, len(peerPrologueMagic)+1+len(peerID))
	buf = append(buf, peerPrologueMagic...)
	buf = append(buf, byte(len(peerID)))
	buf = append(buf, peerID...)
	_, err := w.Write(buf)
	if err != nil {
		return wrap(KindTransport, "peer prologue", err)
	}
	return nil
}

// ReadPeerPrologue reads the peer-id selector written by WritePeerPrologue.
func ReadPeerPrologue(r io.Reader) (string, error) {
	hdr := make([]byte, len(peerPrologueMagic)+1)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return "", wrap(KindTransport, "peer prologue", err)
	}
	if string(hdr[:len(peerPrologueMagic)]) != peerPrologueMagic {
		return "", fail(KindAuth, "missing peer prologue")
	}
	n := int(hdr[len(peerPrologueMagic)])
	if n == 0 || n > maxPeerIDLen {
		return "", fail(KindAuth, "bad peer id length")
	}
	id := make([]byte, n)
	if _, err := io.ReadFull(r, id); err != nil {
		return "", wrap(KindTransport, "peer id", err)
	}
	s := string(id)
	if err := ValidatePeerID(s); err != nil {
		return "", err
	}
	return s, nil
}

// ParsePeerKeyFlag parses ID=PATH for CLI -peer-key.
func ParsePeerKeyFlag(v string) (id, path string, err error) {
	v = strings.TrimSpace(v)
	i := strings.IndexByte(v, '=')
	if i <= 0 || i == len(v)-1 {
		return "", "", fmt.Errorf("peer-key must be ID=PATH")
	}
	id, path = v[:i], v[i+1:]
	if err := ValidatePeerID(id); err != nil {
		return "", "", err
	}
	if strings.TrimSpace(path) == "" {
		return "", "", fmt.Errorf("peer-key path empty")
	}
	return id, path, nil
}

// PeerIDDigest returns a short opaque hex id for logs (not the raw peer string if sensitive).
func PeerIDDigest(peerID string) string {
	sum := sha256.Sum256([]byte(peerID))
	return fmt.Sprintf("%x", sum[:8])
}
