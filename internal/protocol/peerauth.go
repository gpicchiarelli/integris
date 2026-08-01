package protocol

import "fmt"

// PeerAuthBody layout: 3-byte direction ("i2r"|"r2i") || HMAC proof.
const peerAuthDirLen = 3

// EncodePeerAuthBody packs direction and proof for a TypePeerAuth frame.
func EncodePeerAuthBody(direction string, proof []byte) []byte {
	return append([]byte(direction), proof...)
}

// ParsePeerAuthBody splits a TypePeerAuth body into direction and proof.
func ParsePeerAuthBody(body []byte) (direction string, proof []byte, err error) {
	if len(body) < peerAuthDirLen+16 {
		return "", nil, fail("auth", fmt.Sprintf("peer auth body too short (%d)", len(body)))
	}
	direction = string(body[:peerAuthDirLen])
	if direction != "i2r" && direction != "r2i" {
		return "", nil, fail("auth", "invalid peer auth direction")
	}
	return direction, append([]byte{}, body[peerAuthDirLen:]...), nil
}
