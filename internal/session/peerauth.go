package session

import (
	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/observability"
)

// MakeAuthProof builds a provisional HMAC proof over the current transcript
// (IP-C-0002). Session must be NEGOTIATED with a non-nil Transcript.
func (s *Session) MakeAuthProof(authKey []byte, sessionID [16]byte, direction string) ([]byte, error) {
	if s == nil {
		return nil, fail("state", "nil session")
	}
	if s.State != StateNegotiated {
		return nil, fail("state", "MakeAuthProof requires NEGOTIATED")
	}
	if s.Transcript == nil {
		return nil, fail("transcript", "transcript required")
	}
	cands := candidates(s.Offered)
	h, ok := highest(cands)
	if !ok || s.Selected != h {
		return nil, fail("downgrade", "selected version not highest candidate")
	}
	return crypto.PeerAuthProof(authKey, s.Transcript.Digest(), sessionID, direction)
}

// AuthenticateProof verifies a peer HMAC proof then enters PEER_AUTHENTICATED.
func (s *Session) AuthenticateProof(authKey []byte, sessionID [16]byte, direction string, proof []byte) error {
	if s.State != StateNegotiated {
		return fail("state", "AuthenticateProof requires NEGOTIATED")
	}
	if s.Transcript == nil {
		return fail("transcript", "transcript required")
	}
	cands := candidates(s.Offered)
	h, ok := highest(cands)
	if !ok || s.Selected != h {
		s.State = StateFailed
		s.emit("session.failed", "downgrade", "selected version not highest candidate", observability.SeverityError)
		return fail("downgrade", "selected version not highest candidate")
	}
	if err := crypto.VerifyPeerAuthProof(authKey, s.Transcript.Digest(), sessionID, direction, proof); err != nil {
		s.State = StateFailed
		s.emit("session.failed", "auth", "peer auth proof mismatch", observability.SeverityError)
		return fail("auth", err.Error())
	}
	s.PeerAuthenticated = true
	s.State = StatePeerAuthenticated
	// Bind proof tag (not the raw MAC) to avoid transcript circularity on verify.
	tag := crypto.HMACSHA256(authKey, append([]byte("proof-tag:"), proof...))
	s.bind("peer_auth", tag)
	s.bind("peer_auth_dir", []byte(direction))
	return nil
}
