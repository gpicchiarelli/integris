package session

import (
	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/observability"
)

// MakeAuthProof builds a provisional HMAC proof over the frozen post-negotiate
// transcript digest (IP-C-0002). Direction is "i2r" or "r2i".
func (s *Session) MakeAuthProof(authKey []byte, sessionID [16]byte, direction string) ([]byte, error) {
	if s == nil {
		return nil, fail("state", "nil session")
	}
	if s.State != StateNegotiated {
		return nil, fail("state", "MakeAuthProof requires NEGOTIATED")
	}
	if !s.AuthBaseSet {
		return nil, fail("transcript", "auth base digest required")
	}
	cands := candidates(s.Offered)
	h, ok := highest(cands)
	if !ok || s.Selected != h {
		return nil, fail("downgrade", "selected version not highest candidate")
	}
	return crypto.PeerAuthProof(authKey, s.AuthBaseDigest, sessionID, direction)
}

// AuthenticateProof verifies one directional HMAC proof. PEER_AUTHENTICATED is
// entered only after both i2r and r2i succeed (unordered). Proofs always verify
// against the frozen AuthBaseDigest so order does not shift the MAC input.
func (s *Session) AuthenticateProof(authKey []byte, sessionID [16]byte, direction string, proof []byte) error {
	if s.State != StateNegotiated {
		return fail("state", "AuthenticateProof requires NEGOTIATED")
	}
	if !s.AuthBaseSet {
		return fail("transcript", "auth base digest required")
	}
	cands := candidates(s.Offered)
	h, ok := highest(cands)
	if !ok || s.Selected != h {
		s.State = StateFailed
		s.emit("session.failed", "downgrade", "selected version not highest candidate", observability.SeverityError)
		return fail("downgrade", "selected version not highest candidate")
	}
	switch direction {
	case "i2r":
		if s.AuthI2R {
			s.State = StateFailed
			s.emit("session.failed", "auth", "duplicate i2r proof", observability.SeverityError)
			return fail("auth", "duplicate i2r proof")
		}
	case "r2i":
		if s.AuthR2I {
			s.State = StateFailed
			s.emit("session.failed", "auth", "duplicate r2i proof", observability.SeverityError)
			return fail("auth", "duplicate r2i proof")
		}
	default:
		return fail("direction", "direction must be i2r or r2i")
	}
	if err := crypto.VerifyPeerAuthProof(authKey, s.AuthBaseDigest, sessionID, direction, proof); err != nil {
		s.State = StateFailed
		s.emit("session.failed", "auth", "peer auth proof mismatch", observability.SeverityError)
		return fail("auth", err.Error())
	}
	// Bind proof tag (not the raw MAC) after verify; does not affect AuthBaseDigest.
	tag := crypto.HMACSHA256(authKey, append([]byte("proof-tag:"), proof...))
	s.bind("peer_auth", tag)
	s.bind("peer_auth_dir", []byte(direction))
	if direction == "i2r" {
		s.AuthI2R = true
	} else {
		s.AuthR2I = true
	}
	if s.AuthI2R && s.AuthR2I {
		s.PeerAuthenticated = true
		s.State = StatePeerAuthenticated
		s.freezeArchiveBase()
	}
	return nil
}

// freezeAuthBase snapshots the negotiation transcript for mutual peer-auth MACs.
func (s *Session) freezeAuthBase() {
	if s == nil || s.Transcript == nil {
		return
	}
	s.AuthBaseDigest = s.Transcript.Digest()
	s.AuthBaseSet = true
}
