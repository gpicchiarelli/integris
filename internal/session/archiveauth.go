package session

import (
	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/observability"
)

// MakeArchiveProof builds a provisional HMAC over the frozen post-peer-auth
// transcript digest (IP-C-0002).
func (s *Session) MakeArchiveProof(authKey []byte, sessionID [16]byte) ([]byte, error) {
	if s == nil {
		return nil, fail("state", "nil session")
	}
	if s.State != StatePeerAuthenticated || !s.PeerAuthenticated {
		return nil, fail("state", "MakeArchiveProof requires PEER_AUTHENTICATED")
	}
	if !s.ArchiveBaseSet {
		return nil, fail("transcript", "archive base digest required")
	}
	return crypto.ArchiveAuthProof(authKey, s.ArchiveBaseDigest, sessionID)
}

// AuthorizeArchiveProof verifies an archive HMAC proof then enters
// ARCHIVE_AUTHORIZED. Proofs verify against the frozen ArchiveBaseDigest.
func (s *Session) AuthorizeArchiveProof(authKey []byte, sessionID [16]byte, proof []byte) error {
	if s.State != StatePeerAuthenticated || !s.PeerAuthenticated {
		return fail("state", "AuthorizeArchiveProof requires PEER_AUTHENTICATED")
	}
	if !s.ArchiveBaseSet {
		return fail("transcript", "archive base digest required")
	}
	if err := crypto.VerifyArchiveAuthProof(authKey, s.ArchiveBaseDigest, sessionID, proof); err != nil {
		s.State = StateFailed
		s.emit("session.failed", "archive", "archive auth proof mismatch", observability.SeverityError)
		return fail("archive", err.Error())
	}
	tag := crypto.HMACSHA256(authKey, append([]byte("archive-tag:"), proof...))
	s.bind("archive_auth", tag)
	s.ArchiveAuthorized = true
	s.State = StateArchiveAuthorized
	return nil
}

// freezeArchiveBase snapshots the transcript after mutual peer-auth.
func (s *Session) freezeArchiveBase() {
	if s == nil || s.Transcript == nil {
		return
	}
	s.ArchiveBaseDigest = s.Transcript.Digest()
	s.ArchiveBaseSet = true
}
