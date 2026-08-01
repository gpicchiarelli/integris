// Package session implements the authenticated session state machine refined
// from formal/session/Session.tla (M1 conformance surface for VER-PROTO-001).
//
// TLC does not prove this Go code. Peer authentication may use the boolean
// Authenticate step (TLA conformance; both directions at once) or mutual
// AuthenticateProof for i2r and r2i. Archive authorization may use boolean
// AuthorizeArchive or AuthorizeArchiveProof (provisional HMAC over the frozen
// post-peer-auth digest, IP-C-0002). Traffic protection uses provisional AEAD
// after suite negotiation and transcript-bound key derivation.
package session

import (
	"fmt"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/observability"
)

// Version is a protocol version identifier.
type Version uint8

const (
	MinVersion Version = 1
	MaxVersion Version = 3
)

// LocalAllowed is the local negotiation allow-list (matches TLA+ LocalAllowed).
var LocalAllowed = []Version{2, 3}

// MaxMessages bounds AcceptNext (matches TLA+ MaxMessages).
const MaxMessages = 3

// State mirrors Session.tla States.
type State string

const (
	StateNew               State = "NEW"
	StateNegotiated        State = "NEGOTIATED"
	StatePeerAuthenticated State = "PEER_AUTHENTICATED"
	StateArchiveAuthorized State = "ARCHIVE_AUTHORIZED"
	StateActive            State = "ACTIVE"
	StateClosed            State = "CLOSED"
	StateFailed            State = "FAILED"
)

// Session is one connection's negotiation/auth state.
type Session struct {
	State             State
	Offered           []Version
	Selected          Version
	OfferedSuites     []string
	SelectedSuite     string
	RequireSuite      bool // when true, Negotiate fails without a common suite
	PeerAuthenticated bool
	AuthI2R           bool // initiator→responder proof accepted
	AuthR2I           bool // responder→initiator proof accepted
	ArchiveAuthorized bool
	ReceiveSequence   uint64
	ReplayAccepted    bool
	ProductMutation   bool
	// Events is an optional sink for redacted session lifecycle events.
	// Emission failures never fail session transitions.
	Events observability.Sink
	// Transcript, when non-nil, records negotiation/auth steps for binding
	// (provisional SHA-256 per IP-C-0001). Not a session AEAD.
	Transcript *crypto.Transcript
	// AuthBaseDigest is frozen at Negotiate for mutual peer-auth MACs.
	AuthBaseDigest codec.Digest
	AuthBaseSet    bool
	// ArchiveBaseDigest is frozen when entering PEER_AUTHENTICATED.
	ArchiveBaseDigest codec.Digest
	ArchiveBaseSet    bool
}

func (s *Session) emit(id, cause, message string, sev observability.Severity) {
	if s == nil || s.Events == nil {
		return
	}
	_ = s.Events.Emit(observability.Event{
		ID:            observability.EventID(id),
		Channel:       observability.ChannelSecurity,
		Severity:      sev,
		Component:     "session",
		CauseCategory: cause,
		Redaction:     observability.RedactionInternal,
		Message:       message,
	})
}

func (s *Session) bind(label string, data []byte) {
	if s == nil || s.Transcript == nil {
		return
	}
	_ = s.Transcript.Append(label, data)
}

func (s *Session) bindVersions(label string, vers []Version) {
	if s == nil || s.Transcript == nil {
		return
	}
	buf := make([]byte, len(vers))
	for i, v := range vers {
		buf[i] = byte(v)
	}
	_ = s.Transcript.Append(label, buf)
}

// Error is a typed session failure.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Code + ": " + e.Message
}

func fail(code, msg string) error { return &Error{Code: code, Message: msg} }

// New starts in NEW with the peer's offered versions.
func New(offered []Version) Session {
	cp := append([]Version{}, offered...)
	return Session{State: StateNew, Offered: cp, RequireSuite: false}
}

// NewWithSuites starts in NEW with versions and peer-offered crypto suites.
// RequireSuite is true: negotiation fails closed without a common suite.
func NewWithSuites(offered []Version, suites []string) Session {
	s := New(offered)
	s.OfferedSuites = append([]string{}, suites...)
	s.RequireSuite = true
	return s
}

func highest(cands []Version) (Version, bool) {
	if len(cands) == 0 {
		return 0, false
	}
	h := cands[0]
	for _, v := range cands[1:] {
		if v > h {
			h = v
		}
	}
	return h, true
}

func candidates(offered []Version) []Version {
	allow := map[Version]struct{}{}
	for _, v := range LocalAllowed {
		allow[v] = struct{}{}
	}
	var out []Version
	for _, v := range offered {
		if _, ok := allow[v]; ok {
			out = append(out, v)
		}
	}
	return out
}

// Negotiate selects the highest mutually allowed version.
func (s *Session) Negotiate() error {
	if s.State != StateNew {
		return fail("state", "Negotiate requires NEW")
	}
	cands := candidates(s.Offered)
	h, ok := highest(cands)
	if !ok {
		s.State = StateFailed
		s.emit("session.failed", "version", "no common version", observability.SeverityError)
		return fail("version", "no common version")
	}
	s.Selected = h
	s.State = StateNegotiated
	s.bind("negotiate", []byte{byte(h)})
	s.bindVersions("offered", s.Offered)
	s.bindVersions("local_allowed", LocalAllowed)
	if s.RequireSuite || len(s.OfferedSuites) > 0 {
		suite, ok := SelectSuite(LocalSuites, s.OfferedSuites)
		if !ok {
			s.State = StateFailed
			s.emit("session.failed", "suite", "no common crypto suite", observability.SeverityError)
			return fail("suite", "no common crypto suite")
		}
		s.SelectedSuite = suite
		s.bind("suite", []byte(suite))
	}
	s.freezeAuthBase()
	return nil
}

// ConfirmAccept fail-closes if a peer NegotiateAccept selection disagrees with
// the local Negotiate result (IP-P-0001 / IP-C-0002). Does not mutate the
// transcript — selection was already bound in Negotiate.
func (s *Session) ConfirmAccept(vers Version, suite string) error {
	if s.State != StateNegotiated {
		return fail("state", "ConfirmAccept requires NEGOTIATED")
	}
	if s.Selected != vers {
		s.State = StateFailed
		s.emit("session.failed", "version", "accept version mismatch", observability.SeverityError)
		return fail("version", "accept version mismatch")
	}
	if suite == "" {
		if s.SelectedSuite != "" {
			s.State = StateFailed
			s.emit("session.failed", "suite", "accept suite missing", observability.SeverityError)
			return fail("suite", "accept suite missing")
		}
		return nil
	}
	if s.SelectedSuite != suite {
		s.State = StateFailed
		s.emit("session.failed", "suite", "accept suite mismatch", observability.SeverityError)
		return fail("suite", "accept suite mismatch")
	}
	return nil
}

// Authenticate records successful mutual peer authentication without crypto
// proofs (TLA conformance / tests). Prefer AuthenticateProof for i2r and r2i.
func (s *Session) Authenticate() error {
	if s.State != StateNegotiated {
		return fail("state", "Authenticate requires NEGOTIATED")
	}
	cands := candidates(s.Offered)
	h, ok := highest(cands)
	if !ok || s.Selected != h {
		s.State = StateFailed
		s.emit("session.failed", "downgrade", "selected version not highest candidate", observability.SeverityError)
		return fail("downgrade", "selected version not highest candidate")
	}
	s.AuthI2R = true
	s.AuthR2I = true
	s.PeerAuthenticated = true
	s.State = StatePeerAuthenticated
	s.bind("peer_auth", []byte{1})
	s.freezeArchiveBase()
	return nil
}

// AuthorizeArchive records archive authorization without a crypto proof
// (TLA conformance / tests). Prefer AuthorizeArchiveProof when ArchiveKey is set.
func (s *Session) AuthorizeArchive() error {
	if s.State != StatePeerAuthenticated || !s.PeerAuthenticated {
		return fail("state", "AuthorizeArchive requires PEER_AUTHENTICATED")
	}
	s.ArchiveAuthorized = true
	s.State = StateArchiveAuthorized
	s.bind("archive_auth", []byte{1})
	return nil
}

// Activate enters ACTIVE only when authenticated, archive-authorized, and not downgraded.
func (s *Session) Activate() error {
	if s.State != StateArchiveAuthorized {
		return fail("state", "Activate requires ARCHIVE_AUTHORIZED")
	}
	if !s.PeerAuthenticated || !s.ArchiveAuthorized {
		s.State = StateFailed
		s.emit("session.failed", "auth", "missing authentication or archive authorization", observability.SeverityError)
		return fail("auth", "missing authentication or archive authorization")
	}
	cands := candidates(s.Offered)
	h, ok := highest(cands)
	if !ok || s.Selected != h {
		s.State = StateFailed
		s.emit("session.failed", "downgrade", "active session would be downgraded", observability.SeverityError)
		return fail("downgrade", "active session would be downgraded")
	}
	s.State = StateActive
	s.bind("activate", []byte{byte(s.Selected)})
	if s.SelectedSuite != "" {
		s.bind("suite_active", []byte(s.SelectedSuite))
	}
	return nil
}

// AcceptNext accepts the next monotonic message and may mark product mutation.
func (s *Session) AcceptNext() error {
	if s.State != StateActive {
		return fail("state", "AcceptNext requires ACTIVE")
	}
	if s.ReceiveSequence >= MaxMessages {
		return fail("limit", fmt.Sprintf("receive sequence at MaxMessages=%d", MaxMessages))
	}
	s.ReceiveSequence++
	s.ProductMutation = true
	return nil
}

// RejectReplay fails the session without accepting replay.
func (s *Session) RejectReplay() error {
	if s.State != StateActive {
		return fail("state", "RejectReplay requires ACTIVE")
	}
	s.ReplayAccepted = false
	s.State = StateFailed
	s.emit("session.failed", "replay", "replay rejected", observability.SeverityCritical)
	return nil
}

// Close transitions ACTIVE → CLOSED.
func (s *Session) Close() error {
	if s.State != StateActive {
		return fail("state", "Close requires ACTIVE")
	}
	s.State = StateClosed
	s.emit("session.closed", "close", "session closed", observability.SeverityInfo)
	return nil
}

// Invariants holds TLA+-shaped safety checks for the current state.
func (s Session) Invariants() error {
	if s.State == StateActive {
		if !s.PeerAuthenticated || !s.ArchiveAuthorized {
			return fail("inv", "ActiveIsAuthorized violated")
		}
		cands := candidates(s.Offered)
		h, ok := highest(cands)
		if !ok || s.Selected != h {
			return fail("inv", "ActiveIsNotDowngraded violated")
		}
	}
	if s.ReplayAccepted {
		return fail("inv", "ReplayNeverAccepted violated")
	}
	if s.ProductMutation && !(s.PeerAuthenticated && s.ArchiveAuthorized) {
		return fail("inv", "MutationIsAuthorized violated")
	}
	if s.State == StatePeerAuthenticated || s.PeerAuthenticated {
		if !(s.AuthI2R && s.AuthR2I) {
			return fail("inv", "PeerAuthIsMutual violated")
		}
	}
	return nil
}
