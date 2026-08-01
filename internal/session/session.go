// Package session implements the authenticated session state machine refined
// from formal/session/Session.tla (M1 conformance surface for VER-PROTO-001).
//
// TLC does not prove this Go code. Cryptographic authentication is stubbed as
// explicit boolean steps pending IP-C.
package session

import (
	"fmt"

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
	PeerAuthenticated bool
	ArchiveAuthorized bool
	ReceiveSequence   uint64
	ReplayAccepted    bool
	ProductMutation   bool
	// Events is an optional sink for redacted session lifecycle events.
	// Emission failures never fail session transitions.
	Events observability.Sink
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
	return Session{State: StateNew, Offered: cp}
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
	return nil
}

// Authenticate records successful peer authentication (crypto pending IP-C).
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
	s.PeerAuthenticated = true
	s.State = StatePeerAuthenticated
	return nil
}

// AuthorizeArchive records archive authorization.
func (s *Session) AuthorizeArchive() error {
	if s.State != StatePeerAuthenticated || !s.PeerAuthenticated {
		return fail("state", "AuthorizeArchive requires PEER_AUTHENTICATED")
	}
	s.ArchiveAuthorized = true
	s.State = StateArchiveAuthorized
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
	return nil
}
