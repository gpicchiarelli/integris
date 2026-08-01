// Package observability implements redacted operational/security event records
// per docs/specifications/observability.md (M1 MVP).
//
// Operational logs are not primary integrity evidence; the journal remains
// authoritative for transaction claims.
package observability

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/resource"
)

// Channel separates event sinks.
type Channel uint8

const (
	ChannelOperational Channel = 1
	ChannelSecurity    Channel = 2
	ChannelAudit       Channel = 3
	ChannelDiagnostic  Channel = 4
	ChannelMetrics     Channel = 5
)

// Severity is a stable severity class.
type Severity uint8

const (
	SeverityDebug    Severity = 1
	SeverityInfo     Severity = 2
	SeverityWarning  Severity = 3
	SeverityError    Severity = 4
	SeverityCritical Severity = 5
)

// RedactionClass controls what may appear in Message.
type RedactionClass uint8

const (
	RedactionPublic    RedactionClass = 1
	RedactionInternal  RedactionClass = 2
	RedactionSensitive RedactionClass = 3 // message must be empty or opaque id only
	RedactionForbidden RedactionClass = 4 // must not emit content fields
)

// EventID is a stable event type identifier (ASCII, bounded).
type EventID string

// Event is one redacted observability record.
type Event struct {
	ID               EventID
	Channel          Channel
	Severity         Severity
	Component        string
	ArchivePseudonym codec.Digest // keyed commitment / pseudonym; never a path
	TransactionID    [16]byte
	Sequence         uint64
	CauseCategory    string
	Redaction        RedactionClass
	Message          string // already sanitized; empty when Sensitive/Forbidden
}

// Error is a typed observability failure.
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

func reject(code, msg string) error { return &Error{Code: code, Message: msg} }

const (
	maxEventIDLen   = 64
	maxComponentLen = 64
	maxCauseLen     = 64
	maxMessageLen   = 256
)

// Validate checks structural bounds and redaction rules before emission.
func Validate(e Event) error {
	if e.ID == "" || len(e.ID) > maxEventIDLen {
		return reject("id", "event id missing or too long")
	}
	for _, c := range e.ID {
		if c < 0x20 || c > 0x7e {
			return reject("id", "event id must be printable ASCII")
		}
	}
	if e.Channel < ChannelOperational || e.Channel > ChannelMetrics {
		return reject("channel", "invalid channel")
	}
	if e.Severity < SeverityDebug || e.Severity > SeverityCritical {
		return reject("severity", "invalid severity")
	}
	if e.Component == "" || len(e.Component) > maxComponentLen {
		return reject("component", "component missing or too long")
	}
	if len(e.CauseCategory) > maxCauseLen {
		return reject("cause", "cause category too long")
	}
	if e.Redaction < RedactionPublic || e.Redaction > RedactionForbidden {
		return reject("redaction", "invalid redaction class")
	}
	switch e.Redaction {
	case RedactionForbidden:
		if e.Message != "" {
			return reject("redaction", "forbidden class cannot carry message")
		}
	case RedactionSensitive:
		if len(e.Message) > 64 {
			return reject("redaction", "sensitive message must be opaque and short")
		}
	default:
		if len(e.Message) > maxMessageLen {
			return reject("message", "message exceeds bound")
		}
	}
	if containsForbidden(e.Message) {
		return reject("sanitize", "message contains forbidden material markers")
	}
	return nil
}

func containsForbidden(s string) bool {
	// Conservative markers; full sanitizer is policy-driven later.
	forbidden := []string{"-----BEGIN", "PRIVATE KEY", "password=", "Authorization:"}
	for _, f := range forbidden {
		if len(s) >= len(f) {
			for i := 0; i+len(f) <= len(s); i++ {
				if s[i:i+len(f)] == f {
					return true
				}
			}
		}
	}
	return false
}

// Sink receives validated events.
type Sink interface {
	Emit(Event) error
}

// MemSink stores events in memory with a bounded queue (INT-IC3-0002).
type MemSink struct {
	limits  resource.Limits
	mu      sync.Mutex
	events  []Event
	seq     atomic.Uint64
	dropped atomic.Uint64
}

// NewMemSink creates a bounded in-memory sink.
func NewMemSink(maxQueue uint64) *MemSink {
	return &MemSink{limits: resource.Limits{
		MaxBytes: 1 << 20, MaxCount: maxQueue, MaxNesting: 1,
		MaxQueueDepth: maxQueue, MaxConcurrent: 1, MaxRetries: 1,
	}}
}

// Emit validates, assigns a monotonic sequence, and enqueues or drops with metric.
func (s *MemSink) Emit(e Event) error {
	if err := Validate(e); err != nil {
		return err
	}
	e.Sequence = s.seq.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.limits.AdmitQueue(uint64(len(s.events) + 1)); err != nil {
		s.dropped.Add(1)
		return reject("backpressure", "operational queue full; event dropped")
	}
	s.events = append(s.events, e)
	return nil
}

// Dropped returns how many events were refused due to backpressure.
func (s *MemSink) Dropped() uint64 { return s.dropped.Load() }

// Snapshot returns a copy of buffered events.
func (s *MemSink) Snapshot() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, len(s.events))
	copy(out, s.events)
	return out
}

// EncodeCanonical encodes a validated event to a stable byte layout for tests.
func EncodeCanonical(e Event) ([]byte, error) {
	if err := Validate(e); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 128+len(e.ID)+len(e.Component)+len(e.CauseCategory)+len(e.Message))
	buf = append(buf, byte(e.Channel), byte(e.Severity), byte(e.Redaction))
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], e.Sequence)
	buf = append(buf, tmp[:]...)
	buf = append(buf, e.ArchivePseudonym[:]...)
	buf = append(buf, e.TransactionID[:]...)
	buf = appendU16String(buf, string(e.ID))
	buf = appendU16String(buf, e.Component)
	buf = appendU16String(buf, e.CauseCategory)
	buf = appendU16String(buf, e.Message)
	return buf, nil
}

func appendU16String(buf []byte, s string) []byte {
	if len(s) > 65535 {
		s = s[:65535]
	}
	var tmp [2]byte
	codec.PutU16LE(tmp[:], uint16(len(s)))
	buf = append(buf, tmp[:]...)
	return append(buf, s...)
}

// PathPseudonym derives an opaque path reference from a keyed commitment input.
func PathPseudonym(key, pathHint []byte) codec.Digest {
	return codec.SHA256(append(append([]byte{}, key...), pathHint...))
}

// FormatDropMetric returns a stable diagnostic string for dropped events.
func FormatDropMetric(n uint64) string {
	return fmt.Sprintf("observability.dropped_events=%d", n)
}
