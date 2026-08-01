package recovery

import "fmt"

// Kind classifies recovery failures.
type Kind int

const (
	// KindFatal indicates interior journal corruption or contradictory durable effects.
	KindFatal Kind = iota + 1
	// KindQuarantine indicates recovery landed in quarantine without inventing success.
	KindQuarantine
	// KindIdentity indicates root/volume authority mismatch.
	KindIdentity
	// KindState indicates an unexpected state/record pair.
	KindState
	// KindIO indicates injected or real persistence I/O failure.
	KindIO
)

// Error is a typed recovery failure.
type Error struct {
	Kind    Kind
	Field   string
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		if e.Field == "" {
			return fmt.Sprintf("recovery: %s: %v", e.Message, e.Cause)
		}
		return fmt.Sprintf("recovery: %s: %s: %v", e.Field, e.Message, e.Cause)
	}
	if e.Field == "" {
		return fmt.Sprintf("recovery: %s", e.Message)
	}
	return fmt.Sprintf("recovery: %s: %s", e.Field, e.Message)
}

func (e *Error) Unwrap() error { return e.Cause }

func fatal(field, msg string, cause error) error {
	return &Error{Kind: KindFatal, Field: field, Message: msg, Cause: cause}
}

func identityErr(msg string) error {
	return &Error{Kind: KindIdentity, Field: "identity", Message: msg}
}

func stateErr(msg string) error {
	return &Error{Kind: KindState, Field: "state", Message: msg}
}

func ioErr(label CrashLabel, cause error) error {
	return &Error{Kind: KindIO, Field: string(label), Message: "persistence boundary failed", Cause: cause}
}

// AsKind reports whether err is a recovery.Error of the given kind.
func AsKind(err error, kind Kind) bool {
	e, ok := err.(*Error)
	return ok && e.Kind == kind
}
