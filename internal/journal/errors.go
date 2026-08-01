package journal

import (
	"fmt"

	"github.com/gpicchiarelli/integris/internal/codec"
)

// Kind classifies journal stream failures.
type Kind int

const (
	// KindTornTail indicates an incomplete final record; prior prefix is valid.
	KindTornTail Kind = iota + 1
	// KindFatal indicates interior corruption, gap, fork, or limit violation.
	KindFatal
	// KindClosed indicates use after close or disabled destructive action.
	KindClosed
	// KindState indicates an invalid writer/reader state transition.
	KindState
)

// Error is a typed journal failure.
type Error struct {
	Kind    Kind
	Offset  int64
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("journal: %s (offset %d): %v", e.Message, e.Offset, e.Cause)
	}
	return fmt.Sprintf("journal: %s (offset %d)", e.Message, e.Offset)
}

func (e *Error) Unwrap() error { return e.Cause }

func torn(offset int64, cause error) *Error {
	return &Error{Kind: KindTornTail, Offset: offset, Message: "torn tail", Cause: cause}
}

func fatal(offset int64, msg string, cause error) *Error {
	return &Error{Kind: KindFatal, Offset: offset, Message: msg, Cause: cause}
}

// IsTorn reports whether err is a torn-tail condition.
func IsTorn(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Kind == KindTornTail
}

// IsFatal reports whether err is a fatal stream condition.
func IsFatal(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Kind == KindFatal
}

func classifyDecode(offset int64, err error) *Error {
	if err == nil {
		return nil
	}
	if codec.AsKind(err, codec.KindIncomplete) {
		return torn(offset, err)
	}
	return fatal(offset, "interior corruption or non-canonical record", err)
}
