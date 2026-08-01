package codec

import "fmt"

// Kind classifies codec failures for stable control flow across trust boundaries.
type Kind int

const (
	// KindIncomplete indicates truncated input that cannot form a full value.
	KindIncomplete Kind = iota + 1
	// KindNonCanonical indicates a syntactically complete but non-canonical encoding.
	KindNonCanonical
	// KindLimit indicates a declared length or count exceeds an explicit maximum.
	KindLimit
	// KindUnsupported indicates an unknown format version or record type.
	KindUnsupported
	// KindDigest indicates a payload digest or record commitment mismatch.
	KindDigest
)

// Error is a typed codec failure. Callers must not match on Error.Error() text.
type Error struct {
	Kind    Kind
	Field   string
	Message string
}

func (e *Error) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("codec: %s", e.Message)
	}
	return fmt.Sprintf("codec: %s: %s", e.Field, e.Message)
}

func incomplete(field, msg string) error {
	return &Error{Kind: KindIncomplete, Field: field, Message: msg}
}

func nonCanonical(field, msg string) error {
	return &Error{Kind: KindNonCanonical, Field: field, Message: msg}
}

func limit(field, msg string) error {
	return &Error{Kind: KindLimit, Field: field, Message: msg}
}

func unsupported(field, msg string) error {
	return &Error{Kind: KindUnsupported, Field: field, Message: msg}
}

func digestErr(field, msg string) error {
	return &Error{Kind: KindDigest, Field: field, Message: msg}
}

// AsKind reports whether err is a codec.Error of the given kind.
func AsKind(err error, kind Kind) bool {
	e, ok := err.(*Error)
	return ok && e.Kind == kind
}
