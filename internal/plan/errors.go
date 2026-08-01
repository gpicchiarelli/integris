package plan

import "fmt"

// Kind classifies planner failures for stable control flow.
type Kind int

const (
	// KindRefuse indicates blocking classification or policy refusal.
	KindRefuse Kind = iota + 1
	// KindLimit indicates a resource limit would be exceeded.
	KindLimit
	// KindNonCanonical indicates invalid or non-canonical input.
	KindNonCanonical
	// KindUnsupported indicates an unknown action or capability code.
	KindUnsupported
)

// Error is a typed planner failure. Callers must not match on Error() text.
type Error struct {
	Kind    Kind
	Field   string
	Message string
}

func (e *Error) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("plan: %s", e.Message)
	}
	return fmt.Sprintf("plan: %s: %s", e.Field, e.Message)
}

func refuse(field, msg string) error {
	return &Error{Kind: KindRefuse, Field: field, Message: msg}
}

func limit(field, msg string) error {
	return &Error{Kind: KindLimit, Field: field, Message: msg}
}

func nonCanonical(field, msg string) error {
	return &Error{Kind: KindNonCanonical, Field: field, Message: msg}
}

func unsupported(field, msg string) error {
	return &Error{Kind: KindUnsupported, Field: field, Message: msg}
}

// AsKind reports whether err is a plan.Error of the given kind.
func AsKind(err error, kind Kind) bool {
	e, ok := err.(*Error)
	return ok && e.Kind == kind
}
