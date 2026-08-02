package localsync

import (
	"errors"
)

// Kind classifies localsync failures for stable control flow (not string match).
type Kind string

const (
	KindInvalidArgument Kind = "invalid_argument"
	KindPathUnsafe      Kind = "path_unsafe"
	KindUnsupported     Kind = "unsupported"
	KindPermission      Kind = "permission"
	KindRead            Kind = "read"
	KindWrite           Kind = "write"
	KindNoSpace         Kind = "no_space"
	KindVerify          Kind = "verify"
	KindConflict        Kind = "conflict"
	KindInternal        Kind = "internal"
)

// Error is a classified localsync failure that wraps an optional cause.
type Error struct {
	Kind    Kind
	Op      string
	Path    string // logical relative path when applicable
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	base := string(e.Kind)
	if e.Op != "" {
		base += ": " + e.Op
	}
	if e.Path != "" {
		base += ": " + e.Path
	}
	if e.Message != "" {
		base += ": " + e.Message
	}
	if e.Err != nil {
		base += ": " + e.Err.Error()
	}
	return base
}

func (e *Error) Unwrap() error { return e.Err }

// IsKind reports whether err (or any wrapped Error) has kind k.
func IsKind(err error, k Kind) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind == k
	}
	return false
}

func classify(kind Kind, op, rel, msg string, err error) error {
	return &Error{Kind: kind, Op: op, Path: rel, Message: msg, Err: err}
}

func invalidArg(op, msg string) error {
	return classify(KindInvalidArgument, op, "", msg, nil)
}

func pathUnsafe(op, msg string) error {
	return classify(KindPathUnsafe, op, "", msg, nil)
}

func unsupported(op, rel, msg string) error {
	return classify(KindUnsupported, op, rel, msg, nil)
}

func wrap(kind Kind, op, rel string, err error) error {
	if err == nil {
		return nil
	}
	var existing *Error
	if errors.As(err, &existing) {
		return err
	}
	return classify(kind, op, rel, "", err)
}
