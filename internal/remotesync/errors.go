package remotesync

import (
	"errors"
	"fmt"
)

// Kind classifies remotesync failures.
type Kind string

const (
	KindInvalidArgument Kind = "invalid_argument"
	KindHandshake       Kind = "handshake"
	KindTransport       Kind = "transport"
	KindProtocol        Kind = "protocol"
	KindAuth            Kind = "auth"
	KindApply           Kind = "apply"
	KindInternal        Kind = "internal"
)

// Error is a classified remotesync failure.
type Error struct {
	Kind    Kind
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	s := string(e.Kind)
	if e.Message != "" {
		s += ": " + e.Message
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

// IsKind reports whether err has kind k.
func IsKind(err error, k Kind) bool {
	var e *Error
	return errors.As(err, &e) && e.Kind == k
}

func wrap(k Kind, msg string, err error) error {
	return &Error{Kind: k, Message: msg, Err: err}
}

func fail(k Kind, msg string) error {
	return &Error{Kind: k, Message: msg}
}

func failf(k Kind, format string, args ...any) error {
	return fail(k, fmt.Sprintf(format, args...))
}
