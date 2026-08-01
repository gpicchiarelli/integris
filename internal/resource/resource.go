// Package resource implements pre-allocation admission checks for INT-IC3-0002.
// External lengths, counts, nesting depths, and queue admissions are refused
// before allocation when they would exceed explicit finite limits.
package resource

import (
	"fmt"
	"math"
)

// Limits are immutable session quotas. Zero means the named dimension is unused
// (callers must not pass zero for a dimension they intend to enforce).
type Limits struct {
	MaxBytes      uint64
	MaxCount      uint64
	MaxNesting    uint64
	MaxQueueDepth uint64
	MaxConcurrent uint64
	MaxRetries    uint64
}

// DefaultLimits returns conservative M1 defaults aligned with journal/path budgets.
func DefaultLimits() Limits {
	return Limits{
		MaxBytes:      16 << 20,
		MaxCount:      1 << 20,
		MaxNesting:    1024,
		MaxQueueDepth: 1024,
		MaxConcurrent: 256,
		MaxRetries:    64,
	}
}

// Kind classifies a refusal.
type Kind string

const (
	KindBytes      Kind = "bytes"
	KindCount      Kind = "count"
	KindNesting    Kind = "nesting"
	KindQueue      Kind = "queue"
	KindConcurrent Kind = "concurrent"
	KindRetries    Kind = "retries"
	KindOverflow   Kind = "overflow"
)

// Error is a typed admission refusal. It never panics.
type Error struct {
	Kind    Kind
	Limit   uint64
	Request uint64
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return fmt.Sprintf("%s: %s (limit=%d request=%d)", e.Kind, e.Message, e.Limit, e.Request)
	}
	return fmt.Sprintf("%s: limit=%d request=%d", e.Kind, e.Limit, e.Request)
}

func refuse(kind Kind, limit, request uint64, msg string) error {
	return &Error{Kind: kind, Limit: limit, Request: request, Message: msg}
}

// AdmitBytes refuses if n is zero-policy-disabled incorrectly or exceeds MaxBytes.
func (l Limits) AdmitBytes(n uint64) error {
	if l.MaxBytes == 0 {
		return refuse(KindBytes, 0, n, "MaxBytes not configured")
	}
	if n > l.MaxBytes {
		return refuse(KindBytes, l.MaxBytes, n, "byte budget exceeded")
	}
	return nil
}

// AdmitCount refuses if n exceeds MaxCount.
func (l Limits) AdmitCount(n uint64) error {
	if l.MaxCount == 0 {
		return refuse(KindCount, 0, n, "MaxCount not configured")
	}
	if n > l.MaxCount {
		return refuse(KindCount, l.MaxCount, n, "count budget exceeded")
	}
	return nil
}

// AdmitNesting refuses if depth exceeds MaxNesting.
func (l Limits) AdmitNesting(depth uint64) error {
	if l.MaxNesting == 0 {
		return refuse(KindNesting, 0, depth, "MaxNesting not configured")
	}
	if depth > l.MaxNesting {
		return refuse(KindNesting, l.MaxNesting, depth, "nesting budget exceeded")
	}
	return nil
}

// AdmitQueue refuses if depth exceeds MaxQueueDepth.
func (l Limits) AdmitQueue(depth uint64) error {
	if l.MaxQueueDepth == 0 {
		return refuse(KindQueue, 0, depth, "MaxQueueDepth not configured")
	}
	if depth > l.MaxQueueDepth {
		return refuse(KindQueue, l.MaxQueueDepth, depth, "queue budget exceeded")
	}
	return nil
}

// AdmitConcurrent refuses if n exceeds MaxConcurrent.
func (l Limits) AdmitConcurrent(n uint64) error {
	if l.MaxConcurrent == 0 {
		return refuse(KindConcurrent, 0, n, "MaxConcurrent not configured")
	}
	if n > l.MaxConcurrent {
		return refuse(KindConcurrent, l.MaxConcurrent, n, "concurrency budget exceeded")
	}
	return nil
}

// AdmitRetries refuses if n exceeds MaxRetries.
func (l Limits) AdmitRetries(n uint64) error {
	if l.MaxRetries == 0 {
		return refuse(KindRetries, 0, n, "MaxRetries not configured")
	}
	if n > l.MaxRetries {
		return refuse(KindRetries, l.MaxRetries, n, "retry budget exceeded")
	}
	return nil
}

// AddUint64 returns a+b or an overflow refusal (before allocation of a+b sized work).
func AddUint64(a, b uint64) (uint64, error) {
	if a > math.MaxUint64-b {
		return 0, refuse(KindOverflow, math.MaxUint64, a, "unsigned addition overflow")
	}
	return a + b, nil
}

// MulUint64 returns a*b or an overflow refusal.
func MulUint64(a, b uint64) (uint64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	if a > math.MaxUint64/b {
		return 0, refuse(KindOverflow, math.MaxUint64, a, "unsigned multiplication overflow")
	}
	return a * b, nil
}

// AdmitSliceCap refuses allocating a slice of n elements of elemSize bytes.
func (l Limits) AdmitSliceCap(n, elemSize uint64) error {
	if err := l.AdmitCount(n); err != nil {
		return err
	}
	total, err := MulUint64(n, elemSize)
	if err != nil {
		return err
	}
	return l.AdmitBytes(total)
}

// Budget tracks cumulative admitted work within a Limits envelope.
type Budget struct {
	Limits Limits
	Bytes  uint64
	Count  uint64
}

// ConsumeBytes admits and records n additional bytes.
func (b *Budget) ConsumeBytes(n uint64) error {
	sum, err := AddUint64(b.Bytes, n)
	if err != nil {
		return err
	}
	if err := b.Limits.AdmitBytes(sum); err != nil {
		return err
	}
	b.Bytes = sum
	return nil
}

// ConsumeCount admits and records n additional items.
func (b *Budget) ConsumeCount(n uint64) error {
	sum, err := AddUint64(b.Count, n)
	if err != nil {
		return err
	}
	if err := b.Limits.AdmitCount(sum); err != nil {
		return err
	}
	b.Count = sum
	return nil
}
