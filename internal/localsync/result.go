package localsync

import (
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/gpicchiarelli/integris/internal/codec"
)

// Outcome is the overall sync status.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailed  Outcome = "failed"
)

// Result is the structured, verifiable sync report.
type Result struct {
	Outcome          Outcome       `json:"outcome"`
	Source           string        `json:"source"`
	Destination      string        `json:"destination"`
	PlannedOps       int           `json:"planned_ops"`
	CompletedOps     int           `json:"completed_ops"`
	SkippedOps       int           `json:"skipped_ops"`
	BytesTransferred int64         `json:"bytes_transferred"`
	Duration         time.Duration `json:"duration_ns"`
	Plan             Plan          `json:"plan"`
	Error            string        `json:"error,omitempty"`
	ErrorKind        Kind          `json:"error_kind,omitempty"`
	DurabilityNote   string        `json:"durability_mechanism"`
	JournalPath      string        `json:"journal_path,omitempty"`
	Resumed          bool          `json:"resumed,omitempty"`
	PlanDigest       codec.Digest  `json:"-"`
	PlanDigestHex    string        `json:"plan_digest_sha256,omitempty"`
	TransactionID    []byte        `json:"-"`
	TransactionHex   string        `json:"transaction_id,omitempty"`
}

// JSON emits a diagnostic JSON document.
func (r Result) JSON() ([]byte, error) {
	type alias struct {
		Outcome          Outcome `json:"outcome"`
		Source           string  `json:"source"`
		Destination      string  `json:"destination"`
		PlannedOps       int     `json:"planned_ops"`
		CompletedOps     int     `json:"completed_ops"`
		SkippedOps       int     `json:"skipped_ops"`
		BytesTransferred int64   `json:"bytes_transferred"`
		DurationMS       int64   `json:"duration_ms"`
		Plan             Plan    `json:"plan"`
		Error            string  `json:"error,omitempty"`
		ErrorKind        Kind    `json:"error_kind,omitempty"`
		DurabilityNote   string  `json:"durability_mechanism"`
		JournalPath      string  `json:"journal_path,omitempty"`
		Resumed          bool    `json:"resumed,omitempty"`
		PlanDigestHex    string  `json:"plan_digest_sha256,omitempty"`
		TransactionHex   string  `json:"transaction_id,omitempty"`
	}
	pd := r.PlanDigestHex
	if pd == "" && r.PlanDigest != (codec.Digest{}) {
		pd = hex.EncodeToString(r.PlanDigest[:])
	}
	tx := r.TransactionHex
	if tx == "" && len(r.TransactionID) > 0 {
		tx = hex.EncodeToString(r.TransactionID)
	}
	a := alias{
		Outcome:          r.Outcome,
		Source:           r.Source,
		Destination:      r.Destination,
		PlannedOps:       r.PlannedOps,
		CompletedOps:     r.CompletedOps,
		SkippedOps:       r.SkippedOps,
		BytesTransferred: r.BytesTransferred,
		DurationMS:       r.Duration.Milliseconds(),
		Plan:             r.Plan,
		Error:            r.Error,
		ErrorKind:        r.ErrorKind,
		DurabilityNote:   r.DurabilityNote,
		JournalPath:      r.JournalPath,
		Resumed:          r.Resumed,
		PlanDigestHex:    pd,
		TransactionHex:   tx,
	}
	return json.MarshalIndent(a, "", "  ")
}
