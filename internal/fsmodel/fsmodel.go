// Package fsmodel implements filesystem capability comparison for INT-IC1-0006
// (no silent semantic loss) and docs/specifications/filesystem-model.md.
package fsmodel

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/plan"
)

// Fact is one discovered capability attribute on a volume.
type Fact struct {
	ID     plan.CapabilityID
	Result plan.ResultCode
	// DetailDigest binds probe evidence (may be zero for LOSSLESS defaults).
	DetailDigest codec.Digest
}

// Vector is an immutable per-session capability vector. Facts are stored sorted
// by CapabilityID; duplicates are rejected.
type Vector struct {
	VolumeIdentity codec.Digest
	Facts          []Fact
}

// Error is a typed capability/preflight failure.
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

// NewVector validates and sorts facts. Unknown capability IDs refuse closed.
func NewVector(volume codec.Digest, facts []Fact) (Vector, error) {
	var zero Vector
	if volume == (codec.Digest{}) {
		return zero, reject("volume", "volume identity digest required")
	}
	cp, err := normalizeFacts(facts)
	if err != nil {
		return zero, err
	}
	return Vector{VolumeIdentity: volume, Facts: cp}, nil
}

func normalizeFacts(facts []Fact) ([]Fact, error) {
	cp := append([]Fact{}, facts...)
	sort.Slice(cp, func(i, j int) bool { return cp[i].ID < cp[j].ID })
	seen := map[plan.CapabilityID]struct{}{}
	for _, f := range cp {
		if !plan.KnownCapability(f.ID) {
			return nil, reject("capability", fmt.Sprintf("unknown capability id %d", f.ID))
		}
		if !plan.ValidResult(f.Result) {
			return nil, reject("result", fmt.Sprintf("invalid result %d", f.Result))
		}
		if _, ok := seen[f.ID]; ok {
			return nil, reject("duplicate", fmt.Sprintf("duplicate capability %d", f.ID))
		}
		seen[f.ID] = struct{}{}
	}
	return cp, nil
}

// Digest returns SHA-256 of a canonical encoding of the vector.
func (v Vector) Digest() codec.Digest {
	var buf []byte
	buf = append(buf, v.VolumeIdentity[:]...)
	var tmp [4]byte
	codec.PutU16LE(tmp[:2], uint16(len(v.Facts)))
	buf = append(buf, tmp[:2]...)
	for _, f := range v.Facts {
		codec.PutU16LE(tmp[:2], uint16(f.ID))
		buf = append(buf, tmp[:2]...)
		codec.PutU16LE(tmp[:2], uint16(f.Result))
		buf = append(buf, tmp[:2]...)
		buf = append(buf, f.DetailDigest[:]...)
	}
	return codec.SHA256(buf)
}

// Issue is one blocking or informational comparison finding.
type Issue struct {
	Capability plan.CapabilityID
	Source     plan.ResultCode
	Target     plan.ResultCode
	Outcome    plan.ResultCode // effective planning result
	Blocks     bool
	Reason     string
}

// PreflightReport is the precise refusal/allow report before authorization.
type PreflightReport struct {
	Allowed bool
	Issues  []Issue
}

// Compare maps source feature results onto a target vector. Missing target facts
// become UNKNOWN. UNREPRESENTABLE/UNKNOWN/POLICY_FORBIDDEN block by default.
func Compare(source []Fact, target Vector) (PreflightReport, error) {
	src, err := normalizeFacts(source)
	if err != nil {
		return PreflightReport{}, err
	}
	idx := map[plan.CapabilityID]Fact{}
	for _, f := range target.Facts {
		idx[f.ID] = f
	}
	var issues []Issue
	blocked := false
	for _, s := range src {
		t, ok := idx[s.ID]
		outcome := s.Result
		reason := "source classification"
		if !ok {
			outcome = plan.ResultUnknown
			reason = "target capability missing"
		} else {
			outcome = merge(s.Result, t.Result)
			reason = "merged source/target"
		}
		block := plan.BlocksAuthorization(outcome)
		if block {
			blocked = true
		}
		tgtRes := plan.ResultUnknown
		if ok {
			tgtRes = t.Result
		}
		issues = append(issues, Issue{
			Capability: s.ID,
			Source:     s.Result,
			Target:     tgtRes,
			Outcome:    outcome,
			Blocks:     block,
			Reason:     reason,
		})
	}
	sort.Slice(issues, func(i, j int) bool { return issues[i].Capability < issues[j].Capability })
	return PreflightReport{Allowed: !blocked, Issues: issues}, nil
}

func merge(src, tgt plan.ResultCode) plan.ResultCode {
	// Prefer the more restrictive outcome.
	rank := func(r plan.ResultCode) int {
		switch r {
		case plan.ResultLossless:
			return 1
		case plan.ResultWrapped:
			return 2
		case plan.ResultPolicyForbidden:
			return 3
		case plan.ResultUnrepresentable:
			return 4
		default:
			return 5 // UNKNOWN
		}
	}
	if rank(src) >= rank(tgt) {
		return src
	}
	return tgt
}

// RequireNoSilentLoss fails if any issue would authorize with lossy semantics.
func RequireNoSilentLoss(rep PreflightReport) error {
	if rep.Allowed {
		return nil
	}
	var b bytes.Buffer
	b.WriteString("preflight blocked:")
	for _, is := range rep.Issues {
		if !is.Blocks {
			continue
		}
		fmt.Fprintf(&b, " cap=%d outcome=%d (%s);", is.Capability, is.Outcome, is.Reason)
	}
	return reject("preflight", b.String())
}
