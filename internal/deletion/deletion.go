// Package deletion implements destructive-operation safety gates for
// INT-IC1-0005 / docs/specifications/deletion.md (M1 MVP).
//
// Permanent deletion is disabled by default. Removals require an explicit
// destructive authorization and same-volume quarantine capacity. Crossing any
// threshold is a hard stop; unknown quantities are treated as over-threshold.
package deletion

import (
	"fmt"
	"math"

	"github.com/gpicchiarelli/integris/internal/codec"
)

// Thresholds are policy limits for a destructive plan. Zero Max* means the
// dimension is disabled (any positive observed value fails closed as unknown
// policy). Prefer explicit non-zero maxima.
type Thresholds struct {
	MaxObjectCount     uint64
	MaxPercentBPS      uint64 // basis points of archive object count (10000 = 100%)
	MaxLogicalBytes    uint64
	MaxPhysicalBytes   uint64
	MaxPathClassCount  uint64
	RequireCompleteSrc bool
}

// Observation is the measured destructive scope. Unknown* flags force hard stop.
type Observation struct {
	ObjectCount        uint64
	ArchiveObjectCount uint64
	LogicalBytes       uint64
	PhysicalBytes      uint64
	PathClassCount     uint64
	UnknownObjectCount bool
	UnknownLogical     bool
	UnknownPhysical    bool
	UnknownPathClass   bool
	SourceComplete     bool
	SameVolume         bool
	QuarantineCapacity uint64 // free bytes available for quarantine
	RootSentinelOK     bool
	VolumeAuthorized   bool
}

// Authorization binds digests required before any quarantine move.
type Authorization struct {
	PlanDigest          codec.Digest
	ConfigDigest        codec.Digest
	CapabilityDigest    codec.Digest
	DestructiveAuth     codec.Digest // separate destructive authorization
	AllowPermanentPurge bool         // default false; purge is out of default path
}

// Decision is the gate outcome. Allowed means quarantine may proceed; never
// means permanent delete.
type Decision struct {
	Allowed           bool
	PermanentDisabled bool
	Reason            string
	PercentBPS        uint64
}

// Error is a typed hard-stop refusal.
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

func stop(code, msg string) error { return &Error{Code: code, Message: msg} }

// Evaluate applies preconditions and thresholds. It never authorizes permanent
// deletion. Unknown measurements are over-threshold.
func Evaluate(th Thresholds, obs Observation, auth Authorization) (Decision, error) {
	d := Decision{PermanentDisabled: true}
	if auth.DestructiveAuth == (codec.Digest{}) {
		return d, stop("auth", "destructive authorization digest required")
	}
	if auth.PlanDigest == (codec.Digest{}) || auth.ConfigDigest == (codec.Digest{}) || auth.CapabilityDigest == (codec.Digest{}) {
		return d, stop("auth", "plan/config/capability digests required")
	}
	if !obs.RootSentinelOK {
		return d, stop("sentinel", "archive root sentinel invalid")
	}
	if !obs.VolumeAuthorized {
		return d, stop("volume", "root volume identity not authorized")
	}
	if !obs.SameVolume {
		return d, stop("volume", "quarantine must be same-volume")
	}
	if th.RequireCompleteSrc && !obs.SourceComplete {
		return d, stop("source", "incomplete source blocks destructive ops")
	}
	if obs.UnknownObjectCount || obs.UnknownLogical || obs.UnknownPhysical || obs.UnknownPathClass {
		return d, stop("unknown", "unknown size/count is over threshold")
	}

	if err := checkMax("object_count", obs.ObjectCount, th.MaxObjectCount); err != nil {
		return d, err
	}
	if err := checkMax("logical_bytes", obs.LogicalBytes, th.MaxLogicalBytes); err != nil {
		return d, err
	}
	if err := checkMax("physical_bytes", obs.PhysicalBytes, th.MaxPhysicalBytes); err != nil {
		return d, err
	}
	if err := checkMax("path_class", obs.PathClassCount, th.MaxPathClassCount); err != nil {
		return d, err
	}

	pct, err := percentBPS(obs.ObjectCount, obs.ArchiveObjectCount)
	if err != nil {
		return d, err
	}
	d.PercentBPS = pct
	if th.MaxPercentBPS == 0 && obs.ObjectCount > 0 {
		return d, stop("percent", "MaxPercentBPS not configured")
	}
	if pct > th.MaxPercentBPS {
		return d, stop("percent", fmt.Sprintf("destructive percent %d bps exceeds %d", pct, th.MaxPercentBPS))
	}

	// Quarantine capacity must cover physical bytes (conservative).
	need := obs.PhysicalBytes
	if need == 0 {
		need = obs.LogicalBytes
	}
	if need > obs.QuarantineCapacity {
		return d, stop("capacity", "insufficient quarantine capacity")
	}
	if auth.AllowPermanentPurge {
		// Explicit purge flag still does not enable in-line permanent delete.
		d.Reason = "quarantine-only; permanent purge requires separate transaction"
	}
	d.Allowed = true
	d.Reason = "quarantine permitted"
	return d, nil
}

func checkMax(name string, have, max uint64) error {
	if max == 0 {
		return stop(name, name+" maximum not configured")
	}
	if have > max {
		return stop(name, fmt.Sprintf("%s %d exceeds max %d", name, have, max))
	}
	return nil
}

// percentBPS returns floor(count*10000/total) with overflow-safe math.
// Unknown/zero archive total with positive count is over-threshold.
func percentBPS(count, total uint64) (uint64, error) {
	if count == 0 {
		return 0, nil
	}
	if total == 0 {
		return 0, stop("percent", "archive object count unknown or zero")
	}
	if count > total {
		return 0, stop("percent", "destructive count exceeds archive count")
	}
	// count * 10000 may overflow.
	if count > math.MaxUint64/10000 {
		return 0, stop("percent", "percent arithmetic overflow")
	}
	return (count * 10000) / total, nil
}

// QuarantinePlan is a single same-volume move intent (no FS mutation here).
type QuarantinePlan struct {
	SourceName     []byte
	QuarantineName []byte
	ObjectID       codec.Digest
	PlanDigest     codec.Digest
	AuthDigest     codec.Digest
}

// BuildQuarantinePlan constructs a collision-safe quarantine name intent.
// Callers must open descriptors and perform the move; this only validates names.
func BuildQuarantinePlan(sourceName, quarantineName []byte, objectID, plan, auth codec.Digest) (QuarantinePlan, error) {
	var zero QuarantinePlan
	if len(sourceName) == 0 || len(quarantineName) == 0 {
		return zero, stop("name", "source and quarantine names required")
	}
	if objectID == (codec.Digest{}) || plan == (codec.Digest{}) || auth == (codec.Digest{}) {
		return zero, stop("bind", "object/plan/auth digests required")
	}
	return QuarantinePlan{
		SourceName:     append([]byte{}, sourceName...),
		QuarantineName: append([]byte{}, quarantineName...),
		ObjectID:       objectID,
		PlanDigest:     plan,
		AuthDigest:     auth,
	}, nil
}
