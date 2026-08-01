package plan

import (
	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/path"
)

// Build constructs a canonical plan from CanonicalInput.
// On blocking classifications it returns a populated Preflight, a zero Plan,
// and a KindRefuse error — never an authorize-able plan artifact.
// Acquisition order of Classifications does not affect output bytes or digests.
func Build(in CanonicalInput) (Plan, Preflight, error) {
	var zero Plan
	limits := in.Limits.Resolve()

	if uint64(len(in.Classifications)) > uint64(limits.MaxCapabilityComparisons) {
		return zero, Preflight{}, limit("classifications", "exceeds MaxCapabilityComparisons")
	}
	if uint64(len(in.Classifications)) > uint64(limits.MaxEntries) {
		return zero, Preflight{}, limit("entries", "exceeds MaxEntries")
	}

	sorted := sortClassifications(in.Classifications)
	wrapAllow := sortUint16(in.Policy.WrapAllowList)
	repAllow := sortUint16(in.Policy.RepresentationAllowList)

	entries := make([]Entry, 0, len(sorted))
	blocking := make([]BlockingItem, 0)

	for i := range sorted {
		c := sorted[i]
		if err := validateClassification(c); err != nil {
			return zero, Preflight{}, err
		}
		if i > 0 && compareClassifications(sorted[i-1], c) == 0 {
			return zero, Preflight{}, nonCanonical("classifications", "duplicate path/capability/action")
		}

		resolved, block, err := resolveClassification(c, wrapAllow, repAllow)
		if err != nil {
			return zero, Preflight{}, err
		}
		if block {
			blocking = append(blocking, BlockingItem{
				Path:         clonePath(c.Path),
				CapabilityID: c.CapabilityID,
				Result:       resolved.Result,
			})
			continue
		}
		entries = append(entries, resolved)
	}

	pf := Preflight{Blocking: blocking}
	if len(blocking) > 0 {
		return zero, pf, refuse("preflight", "blocking classifications refuse authorization")
	}

	entries = sortEntries(entries)
	destrDigest := codec.SHA256(encodeDestructiveSubset(entries))

	bytes, digest, err := encodePlan(
		in.ManifestDigest,
		in.CapabilityVectorDigest,
		in.ConfigurationDigest,
		entries,
		destrDigest,
	)
	if err != nil {
		return zero, pf, err
	}
	if uint64(len(bytes)) > uint64(limits.MaxPlanBytes) {
		return zero, pf, limit("plan_bytes", "exceeds MaxPlanBytes")
	}
	return Plan{Bytes: bytes, Digest: digest}, pf, nil
}

func validateClassification(c Classification) error {
	if err := path.ValidateComponentsDefault(c.Path); err != nil {
		return nonCanonical("path", err.Error())
	}
	if !ValidAction(c.Action) {
		return unsupported("action_code", "unknown or zero action")
	}
	if !ValidResult(c.Result) {
		return unsupported("result_code", "unknown or zero result")
	}
	if c.CapabilityID == 0 {
		return unsupported("capability_id", "zero capability id")
	}
	if !KnownCapability(c.CapabilityID) {
		// Unknown registry IDs refuse closed via preflight UNKNOWN, not silent pass.
		return nil
	}
	if uint64(len(c.RepresentationIDs)) > uint64(MaxDefaultCapabilityComparisons) {
		return limit("representation_ids", "exceeds MaxCapabilityComparisons")
	}
	return nil
}

func resolveClassification(c Classification, wrapAllow, repAllow []uint16) (Entry, bool, error) {
	e := Entry{
		Path:         clonePath(c.Path),
		CapabilityID: c.CapabilityID,
		Action:       c.Action,
		Result:       c.Result,
		AuxDigest:    c.AuxDigest,
	}

	if !KnownCapability(c.CapabilityID) {
		e.Result = ResultUnknown
		return e, true, nil
	}
	if BlocksAuthorization(c.Result) {
		return e, true, nil
	}

	switch c.Result {
	case ResultLossless:
		id, ok := pickRepresentation(c.RepresentationIDs, repAllow, true)
		if !ok && len(c.RepresentationIDs) > 0 {
			// Enumerated candidates existed but none were allowed.
			e.Result = ResultPolicyForbidden
			return e, true, nil
		}
		e.RepresentationID = id
		return e, false, nil

	case ResultWrapped:
		id, ok := pickRepresentation(c.RepresentationIDs, wrapAllow, false)
		if !ok {
			e.Result = ResultPolicyForbidden
			return e, true, nil
		}
		e.RepresentationID = id
		return e, false, nil

	default:
		return e, true, unsupported("result_code", "unhandled result")
	}
}

// pickRepresentation selects the lexicographically least eligible ID.
// If allow is empty and emptyAllowAll is true, any positive candidate is eligible
// (LOSSLESS with no policy restriction). For WRAPPED, empty allow-list admits nothing.
func pickRepresentation(candidates, allow []uint16, emptyAllowAll bool) (uint16, bool) {
	sorted := sortUint16(candidates)
	var best uint16
	found := false
	for _, id := range sorted {
		if id == 0 {
			continue
		}
		eligible := emptyAllowAll && len(allow) == 0
		if len(allow) > 0 {
			eligible = allowContains(allow, id)
		}
		if !eligible {
			continue
		}
		if !found || id < best {
			best = id
			found = true
		}
	}
	if !found && len(sorted) == 0 && emptyAllowAll {
		// Sole declared mapping with no representation id: unused (0).
		return 0, true
	}
	return best, found
}
