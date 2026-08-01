package plan

import "github.com/gpicchiarelli/integris/internal/codec"

// Plan document constants (IP-S-0002 v1).
const (
	PlanVersion uint16 = 1

	MaxDefaultEntries               = 1 << 20
	MaxDefaultPlanBytes             = 16 << 20
	MaxDefaultCapabilityComparisons = 1 << 24
)

// PlanMagic is the 8-byte plan prefix INTPLAN1.
var PlanMagic = [8]byte{'I', 'N', 'T', 'P', 'L', 'A', 'N', '1'}

// ActionCode is a v1 plan action allow-list member.
type ActionCode uint16

const (
	ActionCreate           ActionCode = 1
	ActionReplace          ActionCode = 2
	ActionMetadataUpdate   ActionCode = 3
	ActionQuarantineDelete ActionCode = 4
	ActionSkipIdentical    ActionCode = 5
)

// ValidAction reports whether a is in the v1 allow-list.
func ValidAction(a ActionCode) bool {
	return a >= ActionCreate && a <= ActionSkipIdentical
}

// IsDestructive reports whether a contributes to the destructive summary.
func IsDestructive(a ActionCode) bool {
	return a == ActionQuarantineDelete
}

// ResultCode is a capability classification result.
type ResultCode uint16

const (
	ResultLossless        ResultCode = 1
	ResultWrapped         ResultCode = 2
	ResultUnrepresentable ResultCode = 3
	ResultPolicyForbidden ResultCode = 4
	ResultUnknown         ResultCode = 5
)

// ValidResult reports whether r is a known result code.
func ValidResult(r ResultCode) bool {
	return r >= ResultLossless && r <= ResultUnknown
}

// BlocksAuthorization reports whether r refuses plan authorization by default.
func BlocksAuthorization(r ResultCode) bool {
	switch r {
	case ResultUnrepresentable, ResultPolicyForbidden, ResultUnknown:
		return true
	default:
		return false
	}
}

// CapabilityID is a provisional M1 capability registry identifier.
// Unknown IDs refuse closed (IP-S-0002 dissent item 1).
type CapabilityID uint16

const (
	CapIdentity        CapabilityID = 1
	CapCase            CapabilityID = 2
	CapUnicode         CapabilityID = 3
	CapNameEncoding    CapabilityID = 4
	CapSymlink         CapabilityID = 5
	CapHardlink        CapabilityID = 6
	CapACL             CapabilityID = 7
	CapXattr           CapabilityID = 8
	CapBSDFlags        CapabilityID = 9
	CapSparse          CapabilityID = 10
	CapResourceFork    CapabilityID = 11
	CapTimes           CapabilityID = 12
	CapIdentityMap     CapabilityID = 13
	CapMount           CapabilityID = 14
	CapSpecialObject   CapabilityID = 15
	CapRenameAtomicity CapabilityID = 16
	CapSync            CapabilityID = 17
	CapCOW             CapabilityID = 18
	CapSnapshot        CapabilityID = 19
	CapDurability      CapabilityID = 20
)

// KnownCapability reports whether id is in the provisional M1 registry.
func KnownCapability(id CapabilityID) bool {
	return id >= CapIdentity && id <= CapDurability
}

// Classification is one (path, capability) decision already captured by the caller.
// RepresentationIDs enumerates LOSSLESS/WRAPPED candidates; the planner selects
// the lexicographically least ID allowed by policy (stable tie-break).
type Classification struct {
	Path              [][]byte
	CapabilityID      CapabilityID
	Action            ActionCode
	Result            ResultCode
	RepresentationIDs []uint16
	AuxDigest         codec.Digest
}

// Policy constrains WRAPPED formats and optional LOSSLESS representation allow-lists.
type Policy struct {
	// WrapAllowList is the set of accepted wrap format IDs. Empty means no wrap
	// format is authorized.
	WrapAllowList []uint16
	// RepresentationAllowList, when non-empty, restricts LOSSLESS representation
	// IDs. Empty means any positive representation ID from the classification
	// enumeration is eligible for the min-ID tie-break; ID 0 means unused.
	RepresentationAllowList []uint16
}

// Limits bounds planner work before allocation (INT-IC3-0002).
type Limits struct {
	MaxEntries               uint32
	MaxPlanBytes             uint32
	MaxCapabilityComparisons uint32
}

// Resolve returns limits with zeros replaced by M1 defaults.
func (l Limits) Resolve() Limits {
	out := l
	if out.MaxEntries == 0 {
		out.MaxEntries = MaxDefaultEntries
	}
	if out.MaxPlanBytes == 0 {
		out.MaxPlanBytes = MaxDefaultPlanBytes
	}
	if out.MaxCapabilityComparisons == 0 {
		out.MaxCapabilityComparisons = MaxDefaultCapabilityComparisons
	}
	return out
}

// CanonicalInput is the planner's sole input surface. Callers must supply
// already-captured classifications; the planner does not probe the filesystem.
type CanonicalInput struct {
	ManifestDigest         codec.Digest
	CapabilityVectorDigest codec.Digest
	ConfigurationDigest    codec.Digest
	Classifications        []Classification
	Policy                 Policy
	Limits                 Limits
}

// BlockingItem is one preflight refusal, ordered canonically.
type BlockingItem struct {
	Path         [][]byte
	CapabilityID CapabilityID
	Result       ResultCode
}

// Preflight enumerates authorization blockers in canonical order.
type Preflight struct {
	Blocking []BlockingItem
}

// Authorized reports whether the preflight permits an authorize-able plan.
func (p Preflight) Authorized() bool {
	return len(p.Blocking) == 0
}

// Plan is a canonical binary plan document and its body digest.
type Plan struct {
	Bytes  []byte
	Digest codec.Digest
}

// Entry is one encoded plan row after classification resolution.
type Entry struct {
	Path             [][]byte
	CapabilityID     CapabilityID
	Action           ActionCode
	Result           ResultCode
	RepresentationID uint16
	AuxDigest        codec.Digest
}
