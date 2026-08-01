package supervisor

import (
	"fmt"

	"github.com/gpicchiarelli/integris/internal/authority"
)

// ValidateSlots rejects conferred capabilities or descriptor slots that violate
// the authority inventory (MustNot / closed MayHold).
func ValidateSlots(role authority.ProcessRole, confer []authority.Capability, slots []DescriptorSlot) error {
	if err := authority.DeniedProbe(role, confer); err != nil {
		return fail("authority", err.Error())
	}
	for _, s := range slots {
		if err := slotAllowed(role, s.Kind); err != nil {
			return err
		}
	}
	return nil
}

// SlotKinds returns the kind strings for env/probe encoding.
func SlotKinds(slots []DescriptorSlot) []string {
	out := make([]string, len(slots))
	for i, s := range slots {
		out[i] = string(s.Kind)
	}
	return out
}

func slotAllowed(role authority.ProcessRole, kind DescriptorKind) error {
	switch kind {
	case DescIPCEndpoint, DescPolicyIdentity, DescJournalSegment,
		DescReadonlyJournal, DescEventSink:
		return nil
	case DescArchiveRoot, DescStagingRoot, DescQuarantineRoot:
		if archiveAuthorityOK(role) {
			return nil
		}
		return fail("slot", fmt.Sprintf("%s must not hold slot %s", role, kind))
	default:
		return fail("slot", "unknown descriptor kind "+string(kind))
	}
}

func archiveAuthorityOK(role authority.ProcessRole) bool {
	for _, cap := range []authority.Capability{
		authority.CapArchiveDescriptors,
		authority.CapArchiveRoots,
		authority.CapReadonlyArchiveRoot,
		authority.CapArchives,
	} {
		ok, err := authority.Allows(role, cap)
		if err == nil && ok {
			return true
		}
	}
	return false
}
