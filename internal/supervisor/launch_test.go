package supervisor_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/supervisor"
)

func TestMaterializeLaunchSealed(t *testing.T) {
	p, err := supervisor.MinimalRuntimePlan()
	if err != nil {
		t.Fatal(err)
	}
	root := bytes.Repeat([]byte{0x5a}, 32)
	var nonce [16]byte
	nonce[3] = 9
	set, err := supervisor.MaterializeLaunch(p, root, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Children) != 9 {
		t.Fatalf("children=%d", len(set.Children))
	}
	if err := set.VerifyAll(root); err != nil {
		t.Fatal(err)
	}
	for _, c := range set.Children {
		if c.Role == authority.RoleNet {
			for _, s := range c.Slots {
				if s.Kind == supervisor.DescArchiveRoot {
					t.Fatal("net must not hold archive_root")
				}
			}
		}
	}
	var apply *supervisor.ChildLaunch
	for i := range set.Children {
		if set.Children[i].Role == authority.RoleApply {
			apply = &set.Children[i]
			break
		}
	}
	if apply == nil {
		t.Fatal("missing apply")
	}
	kinds := map[supervisor.DescriptorKind]bool{}
	for _, s := range apply.Slots {
		kinds[s.Kind] = true
	}
	for _, want := range []supervisor.DescriptorKind{
		supervisor.DescArchiveRoot, supervisor.DescStagingRoot, supervisor.DescQuarantineRoot,
	} {
		if !kinds[want] {
			t.Fatalf("apply missing slot %s", want)
		}
	}
	apply.Seal[0] ^= 0xff
	if err := apply.Verify(root, set.PlanDigest); err == nil {
		t.Fatal("expected seal failure")
	}
}

func TestValidateSlotsRejectsNetArchive(t *testing.T) {
	err := supervisor.ValidateSlots(authority.RoleNet,
		[]authority.Capability{authority.CapNetworkSockets},
		[]supervisor.DescriptorSlot{{Kind: supervisor.DescArchiveRoot, Label: "bad"}},
	)
	if err == nil {
		t.Fatal("expected rejection")
	}
}

func TestValidateSlotsRejectsParserNetworkCap(t *testing.T) {
	err := supervisor.ValidateSlots(authority.RoleParser,
		[]authority.Capability{authority.CapBoundedMessageIPC, authority.CapNetworkSockets},
		nil,
	)
	if err == nil {
		t.Fatal("expected rejection")
	}
}

func TestValidateSlotsRejectsPlanArchiveAndJournalNet(t *testing.T) {
	if err := supervisor.ValidateSlots(authority.RolePlan,
		[]authority.Capability{authority.CapPlanOutput},
		[]supervisor.DescriptorSlot{{Kind: supervisor.DescArchiveRoot, Label: "bad"}},
	); err == nil {
		t.Fatal("expected plan archive rejection")
	}
	if err := supervisor.ValidateSlots(authority.RoleJournal,
		[]authority.Capability{authority.CapJournalDescriptor, authority.CapNetwork},
		nil,
	); err == nil {
		t.Fatal("expected journal network rejection")
	}
	if err := supervisor.ValidateSlots(authority.RoleAudit,
		[]authority.Capability{authority.CapReadonlyJournal, authority.CapOperationDecisions},
		nil,
	); err == nil {
		t.Fatal("expected audit decision rejection")
	}
}
