package plan

import (
	"bytes"
	"math/rand"
	"testing"
)

// Property: random permutations of identical classifications yield identical
// plan bytes and digests (VER-PLAN-001 surface).
func TestPropertyAcquisitionOrder(t *testing.T) {
	base := []Classification{
		{Path: pathOf("p", "1"), CapabilityID: CapTimes, Action: ActionCreate, Result: ResultLossless, RepresentationIDs: []uint16{5, 1, 4}},
		{Path: pathOf("p", "2"), CapabilityID: CapXattr, Action: ActionReplace, Result: ResultLossless},
		{Path: pathOf("q"), CapabilityID: CapACL, Action: ActionMetadataUpdate, Result: ResultWrapped, RepresentationIDs: []uint16{8, 2}},
		{Path: pathOf("r"), CapabilityID: CapSync, Action: ActionSkipIdentical, Result: ResultLossless},
		{Path: pathOf("s"), CapabilityID: CapIdentity, Action: ActionQuarantineDelete, Result: ResultLossless},
	}
	in := baseInput(base...)
	in.Policy.WrapAllowList = []uint16{2, 8}

	ref, _, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(42))
	for trial := 0; trial < 64; trial++ {
		perm := append([]Classification{}, base...)
		rng.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })
		// Also perturb RepresentationIDs order.
		for i := range perm {
			ids := append([]uint16{}, perm[i].RepresentationIDs...)
			rng.Shuffle(len(ids), func(a, b int) { ids[a], ids[b] = ids[b], ids[a] })
			perm[i].RepresentationIDs = ids
		}
		in2 := baseInput(perm...)
		in2.Policy.WrapAllowList = []uint16{2, 8}
		got, _, err := Build(in2)
		if err != nil {
			t.Fatalf("trial %d: %v", trial, err)
		}
		if !bytes.Equal(ref.Bytes, got.Bytes) || ref.Digest != got.Digest {
			t.Fatalf("trial %d: digest mismatch %x vs %x", trial, ref.Digest, got.Digest)
		}
	}
}

func TestPropertyParallelSchedules(t *testing.T) {
	in := baseInput(
		Classification{Path: pathOf("a"), CapabilityID: CapCase, Action: ActionCreate, Result: ResultLossless},
		Classification{Path: pathOf("b"), CapabilityID: CapUnicode, Action: ActionCreate, Result: ResultLossless},
	)
	const n = 8
	type result struct {
		p   Plan
		err error
	}
	ch := make(chan result, n)
	for i := 0; i < n; i++ {
		go func() {
			p, _, err := Build(in)
			ch <- result{p, err}
		}()
	}
	var ref Plan
	for i := 0; i < n; i++ {
		r := <-ch
		if r.err != nil {
			t.Fatal(r.err)
		}
		if i == 0 {
			ref = r.p
			continue
		}
		if !bytes.Equal(ref.Bytes, r.p.Bytes) {
			t.Fatal("parallel schedule divergence")
		}
	}
}
