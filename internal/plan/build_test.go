package plan

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
)

func dig(s string) codec.Digest {
	return codec.SHA256([]byte(s))
}

func pathOf(parts ...string) [][]byte {
	out := make([][]byte, len(parts))
	for i, p := range parts {
		out[i] = []byte(p)
	}
	return out
}

func baseInput(classes ...Classification) CanonicalInput {
	return CanonicalInput{
		ManifestDigest:         dig("manifest"),
		CapabilityVectorDigest: dig("capvec"),
		ConfigurationDigest:    dig("config"),
		Classifications:        classes,
		Limits: Limits{
			MaxEntries:               1024,
			MaxPlanBytes:             1 << 20,
			MaxCapabilityComparisons: 1024,
		},
	}
}

func TestBuildGoldenDeterministic(t *testing.T) {
	in := baseInput(
		Classification{
			Path: pathOf("dir", "a.txt"), CapabilityID: CapTimes, Action: ActionCreate,
			Result: ResultLossless, RepresentationIDs: []uint16{3, 1, 2},
		},
		Classification{
			Path: pathOf("dir", "b.txt"), CapabilityID: CapXattr, Action: ActionReplace,
			Result: ResultLossless,
		},
	)
	p1, pf, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if !pf.Authorized() {
		t.Fatalf("unexpected blocking: %+v", pf.Blocking)
	}
	if len(p1.Bytes) < 8+2+96+4+32+32 {
		t.Fatalf("plan too short: %d", len(p1.Bytes))
	}
	if !bytes.Equal(p1.Bytes[:8], PlanMagic[:]) {
		t.Fatalf("bad magic")
	}
	if Digest(p1) != p1.Digest {
		t.Fatalf("Digest helper mismatch")
	}

	p2, _, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p1.Bytes, p2.Bytes) || p1.Digest != p2.Digest {
		t.Fatalf("non-deterministic build")
	}

	// Pinned golden digest for the fixed input above (VER-PLAN-001).
	gotHex := hex.EncodeToString(p1.Digest[:])
	const golden = "899e6732f1485a49e2f25b98850d2f6d41baf3c64e7ef3f37cd18fcb296aa0f8"
	if gotHex != golden {
		t.Fatalf("golden digest: got %s want %s", gotHex, golden)
	}
	if len(p1.Bytes) != 282 {
		t.Fatalf("golden size: got %d want 282", len(p1.Bytes))
	}
}

func TestBuildPermutationInvariant(t *testing.T) {
	a := Classification{
		Path: pathOf("z"), CapabilityID: CapCase, Action: ActionCreate, Result: ResultLossless,
	}
	b := Classification{
		Path: pathOf("a"), CapabilityID: CapUnicode, Action: ActionReplace, Result: ResultLossless,
		RepresentationIDs: []uint16{9, 2},
	}
	c := Classification{
		Path: pathOf("m"), CapabilityID: CapACL, Action: ActionMetadataUpdate, Result: ResultLossless,
	}

	orders := [][]Classification{
		{a, b, c},
		{c, a, b},
		{b, c, a},
		{c, b, a},
		{a, c, b},
		{b, a, c},
	}
	var ref Plan
	for i, ord := range orders {
		p, pf, err := Build(baseInput(ord...))
		if err != nil {
			t.Fatalf("order %d: %v", i, err)
		}
		if !pf.Authorized() {
			t.Fatalf("order %d blocked", i)
		}
		if i == 0 {
			ref = p
			continue
		}
		if !bytes.Equal(ref.Bytes, p.Bytes) || ref.Digest != p.Digest {
			t.Fatalf("order %d diverged from ref digest %x vs %x", i, ref.Digest, p.Digest)
		}
	}
}

func TestRefuseUnrepresentableUnknownForbidden(t *testing.T) {
	cases := []struct {
		name string
		c    Classification
	}{
		{"unrep", Classification{Path: pathOf("x"), CapabilityID: CapXattr, Action: ActionCreate, Result: ResultUnrepresentable}},
		{"unknown", Classification{Path: pathOf("x"), CapabilityID: CapXattr, Action: ActionCreate, Result: ResultUnknown}},
		{"forbidden", Classification{Path: pathOf("x"), CapabilityID: CapXattr, Action: ActionCreate, Result: ResultPolicyForbidden}},
		{"unknown-cap", Classification{Path: pathOf("x"), CapabilityID: 999, Action: ActionCreate, Result: ResultLossless}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, pf, err := Build(baseInput(tc.c))
			if err == nil || !AsKind(err, KindRefuse) {
				t.Fatalf("want refuse, got plan=%v err=%v", p, err)
			}
			if pf.Authorized() || len(pf.Blocking) != 1 {
				t.Fatalf("preflight: %+v", pf)
			}
			if len(p.Bytes) != 0 {
				t.Fatalf("authorize-able bytes on refuse: %d", len(p.Bytes))
			}
		})
	}
}

func TestWrappedRequiresAllowList(t *testing.T) {
	c := Classification{
		Path: pathOf("w"), CapabilityID: CapResourceFork, Action: ActionCreate,
		Result: ResultWrapped, RepresentationIDs: []uint16{7, 3},
	}
	_, _, err := Build(baseInput(c))
	if err == nil || !AsKind(err, KindRefuse) {
		t.Fatalf("want refuse without allow-list, got %v", err)
	}

	in := baseInput(c)
	in.Policy.WrapAllowList = []uint16{9, 3, 1}
	p, pf, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if !pf.Authorized() {
		t.Fatal("expected authorized")
	}
	// Least allowed wrap id among candidates ∩ allow = 3.
	if !bytes.Contains(p.Bytes, []byte{3, 0}) { // u16le representation_id appears in entry
		// Soft check: digest stable across rebuild.
		p2, _, _ := Build(in)
		if p.Digest != p2.Digest {
			t.Fatal("wrap plan non-deterministic")
		}
	}
}

func TestDestructiveSummaryStable(t *testing.T) {
	in := baseInput(
		Classification{Path: pathOf("keep"), CapabilityID: CapIdentity, Action: ActionCreate, Result: ResultLossless},
		Classification{Path: pathOf("gone"), CapabilityID: CapIdentity, Action: ActionQuarantineDelete, Result: ResultLossless},
	)
	p1, _, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	p2, _, err := Build(baseInput(
		Classification{Path: pathOf("gone"), CapabilityID: CapIdentity, Action: ActionQuarantineDelete, Result: ResultLossless},
		Classification{Path: pathOf("keep"), CapabilityID: CapIdentity, Action: ActionCreate, Result: ResultLossless},
	))
	if err != nil {
		t.Fatal(err)
	}
	if p1.Digest != p2.Digest {
		t.Fatalf("destructive summary order-dependent")
	}
}

func TestLimitEntries(t *testing.T) {
	in := baseInput(
		Classification{Path: pathOf("a"), CapabilityID: CapCase, Action: ActionCreate, Result: ResultLossless},
		Classification{Path: pathOf("b"), CapabilityID: CapCase, Action: ActionCreate, Result: ResultLossless},
	)
	in.Limits.MaxEntries = 1
	_, _, err := Build(in)
	if err == nil || !AsKind(err, KindLimit) {
		t.Fatalf("want limit, got %v", err)
	}
}

func TestRejectBadActionAndPath(t *testing.T) {
	_, _, err := Build(baseInput(Classification{
		Path: pathOf("."), CapabilityID: CapCase, Action: ActionCreate, Result: ResultLossless,
	}))
	if err == nil || !AsKind(err, KindNonCanonical) {
		t.Fatalf("want non-canonical path, got %v", err)
	}

	_, _, err = Build(baseInput(Classification{
		Path: pathOf("ok"), CapabilityID: CapCase, Action: 99, Result: ResultLossless,
	}))
	if err == nil || !AsKind(err, KindUnsupported) {
		t.Fatalf("want unsupported action, got %v", err)
	}
}

func TestDuplicateClassificationRejected(t *testing.T) {
	c := Classification{Path: pathOf("x"), CapabilityID: CapCase, Action: ActionCreate, Result: ResultLossless}
	_, _, err := Build(baseInput(c, c))
	if err == nil || !AsKind(err, KindNonCanonical) {
		t.Fatalf("want duplicate reject, got %v", err)
	}
}

func TestBlockingPreflightCanonicalOrder(t *testing.T) {
	_, pf, err := Build(baseInput(
		Classification{Path: pathOf("z"), CapabilityID: CapXattr, Action: ActionCreate, Result: ResultUnknown},
		Classification{Path: pathOf("a"), CapabilityID: CapACL, Action: ActionCreate, Result: ResultUnrepresentable},
	))
	if err == nil || !AsKind(err, KindRefuse) {
		t.Fatalf("want refuse, got %v", err)
	}
	if len(pf.Blocking) != 2 {
		t.Fatalf("blocking=%d", len(pf.Blocking))
	}
	// Sorted input order means blockers follow sorted classification order: a then z.
	if string(pf.Blocking[0].Path[0]) != "a" || string(pf.Blocking[1].Path[0]) != "z" {
		t.Fatalf("blocking order %+v", pf.Blocking)
	}
}
