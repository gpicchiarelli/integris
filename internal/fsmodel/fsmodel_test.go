package fsmodel_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/fsmodel"
	"github.com/gpicchiarelli/integris/internal/plan"
)

func dig(s string) codec.Digest { return codec.SHA256([]byte(s)) }

func TestVectorDigestStable(t *testing.T) {
	facts := []fsmodel.Fact{
		{ID: plan.CapSymlink, Result: plan.ResultLossless},
		{ID: plan.CapCase, Result: plan.ResultLossless},
	}
	// Insert out of order.
	v1, err := fsmodel.NewVector(dig("vol"), facts)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := fsmodel.NewVector(dig("vol"), []fsmodel.Fact{
		{ID: plan.CapCase, Result: plan.ResultLossless},
		{ID: plan.CapSymlink, Result: plan.ResultLossless},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v1.Digest() != v2.Digest() {
		t.Fatal("digest unstable under fact permutation")
	}
}

func TestRejectUnknownCapability(t *testing.T) {
	_, err := fsmodel.NewVector(dig("vol"), []fsmodel.Fact{{ID: 999, Result: plan.ResultLossless}})
	var e *fsmodel.Error
	if err == nil || !asFS(err, &e) || e.Code != "capability" {
		t.Fatalf("got %v", err)
	}
}

func TestCompareBlocksUnknownAndUnrepresentable(t *testing.T) {
	target, err := fsmodel.NewVector(dig("vol"), []fsmodel.Fact{
		{ID: plan.CapCase, Result: plan.ResultLossless},
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := fsmodel.Compare([]fsmodel.Fact{
		{ID: plan.CapCase, Result: plan.ResultLossless},
		{ID: plan.CapACL, Result: plan.ResultLossless}, // missing on target → UNKNOWN
		{ID: plan.CapXattr, Result: plan.ResultUnrepresentable},
	}, target)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Allowed {
		t.Fatalf("expected block: %+v", rep)
	}
	if err := fsmodel.RequireNoSilentLoss(rep); err == nil {
		t.Fatal("expected preflight error")
	}
}

func TestCompareAllowsLossless(t *testing.T) {
	target, err := fsmodel.NewVector(dig("vol"), []fsmodel.Fact{
		{ID: plan.CapCase, Result: plan.ResultLossless},
		{ID: plan.CapSymlink, Result: plan.ResultLossless},
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := fsmodel.Compare([]fsmodel.Fact{
		{ID: plan.CapCase, Result: plan.ResultLossless},
		{ID: plan.CapSymlink, Result: plan.ResultLossless},
	}, target)
	if err != nil || !rep.Allowed {
		t.Fatalf("%+v err=%v", rep, err)
	}
	if err := fsmodel.RequireNoSilentLoss(rep); err != nil {
		t.Fatal(err)
	}
}

func TestMergePrefersRestrictive(t *testing.T) {
	target, err := fsmodel.NewVector(dig("vol"), []fsmodel.Fact{
		{ID: plan.CapHardlink, Result: plan.ResultPolicyForbidden},
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := fsmodel.Compare([]fsmodel.Fact{
		{ID: plan.CapHardlink, Result: plan.ResultLossless},
	}, target)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Allowed || rep.Issues[0].Outcome != plan.ResultPolicyForbidden {
		t.Fatalf("%+v", rep)
	}
}

func asFS(err error, target **fsmodel.Error) bool {
	if e, ok := err.(*fsmodel.Error); ok {
		*target = e
		return true
	}
	return false
}
