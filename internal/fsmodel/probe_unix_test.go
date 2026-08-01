//go:build unix

package fsmodel_test

import (
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/fsmodel"
	"github.com/gpicchiarelli/integris/internal/plan"
)

func TestProbeScratchEmpirical(t *testing.T) {
	res, err := fsmodel.ProbeScratch(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.GOOS == "" || len(res.Vector.Facts) == 0 {
		t.Fatalf("%+v", res)
	}
	byID := map[plan.CapabilityID]plan.ResultCode{}
	for _, f := range res.Vector.Facts {
		byID[f.ID] = f.Result
	}
	if byID[plan.CapSymlink] != plan.ResultLossless && byID[plan.CapSymlink] != plan.ResultUnrepresentable {
		t.Fatalf("symlink=%v", byID[plan.CapSymlink])
	}
	if byID[plan.CapCase] != plan.ResultLossless && byID[plan.CapCase] != plan.ResultWrapped {
		t.Fatalf("case=%v", byID[plan.CapCase])
	}
	switch byID[plan.CapCOW] {
	case plan.ResultLossless, plan.ResultUnrepresentable, plan.ResultUnknown:
	default:
		t.Fatalf("cow=%v", byID[plan.CapCOW])
	}
	switch byID[plan.CapXattr] {
	case plan.ResultLossless, plan.ResultUnrepresentable, plan.ResultUnknown:
	default:
		t.Fatalf("xattr=%v", byID[plan.CapXattr])
	}
	switch byID[plan.CapBSDFlags] {
	case plan.ResultLossless, plan.ResultUnrepresentable, plan.ResultUnknown:
	default:
		t.Fatalf("bsdflags=%v", byID[plan.CapBSDFlags])
	}
	if runtime.GOOS == "darwin" {
		if byID[plan.CapCOW] != plan.ResultLossless {
			t.Fatalf("darwin CapCOW=%v want LOSSLESS (clonefile)", byID[plan.CapCOW])
		}
		if byID[plan.CapXattr] != plan.ResultLossless {
			t.Fatalf("darwin CapXattr=%v want LOSSLESS", byID[plan.CapXattr])
		}
		if byID[plan.CapBSDFlags] != plan.ResultLossless {
			t.Fatalf("darwin CapBSDFlags=%v want LOSSLESS (chflags)", byID[plan.CapBSDFlags])
		}
	}
	// Digest must be stable across re-probe on same FS type in same dir parent.
	res2, err := fsmodel.ProbeScratch(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Volume digest embeds st_dev; temp dirs on same FS share vol digest shape.
	if res.Vector.VolumeIdentity == (res2.Vector.VolumeIdentity) {
		// Same device: case/symlink/COW outcomes should match.
		if fact(res, plan.CapCase) != fact(res2, plan.CapCase) {
			t.Fatal("case probe unstable")
		}
		if fact(res, plan.CapCOW) != fact(res2, plan.CapCOW) {
			t.Fatal("cow probe unstable")
		}
		if fact(res, plan.CapXattr) != fact(res2, plan.CapXattr) {
			t.Fatal("xattr probe unstable")
		}
		if fact(res, plan.CapBSDFlags) != fact(res2, plan.CapBSDFlags) {
			t.Fatal("bsdflags probe unstable")
		}
	}
}

func fact(r fsmodel.ProbeResult, id plan.CapabilityID) plan.ResultCode {
	for _, f := range r.Vector.Facts {
		if f.ID == id {
			return f.Result
		}
	}
	return 0
}
