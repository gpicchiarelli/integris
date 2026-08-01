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
	if runtime.GOOS == "darwin" && byID[plan.CapCOW] != plan.ResultLossless {
		t.Fatalf("darwin APFS tempdir CapCOW=%v want LOSSLESS (clonefile)", byID[plan.CapCOW])
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
