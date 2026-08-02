package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireApplyAvailable(t *testing.T) {
	ok := confine.Report{Findings: []confine.Finding{{
		ID: "APPLY-SEATBELT", Status: confine.StatusAvailable, Detail: "ok",
	}}}
	if err := ok.RequireApplyAvailable(); err != nil {
		t.Fatal(err)
	}

	bad := confine.Report{Findings: []confine.Finding{{
		ID: "APPLY-SEATBELT", Status: confine.StatusUnavailable, Detail: "fail",
	}}}
	if err := bad.RequireApplyAvailable(); err == nil {
		t.Fatal("expected unavailable refusal")
	}

	skip := confine.Report{Findings: []confine.Finding{{
		ID: "APPLY-SEATBELT", Status: confine.StatusSkipped, Detail: "nocgo",
	}}}
	if err := skip.RequireApplyAvailable(); err == nil {
		t.Fatal("expected skipped refusal")
	}

	empty := confine.Report{}
	if err := empty.RequireApplyAvailable(); err == nil {
		t.Fatal("expected empty refusal")
	}
}
