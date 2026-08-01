package confine_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestFormatNegativeAck(t *testing.T) {
	ack := confine.FormatNegativeAck([]confine.Finding{
		{ID: "NEG-FS-OPEN", Status: confine.StatusDeniedExpected},
		{ID: "NEG-EXEC", Status: confine.StatusDeniedExpected},
		{ID: "NEG-PTRACE", Status: confine.StatusSkipped},
		{ID: "NEG-NET-ARCHIVE", Status: confine.StatusDeniedExpected},
		{ID: "NEG-PARSER-NET", Status: confine.StatusSkipped},
	})
	want := "|NEG-FS:denied_as_expected|NEG-EXEC:denied_as_expected|NEG-PTRACE:skipped|NEG-NET-ARCHIVE:denied_as_expected|NEG-PARSER-NET:skipped"
	if ack != want {
		t.Fatalf("%q", ack)
	}
}

func TestNegativeEngineeringDarwinSkipsExecPtrace(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("live NegativeEngineering exec probe would replace an unconfined process")
	}
	fs := confine.NegativeEngineering()
	ack := confine.FormatNegativeAck(fs)
	for _, tok := range []string{"|NEG-FS:", "|NEG-EXEC:", "|NEG-PTRACE:"} {
		if !strings.Contains(ack, tok) {
			t.Fatalf("missing %s in %q", tok, ack)
		}
	}
	for _, f := range fs {
		if f.ID == "NEG-EXEC" || f.ID == "NEG-PTRACE" {
			if f.Status != confine.StatusSkipped {
				t.Fatalf("%s status %s", f.ID, f.Status)
			}
		}
	}
}
