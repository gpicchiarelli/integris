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
		{ID: "NEG-FS-READ", Status: confine.StatusDeniedExpected},
		{ID: "NEG-FS-PATH", Status: confine.StatusSkipped},
		{ID: "NEG-FS-WRITE", Status: confine.StatusSkipped},
		{ID: "NEG-EXEC", Status: confine.StatusDeniedExpected},
		{ID: "NEG-PTRACE", Status: confine.StatusSkipped},
		{ID: "NEG-ROLE-NET", Status: confine.StatusDeniedExpected},
		{ID: "NEG-NET-ARCHIVE", Status: confine.StatusDeniedExpected},
		{ID: "NEG-PARSER-NET", Status: confine.StatusSkipped},
		{ID: "NEG-PARSER-KEYS", Status: confine.StatusSkipped},
		{ID: "NEG-PARSER-ARCHIVES", Status: confine.StatusSkipped},
		{ID: "NEG-AUTH-ACCEPT", Status: confine.StatusDeniedExpected},
		{ID: "NEG-AUTH-CONTENTS", Status: confine.StatusDeniedExpected},
		{ID: "NEG-AUTH-PUB", Status: confine.StatusDeniedExpected},
		{ID: "NEG-INDEX-PUB", Status: confine.StatusSkipped},
		{ID: "NEG-INDEX-DELETE", Status: confine.StatusSkipped},
		{ID: "NEG-APPLY-KEYS", Status: confine.StatusSkipped},
		{ID: "NEG-APPLY-PATH", Status: confine.StatusSkipped},
		{ID: "NEG-PLAN-WRITE", Status: confine.StatusDeniedExpected},
		{ID: "NEG-AUDIT-DECIDE", Status: confine.StatusDeniedExpected},
		{ID: "NEG-AUDIT-ARCHIVES", Status: confine.StatusSkipped},
		{ID: "NEG-AUDIT-SECRETS", Status: confine.StatusSkipped},
		{ID: "NEG-JOURNAL-NET", Status: confine.StatusDeniedExpected},
		{ID: "NEG-JOURNAL-POLICY", Status: confine.StatusSkipped},
		{ID: "NEG-JOURNAL-MUTATE", Status: confine.StatusSkipped},
	})
	want := "|NEG-FS:denied_as_expected|NEG-FS-READ:denied_as_expected|NEG-FS-PATH:skipped|NEG-FS-WRITE:skipped|NEG-EXEC:denied_as_expected|NEG-PTRACE:skipped|NEG-ROLE-NET:denied_as_expected|NEG-NET-ARCHIVE:denied_as_expected|NEG-PARSER-NET:skipped|NEG-PARSER-KEYS:skipped|NEG-PARSER-ARCHIVES:skipped|NEG-AUTH-ACCEPT:denied_as_expected|NEG-AUTH-CONTENTS:denied_as_expected|NEG-AUTH-PUB:denied_as_expected|NEG-INDEX-PUB:skipped|NEG-INDEX-DELETE:skipped|NEG-APPLY-KEYS:skipped|NEG-APPLY-PATH:skipped|NEG-PLAN-WRITE:denied_as_expected|NEG-AUDIT-DECIDE:denied_as_expected|NEG-AUDIT-ARCHIVES:skipped|NEG-AUDIT-SECRETS:skipped|NEG-JOURNAL-NET:denied_as_expected|NEG-JOURNAL-POLICY:skipped|NEG-JOURNAL-MUTATE:skipped"
	if ack != want {
		t.Fatalf("%q", ack)
	}
}

func TestNegativePtraceSkippedOffLinux(t *testing.T) {
	f := confine.NegativePtrace()
	if runtime.GOOS == "linux" {
		t.Skip("linux ptrace probe mutates; covered in confined stub")
	}
	if f.Status != confine.StatusSkipped {
		t.Fatalf("%+v", f)
	}
	if !strings.Contains(f.Detail, "Linux") {
		t.Fatalf("%q", f.Detail)
	}
}
