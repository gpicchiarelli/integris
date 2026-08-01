package confine_test

import (
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestProbeEngineering(t *testing.T) {
	r := confine.ProbeEngineering()
	if len(r.Findings) == 0 {
		t.Fatal("empty")
	}
	if runtime.GOOS == "linux" {
		ids := map[string]bool{}
		for _, f := range r.Findings {
			ids[f.ID] = true
		}
		if !ids["PROBE-LANDLOCK-ABI"] || !ids["PROBE-SECCOMP-ARCH"] {
			t.Fatalf("%+v", r.Findings)
		}
	}
	if runtime.GOOS == "darwin" {
		ids := map[string]bool{}
		for _, f := range r.Findings {
			ids[f.ID] = true
		}
		if !ids["PROBE-SEATBELT"] {
			t.Fatalf("%+v", r.Findings)
		}
	}
}

func TestApplyEngineeringNotInUnitProcess(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "openbsd", "freebsd", "darwin":
		t.Skip("ApplyEngineering mutates process; covered by role-stub integration")
	}
	r := confine.ApplyEngineering("")
	if len(r.Findings) == 0 || r.Findings[0].Status != confine.StatusSkipped {
		t.Fatalf("%+v", r.Findings)
	}
}
