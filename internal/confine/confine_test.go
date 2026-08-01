package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestDiscoverSorted(t *testing.T) {
	r := confine.Discover()
	if r.GOOS == "" || len(r.Findings) == 0 {
		t.Fatalf("%+v", r)
	}
	for i := 1; i < len(r.Findings); i++ {
		if r.Findings[i-1].ID >= r.Findings[i].ID {
			t.Fatalf("unsorted: %s >= %s", r.Findings[i-1].ID, r.Findings[i].ID)
		}
	}
}

func TestNegativeBaselineEmpty(t *testing.T) {
	r := confine.NegativeBaseline()
	if len(r.Findings) != 0 {
		t.Fatalf("expected empty baseline, got %+v", r.Findings)
	}
	if r.HasUnexpectedAllow() {
		t.Fatal("unexpected")
	}
}
