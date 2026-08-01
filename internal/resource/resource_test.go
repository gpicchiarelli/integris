package resource_test

import (
	"math"
	"testing"

	"github.com/gpicchiarelli/integris/internal/resource"
)

func TestAdmitBoundaries(t *testing.T) {
	l := resource.Limits{MaxBytes: 10, MaxCount: 3, MaxNesting: 2, MaxQueueDepth: 2, MaxConcurrent: 2, MaxRetries: 1}
	if err := l.AdmitBytes(10); err != nil {
		t.Fatal(err)
	}
	if err := l.AdmitBytes(11); err == nil {
		t.Fatal("expected bytes refuse")
	}
	if err := l.AdmitCount(4); err == nil {
		t.Fatal("expected count refuse")
	}
	if err := l.AdmitNesting(3); err == nil {
		t.Fatal("expected nesting refuse")
	}
}

func TestUnconfiguredLimitRefused(t *testing.T) {
	var l resource.Limits
	if err := l.AdmitBytes(1); err == nil {
		t.Fatal("zero MaxBytes must refuse")
	}
}

func TestOverflowSafeArithmetic(t *testing.T) {
	if _, err := resource.AddUint64(math.MaxUint64, 1); err == nil {
		t.Fatal("expected add overflow")
	}
	if _, err := resource.MulUint64(math.MaxUint64, 2); err == nil {
		t.Fatal("expected mul overflow")
	}
	sum, err := resource.AddUint64(2, 3)
	if err != nil || sum != 5 {
		t.Fatalf("sum=%d err=%v", sum, err)
	}
}

func TestAdmitSliceCap(t *testing.T) {
	l := resource.Limits{MaxBytes: 100, MaxCount: 10, MaxNesting: 1, MaxQueueDepth: 1, MaxConcurrent: 1, MaxRetries: 1}
	if err := l.AdmitSliceCap(10, 10); err != nil {
		t.Fatal(err)
	}
	if err := l.AdmitSliceCap(11, 10); err == nil {
		t.Fatal("expected refuse")
	}
}

func TestBudgetCumulative(t *testing.T) {
	b := resource.Budget{Limits: resource.Limits{MaxBytes: 10, MaxCount: 5, MaxNesting: 1, MaxQueueDepth: 1, MaxConcurrent: 1, MaxRetries: 1}}
	if err := b.ConsumeBytes(6); err != nil {
		t.Fatal(err)
	}
	if err := b.ConsumeBytes(5); err == nil {
		t.Fatal("expected cumulative refuse")
	}
	if err := b.ConsumeCount(5); err != nil {
		t.Fatal(err)
	}
	if err := b.ConsumeCount(1); err == nil {
		t.Fatal("expected count refuse")
	}
}

func TestDefaultLimitsPositive(t *testing.T) {
	l := resource.DefaultLimits()
	if l.MaxBytes == 0 || l.MaxCount == 0 {
		t.Fatalf("%+v", l)
	}
}
