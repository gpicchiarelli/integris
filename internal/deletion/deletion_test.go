package deletion_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/deletion"
)

func dig(s string) codec.Digest { return codec.SHA256([]byte(s)) }

func authOK() deletion.Authorization {
	return deletion.Authorization{
		PlanDigest:       dig("plan"),
		ConfigDigest:     dig("cfg"),
		CapabilityDigest: dig("cap"),
		DestructiveAuth:  dig("destr"),
	}
}

func thOK() deletion.Thresholds {
	return deletion.Thresholds{
		MaxObjectCount:     100,
		MaxPercentBPS:      1000, // 10%
		MaxLogicalBytes:    1 << 20,
		MaxPhysicalBytes:   1 << 20,
		MaxPathClassCount:  50,
		RequireCompleteSrc: true,
	}
}

func obsOK() deletion.Observation {
	return deletion.Observation{
		ObjectCount:        5,
		ArchiveObjectCount: 100,
		LogicalBytes:       1000,
		PhysicalBytes:      1000,
		PathClassCount:     1,
		SourceComplete:     true,
		SameVolume:         true,
		QuarantineCapacity: 1 << 20,
		RootSentinelOK:     true,
		VolumeAuthorized:   true,
	}
}

func TestEvaluateAllowsQuarantine(t *testing.T) {
	d, err := deletion.Evaluate(thOK(), obsOK(), authOK())
	if err != nil || !d.Allowed || !d.PermanentDisabled {
		t.Fatalf("%+v err=%v", d, err)
	}
	if d.PercentBPS != 500 {
		t.Fatalf("pct=%d", d.PercentBPS)
	}
}

func TestHardStopUnknown(t *testing.T) {
	obs := obsOK()
	obs.UnknownLogical = true
	_, err := deletion.Evaluate(thOK(), obs, authOK())
	var e *deletion.Error
	if err == nil || !asDel(err, &e) || e.Code != "unknown" {
		t.Fatalf("got %v", err)
	}
}

func TestHardStopThreshold(t *testing.T) {
	obs := obsOK()
	obs.ObjectCount = 50
	obs.ArchiveObjectCount = 100 // 5000 bps > 1000
	_, err := deletion.Evaluate(thOK(), obs, authOK())
	var e *deletion.Error
	if err == nil || !asDel(err, &e) || e.Code != "percent" {
		t.Fatalf("got %v", err)
	}
}

func TestHardStopIncompleteSource(t *testing.T) {
	obs := obsOK()
	obs.SourceComplete = false
	_, err := deletion.Evaluate(thOK(), obs, authOK())
	var e *deletion.Error
	if err == nil || !asDel(err, &e) || e.Code != "source" {
		t.Fatalf("got %v", err)
	}
}

func TestHardStopMissingDestructiveAuth(t *testing.T) {
	a := authOK()
	a.DestructiveAuth = codec.Digest{}
	_, err := deletion.Evaluate(thOK(), obsOK(), a)
	var e *deletion.Error
	if err == nil || !asDel(err, &e) || e.Code != "auth" {
		t.Fatalf("got %v", err)
	}
}

func TestHardStopCapacity(t *testing.T) {
	obs := obsOK()
	obs.QuarantineCapacity = 10
	obs.PhysicalBytes = 100
	_, err := deletion.Evaluate(thOK(), obs, authOK())
	var e *deletion.Error
	if err == nil || !asDel(err, &e) || e.Code != "capacity" {
		t.Fatalf("got %v", err)
	}
}

func TestPermanentPurgeStillQuarantineOnly(t *testing.T) {
	a := authOK()
	a.AllowPermanentPurge = true
	d, err := deletion.Evaluate(thOK(), obsOK(), a)
	if err != nil || !d.Allowed || !d.PermanentDisabled {
		t.Fatalf("%+v err=%v", d, err)
	}
}

func TestBuildQuarantinePlan(t *testing.T) {
	p, err := deletion.BuildQuarantinePlan([]byte("a"), []byte("q/a"), dig("obj"), dig("plan"), dig("auth"))
	if err != nil {
		t.Fatal(err)
	}
	if string(p.SourceName) != "a" {
		t.Fatal(p)
	}
	_, err = deletion.BuildQuarantinePlan(nil, []byte("q"), dig("o"), dig("p"), dig("a"))
	if err == nil {
		t.Fatal("expected name error")
	}
}

func asDel(err error, target **deletion.Error) bool {
	if e, ok := err.(*deletion.Error); ok {
		*target = e
		return true
	}
	return false
}
