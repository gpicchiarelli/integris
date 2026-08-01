package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRejectDuplicateKeys(t *testing.T) {
	t.Parallel()
	err := rejectDuplicateKeys([]byte(`{"id":"one","nested":{"x":1,"x":2}}`))
	if err == nil || !strings.Contains(err.Error(), `duplicate JSON object key "x"`) {
		t.Fatalf("expected duplicate-key error, got %v", err)
	}
}

func TestRejectDuplicateKeysAcceptsDistinctArrayObjects(t *testing.T) {
	t.Parallel()
	if err := rejectDuplicateKeys([]byte(`[{"id":"one"},{"id":"two"}]`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTraceabilityIsDeterministicAndSorted(t *testing.T) {
	t.Parallel()
	records := Records{
		Baseline: "test",
		Requirements: []Requirement{
			{ID: "INT-IC2-0002", Title: "second", Criticality: "IC-2", Hazards: []string{"HAZ-0002"}, Threats: []string{"THR-0002"}, Specifications: []string{"docs/b.md"}, Verifications: []string{"VER-X-002"}, Owner: "owner", ApproverRoles: []string{"reviewer"}},
			{ID: "INT-IC1-0001", Title: "first", Criticality: "IC-1", Hazards: []string{"HAZ-0001"}, Threats: []string{"THR-0001"}, Specifications: []string{"docs/a.md"}, Verifications: []string{"VER-X-001"}, Owner: "owner", ApproverRoles: []string{"reviewer"}},
		},
		Verifications: []Verification{{ID: "VER-X-002", Status: "planned"}, {ID: "VER-X-001", Status: "planned"}},
		Evidence:      []Evidence{{ID: "EVD-X-001", Verification: "VER-X-001", Status: "planned"}, {ID: "EVD-X-002", Verification: "VER-X-002", Status: "planned"}},
	}
	first := records.Traceability()
	second := records.Traceability()
	if string(first) != string(second) {
		t.Fatal("traceability output changed between calls")
	}
	if strings.Index(string(first), "INT-IC1-0001") > strings.Index(string(first), "INT-IC2-0002") {
		t.Fatal("requirements are not sorted")
	}
}

func TestStrictDecoderRejectsUnknownField(t *testing.T) {
	t.Parallel()
	var dst Requirement
	dec := json.NewDecoder(strings.NewReader(`{"id":"x","unexpected":true}`))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&dst); err == nil {
		t.Fatal("expected unknown field to be rejected")
	}
}

func TestCheckRepositoryFileRejectsParent(t *testing.T) {
	t.Parallel()
	var problems []string
	checkRepositoryFile(t.TempDir(), "TEST", "..", &problems)
	if len(problems) != 1 || !strings.Contains(problems[0], "invalid repository path") {
		t.Fatalf("expected parent path rejection, got %v", problems)
	}
}

func FuzzRejectDuplicateKeys(f *testing.F) {
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`[{"nested":{"x":true}}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		// The property is totality: hostile bytes must return, not panic.
		_ = rejectDuplicateKeys(data)
	})
}
