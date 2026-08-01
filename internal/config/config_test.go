package config_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/config"
)

func TestParseCanonicalDigestStable(t *testing.T) {
	a, err := config.Parse([]byte(`{
  "schema_version": 1,
  "node_name": "n1",
  "max_journal_payload_bytes": 1024,
  "session_timeout_ms": 1000,
  "allow_destructive": false,
  "allow_weak_confinement": false,
  "allow_network_listen": false
}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := config.Parse([]byte(`{"allow_network_listen":false,"allow_weak_confinement":false,"allow_destructive":false,"session_timeout_ms":1000,"max_journal_payload_bytes":1024,"node_name":"n1","schema_version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() != b.Digest() {
		t.Fatalf("digest mismatch\n%q\n%q", a.CanonicalJSON(), b.CanonicalJSON())
	}
	if !bytes.Equal(a.CanonicalJSON(), b.CanonicalJSON()) {
		t.Fatal("canonical bytes differ")
	}
}

func TestRejectDuplicateKeys(t *testing.T) {
	_, err := config.Parse([]byte(`{
  "schema_version": 1,
  "schema_version": 1,
  "node_name": "n",
  "max_journal_payload_bytes": 1,
  "session_timeout_ms": 1,
  "allow_destructive": false,
  "allow_weak_confinement": false,
  "allow_network_listen": false
}`))
	var ce *config.Error
	if err == nil {
		t.Fatal("expected error")
	}
	if !asConfig(err, &ce) || ce.Code != "duplicate" {
		t.Fatalf("got %v", err)
	}
}

func TestRejectUnknownField(t *testing.T) {
	_, err := config.Parse([]byte(`{
  "schema_version": 1,
  "node_name": "n",
  "max_journal_payload_bytes": 1,
  "session_timeout_ms": 1,
  "allow_destructive": false,
  "allow_weak_confinement": false,
  "allow_network_listen": false,
  "extra": true
}`))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestRejectMissingAndBounds(t *testing.T) {
	_, err := config.Parse([]byte(`{"schema_version":1}`))
	if err == nil {
		t.Fatal("expected missing")
	}
	_, err = config.Parse([]byte(`{
  "schema_version": 1,
  "node_name": "n",
  "max_journal_payload_bytes": 0,
  "session_timeout_ms": 1,
  "allow_destructive": false,
  "allow_weak_confinement": false,
  "allow_network_listen": false
}`))
	var ce *config.Error
	if !asConfig(err, &ce) || ce.Code != "max_journal_payload_bytes" {
		t.Fatalf("got %v", err)
	}
}

func TestDefaultsSafeClosed(t *testing.T) {
	d := config.DefaultsDocument()
	if d.AllowDestructive || d.AllowWeakConfinement || d.AllowNetworkListen {
		t.Fatalf("defaults must be closed: %+v", d)
	}
}

func asConfig(err error, target **config.Error) bool {
	if e, ok := err.(*config.Error); ok {
		*target = e
		return true
	}
	return false
}
