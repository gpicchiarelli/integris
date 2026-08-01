package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/gpicchiarelli/integris/internal/codec"
)

// SchemaVersion is the M1 configuration schema version.
const SchemaVersion = 1

// MaxConfigBytes is the hard decode budget before allocation from external input.
const MaxConfigBytes = 1 << 20

// Document is the validated immutable configuration.
type Document struct {
	SchemaVersion int    `json:"schema_version"`
	NodeName      string `json:"node_name"`
	// Limits use explicit units in field names (_bytes, _ms).
	MaxJournalPayloadBytes int64 `json:"max_journal_payload_bytes"`
	SessionTimeoutMS       int64 `json:"session_timeout_ms"`
	AllowDestructive       bool  `json:"allow_destructive"`
	AllowWeakConfinement   bool  `json:"allow_weak_confinement"`
	AllowNetworkListen     bool  `json:"allow_network_listen"`

	digest codec.Digest
	raw    []byte // canonical JSON bytes
}

// Digest returns the SHA-256 of the canonical JSON serialization.
func (d Document) Digest() codec.Digest { return d.digest }

// CanonicalJSON returns the deterministic serialization used for digests.
func (d Document) CanonicalJSON() []byte {
	out := make([]byte, len(d.raw))
	copy(out, d.raw)
	return out
}

// Error is a typed configuration failure.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Code + ": " + e.Message
}

func reject(code, msg string) error { return &Error{Code: code, Message: msg} }

// Parse validates and canonicalizes a configuration document from JSON bytes.
func Parse(data []byte) (Document, error) {
	var zero Document
	if len(data) == 0 {
		return zero, reject("empty", "configuration is empty")
	}
	if len(data) > MaxConfigBytes {
		return zero, reject("limit", "configuration exceeds MaxConfigBytes")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return zero, err
	}
	if err := requireKeys(data, []string{
		"schema_version", "node_name", "max_journal_payload_bytes", "session_timeout_ms",
		"allow_destructive", "allow_weak_confinement", "allow_network_listen",
	}); err != nil {
		return zero, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var wire struct {
		SchemaVersion          int    `json:"schema_version"`
		NodeName               string `json:"node_name"`
		MaxJournalPayloadBytes int64  `json:"max_journal_payload_bytes"`
		SessionTimeoutMS       int64  `json:"session_timeout_ms"`
		AllowDestructive       bool   `json:"allow_destructive"`
		AllowWeakConfinement   bool   `json:"allow_weak_confinement"`
		AllowNetworkListen     bool   `json:"allow_network_listen"`
	}
	if err := dec.Decode(&wire); err != nil {
		return zero, reject("syntax", err.Error())
	}
	if err := ensureEOF(dec); err != nil {
		return zero, err
	}
	doc := Document{
		SchemaVersion:          wire.SchemaVersion,
		NodeName:               wire.NodeName,
		MaxJournalPayloadBytes: wire.MaxJournalPayloadBytes,
		SessionTimeoutMS:       wire.SessionTimeoutMS,
		AllowDestructive:       wire.AllowDestructive,
		AllowWeakConfinement:   wire.AllowWeakConfinement,
		AllowNetworkListen:     wire.AllowNetworkListen,
	}
	if err := validate(doc); err != nil {
		return zero, err
	}
	canon, err := marshalCanonical(doc)
	if err != nil {
		return zero, err
	}
	doc.raw = canon
	doc.digest = codec.SHA256(canon)
	return doc, nil
}

func validate(d Document) error {
	if d.SchemaVersion != SchemaVersion {
		return reject("schema", fmt.Sprintf("unsupported schema_version %d", d.SchemaVersion))
	}
	if d.NodeName == "" || len(d.NodeName) > 255 {
		return reject("node_name", "must be 1..255 bytes")
	}
	if d.MaxJournalPayloadBytes <= 0 || d.MaxJournalPayloadBytes > 1<<30 {
		return reject("max_journal_payload_bytes", "out of safe bounds")
	}
	if d.SessionTimeoutMS <= 0 || d.SessionTimeoutMS > 7*24*3600*1000 {
		return reject("session_timeout_ms", "out of safe bounds")
	}
	return nil
}

func marshalCanonical(d Document) ([]byte, error) {
	type wire struct {
		SchemaVersion          int    `json:"schema_version"`
		NodeName               string `json:"node_name"`
		MaxJournalPayloadBytes int64  `json:"max_journal_payload_bytes"`
		SessionTimeoutMS       int64  `json:"session_timeout_ms"`
		AllowDestructive       bool   `json:"allow_destructive"`
		AllowWeakConfinement   bool   `json:"allow_weak_confinement"`
		AllowNetworkListen     bool   `json:"allow_network_listen"`
	}
	w := wire{
		SchemaVersion:          d.SchemaVersion,
		NodeName:               d.NodeName,
		MaxJournalPayloadBytes: d.MaxJournalPayloadBytes,
		SessionTimeoutMS:       d.SessionTimeoutMS,
		AllowDestructive:       d.AllowDestructive,
		AllowWeakConfinement:   d.AllowWeakConfinement,
		AllowNetworkListen:     d.AllowNetworkListen,
	}
	buf, err := json.Marshal(w)
	if err != nil {
		return nil, reject("canon", err.Error())
	}
	return buf, nil
}

func ensureEOF(dec *json.Decoder) error {
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return reject("syntax", "trailing JSON content")
		}
		return reject("syntax", err.Error())
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	return scanValue(dec)
}

func requireKeys(data []byte, keys []string) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return reject("syntax", err.Error())
	}
	if tok != json.Delim('{') {
		return reject("syntax", "configuration must be a JSON object")
	}
	seen := map[string]struct{}{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return reject("syntax", err.Error())
		}
		key, ok := keyTok.(string)
		if !ok {
			return reject("syntax", "object key must be string")
		}
		seen[key] = struct{}{}
		if err := scanValue(dec); err != nil {
			return err
		}
	}
	for _, k := range keys {
		if _, ok := seen[k]; !ok {
			return reject("missing", "missing field "+k)
		}
	}
	return nil
}

func scanValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return reject("syntax", err.Error())
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return reject("syntax", err.Error())
				}
				key, ok := keyTok.(string)
				if !ok {
					return reject("syntax", "object key must be string")
				}
				if _, dup := seen[key]; dup {
					return reject("duplicate", "duplicate key "+key)
				}
				seen[key] = struct{}{}
				if err := scanValue(dec); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return reject("syntax", err.Error())
			}
			if end != json.Delim('}') {
				return reject("syntax", "expected end of object")
			}
		case '[':
			for dec.More() {
				if err := scanValue(dec); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return reject("syntax", err.Error())
			}
			if end != json.Delim(']') {
				return reject("syntax", "expected end of array")
			}
		default:
			return reject("syntax", "unexpected delimiter")
		}
	case string, float64, bool, nil, json.Number:
		return nil
	default:
		return reject("syntax", fmt.Sprintf("unexpected token %T", t))
	}
	return nil
}

// DefaultsDocument returns a safe-closed default configuration for tests.
func DefaultsDocument() Document {
	d, err := Parse([]byte(`{
  "schema_version": 1,
  "node_name": "test-node",
  "max_journal_payload_bytes": 1048576,
  "session_timeout_ms": 60000,
  "allow_destructive": false,
  "allow_weak_confinement": false,
  "allow_network_listen": false
}`))
	if err != nil {
		panic(err)
	}
	return d
}
