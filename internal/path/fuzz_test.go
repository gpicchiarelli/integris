package path

import (
	"bytes"
	"testing"
)

// FuzzPathComponent exercises grammar validation on arbitrary component bytes.
func FuzzPathComponent(f *testing.F) {
	seeds := [][]byte{
		[]byte("a"),
		[]byte("."),
		[]byte(".."),
		[]byte("a/b"),
		[]byte(`a\b`),
		{0},
		{0xC3, 0xA9},      // NFC é
		{'e', 0xCC, 0x81}, // NFD é
		bytes.Repeat([]byte{'x'}, 255),
		bytes.Repeat([]byte{'x'}, 256),
		{0xC0, 0x80},
		[]byte("CON"),
		[]byte("COM1"),
		[]byte("hello world"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, comp []byte) {
		// Bound copy so fuzz does not force huge allocations inside the
		// harness itself; the validator still enforces MaxComponentBytes.
		if len(comp) > MaxComponentBytes*2 {
			comp = comp[:MaxComponentBytes*2]
		}
		err := ValidateComponents([][]byte{comp}, Profile{WindowsReserved: true})
		if err == nil {
			// Accepted components must be non-empty, UTF-8 NFC, within limits.
			if len(comp) == 0 || len(comp) > MaxComponentBytes {
				t.Fatalf("accepted out-of-limit component len=%d", len(comp))
			}
			if bytes.IndexByte(comp, 0) >= 0 || bytes.IndexByte(comp, '/') >= 0 || bytes.IndexByte(comp, '\\') >= 0 {
				t.Fatalf("accepted component with forbidden byte: %q", comp)
			}
			return
		}
		e, ok := err.(*Error)
		if !ok || e.Rule == "" {
			t.Fatalf("expected typed *Error, got %T %v", err, err)
		}
	})
}

// FuzzPathSequence exercises multi-component sequences under budget.
func FuzzPathSequence(f *testing.F) {
	f.Add([]byte("a"), []byte("b"), []byte("c"))
	f.Add([]byte("."), []byte(".."), []byte("x"))
	f.Fuzz(func(t *testing.T, a, b, c []byte) {
		trim := func(x []byte) []byte {
			if len(x) > MaxComponentBytes+8 {
				return x[:MaxComponentBytes+8]
			}
			return x
		}
		comps := [][]byte{trim(a), trim(b), trim(c)}
		err := ValidateComponents(comps, DefaultProfile)
		if err == nil {
			return
		}
		if _, ok := err.(*Error); !ok {
			t.Fatalf("expected *Error, got %T", err)
		}
	})
}
