package codec

import "testing"

func TestLERoundTrip(t *testing.T) {
	b := make([]byte, 8)
	PutU16LE(b, 0x0201)
	if U16LE(b) != 0x0201 {
		t.Fatalf("u16: got %#x", U16LE(b))
	}
	PutU32LE(b, 0x04030201)
	if U32LE(b) != 0x04030201 {
		t.Fatalf("u32: got %#x", U32LE(b))
	}
	PutU64LE(b, 0x0807060504030201)
	if U64LE(b) != 0x0807060504030201 {
		t.Fatalf("u64: got %#x", U64LE(b))
	}
}

func TestLEByteOrder(t *testing.T) {
	b := make([]byte, 4)
	PutU32LE(b, 0x04030201)
	if b[0] != 0x01 || b[1] != 0x02 || b[2] != 0x03 || b[3] != 0x04 {
		t.Fatalf("unexpected bytes %v", b)
	}
}
