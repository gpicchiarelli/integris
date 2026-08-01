package codec

import (
	"bytes"
	"testing"
)

func testFields(seq uint64, payload []byte) RecordFields {
	var txid TransactionID
	txid[0] = 0x11
	txid[15] = 0x22
	return RecordFields{
		Sequence:           seq,
		TransactionID:      txid,
		Type:               TypeObservation,
		PreviousCommitment: GenesisCommitment(),
		Payload:            payload,
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	f := testFields(1, []byte("hello"))
	enc, err := EncodeRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != RecordOverhead+len(f.Payload) {
		t.Fatalf("len=%d want %d", len(enc), RecordOverhead+len(f.Payload))
	}
	rec, n, err := DecodeRecord(enc)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(enc) {
		t.Fatalf("n=%d want %d", n, len(enc))
	}
	if rec.Sequence != 1 || !bytes.Equal(rec.Payload, f.Payload) {
		t.Fatalf("decoded mismatch: %+v", rec)
	}
	if rec.PayloadDigest != SHA256(f.Payload) {
		t.Fatal("payload digest mismatch")
	}
	if rec.PreviousCommitment != GenesisCommitment() {
		t.Fatal("genesis previous commitment")
	}
}

func TestCommitmentChain(t *testing.T) {
	f1 := testFields(1, []byte("a"))
	b1, err := EncodeRecord(f1)
	if err != nil {
		t.Fatal(err)
	}
	r1, _, err := DecodeRecord(b1)
	if err != nil {
		t.Fatal(err)
	}
	f2 := testFields(2, []byte("b"))
	f2.PreviousCommitment = r1.RecordCommitment
	b2, err := EncodeRecord(f2)
	if err != nil {
		t.Fatal(err)
	}
	r2, _, err := DecodeRecord(b2)
	if err != nil {
		t.Fatal(err)
	}
	if r2.PreviousCommitment != r1.RecordCommitment {
		t.Fatal("chain break")
	}
}

func TestRejectReservedNonZero(t *testing.T) {
	f := testFields(1, nil)
	enc, err := EncodeRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	enc[42] = 1
	_, _, err = DecodeRecord(enc)
	if !AsKind(err, KindNonCanonical) {
		t.Fatalf("want non-canonical, got %v", err)
	}
}

func TestRejectBadMagic(t *testing.T) {
	f := testFields(1, []byte("x"))
	enc, err := EncodeRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	enc[0] ^= 0xff
	_, _, err = DecodeRecord(enc)
	if !AsKind(err, KindNonCanonical) {
		t.Fatalf("want non-canonical, got %v", err)
	}
}

func TestRejectBadCommitment(t *testing.T) {
	f := testFields(1, []byte("x"))
	enc, err := EncodeRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	off := 108 + len(f.Payload)
	enc[off] ^= 0x01
	_, _, err = DecodeRecord(enc)
	if !AsKind(err, KindDigest) {
		t.Fatalf("want digest, got %v", err)
	}
}

func TestRejectBadPayloadDigest(t *testing.T) {
	f := testFields(1, []byte("x"))
	enc, err := EncodeRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	enc[44] ^= 0x01
	_, _, err = DecodeRecord(enc)
	if !AsKind(err, KindDigest) {
		t.Fatalf("want digest, got %v", err)
	}
}

func TestRejectTrailerLengthMismatch(t *testing.T) {
	f := testFields(1, []byte("x"))
	enc, err := EncodeRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	PutU32LE(enc[len(enc)-4:], uint32(len(enc))+1)
	_, _, err = DecodeRecord(enc)
	if !AsKind(err, KindNonCanonical) {
		t.Fatalf("want non-canonical, got %v", err)
	}
}

func TestRejectWrongHeaderLength(t *testing.T) {
	f := testFields(1, nil)
	enc, err := EncodeRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	PutU16LE(enc[10:12], 109)
	_, _, err = DecodeRecord(enc)
	if !AsKind(err, KindNonCanonical) {
		t.Fatalf("want non-canonical, got %v", err)
	}
}

func TestRejectUnknownVersion(t *testing.T) {
	f := testFields(1, nil)
	enc, err := EncodeRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	PutU16LE(enc[8:10], 2)
	_, _, err = DecodeRecord(enc)
	if !AsKind(err, KindUnsupported) {
		t.Fatalf("want unsupported, got %v", err)
	}
}

func TestRejectUnknownType(t *testing.T) {
	f := testFields(1, nil)
	f.Type = 0
	_, err := EncodeRecord(f)
	if !AsKind(err, KindUnsupported) {
		t.Fatalf("encode: want unsupported, got %v", err)
	}
	f.Type = TypeObservation
	enc, err := EncodeRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	PutU16LE(enc[40:42], 99)
	_, _, err = DecodeRecord(enc)
	if !AsKind(err, KindUnsupported) {
		t.Fatalf("decode: want unsupported, got %v", err)
	}
}

func TestRejectPayloadLimit(t *testing.T) {
	payload := make([]byte, MaxPayloadBytes+1)
	_, err := EncodeRecord(testFields(1, payload))
	if !AsKind(err, KindLimit) {
		t.Fatalf("want limit, got %v", err)
	}
}

func TestIncompleteTruncation(t *testing.T) {
	f := testFields(1, []byte("payload"))
	enc, err := EncodeRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(enc); i++ {
		_, _, err := DecodeRecord(enc[:i])
		if err == nil {
			t.Fatalf("offset %d: expected error", i)
		}
		if !AsKind(err, KindIncomplete) && i >= 8 && !bytes.Equal(enc[:8], RecordMagic[:]) {
			// magic mutilation not applicable for prefixes of valid encoding
		}
		if i < 8 {
			if !AsKind(err, KindIncomplete) {
				t.Fatalf("offset %d: want incomplete, got %v", i, err)
			}
			continue
		}
		// Valid magic prefixes that are short are incomplete.
		if !AsKind(err, KindIncomplete) {
			t.Fatalf("offset %d: want incomplete, got %v", i, err)
		}
	}
}

func TestDecodeIgnoresTrailing(t *testing.T) {
	f := testFields(1, []byte("x"))
	enc, err := EncodeRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	buf := append(append([]byte{}, enc...), 0xde, 0xad)
	rec, n, err := DecodeRecord(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(enc) || rec.Sequence != 1 {
		t.Fatalf("n=%d seq=%d", n, rec.Sequence)
	}
}

func TestGenesisPreviousMustBeZero(t *testing.T) {
	f := testFields(1, nil)
	f.PreviousCommitment[0] = 1
	_, err := EncodeRecord(f)
	if !AsKind(err, KindNonCanonical) {
		t.Fatalf("want non-canonical, got %v", err)
	}
}

func TestEmptyPayload(t *testing.T) {
	f := testFields(1, nil)
	enc, err := EncodeRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != RecordOverhead {
		t.Fatalf("len=%d", len(enc))
	}
	_, _, err = DecodeRecord(enc)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMaxPayloadRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, MaxPayloadBytes)
	f := testFields(1, payload)
	enc, err := EncodeRecord(f)
	if err != nil {
		t.Fatal(err)
	}
	rec, n, err := DecodeRecord(enc)
	if err != nil {
		t.Fatal(err)
	}
	if n != MaxRecordBytes || !bytes.Equal(rec.Payload, payload) {
		t.Fatalf("n=%d payload mismatch", n)
	}
}
