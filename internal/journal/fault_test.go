package journal

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal/verify"
)

// buildJournal returns a segment with two committed records.
func buildJournal(t *testing.T) (*MemSegment, []byte) {
	t.Helper()
	seg := NewMemSegment()
	w, _, err := OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(txid(1), codec.TypeObservation, []byte("record-one-payload")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(txid(2), codec.TypeConfirmation, []byte("record-two-payload")); err != nil {
		t.Fatal(err)
	}
	return seg, seg.Bytes()
}

func TestTruncationEveryOffset(t *testing.T) {
	_, full := buildJournal(t)
	for i := 0; i < len(full); i++ {
		p, err := ReadPrefixBytes(full[:i])
		if err != nil {
			t.Fatalf("truncate %d: fatal %v", i, err)
		}
		vr := verify.VerifyBytes(full[:i])
		if vr.Fatal {
			t.Fatalf("truncate %d: verifier fatal %v", i, vr.Err)
		}
		if p.Torn != vr.Torn || len(p.Records) != vr.RecordCount || p.Bytes != vr.Bytes {
			t.Fatalf("truncate %d: reader=%+v verify=%+v", i, p, vr)
		}
		// Empty or exact record boundaries may be clean; otherwise torn.
		if i == 0 {
			if p.Torn || len(p.Records) != 0 {
				t.Fatalf("empty: %+v", p)
			}
			continue
		}
		// Find how many complete records fit.
		complete := 0
		off := 0
		for off < i {
			_, n, derr := codec.DecodeRecord(full[off:i])
			if derr != nil {
				break
			}
			complete++
			off += n
		}
		if complete != len(p.Records) {
			t.Fatalf("truncate %d: complete=%d got=%d", i, complete, len(p.Records))
		}
		if off < i && !p.Torn {
			t.Fatalf("truncate %d: expected torn at %d", i, off)
		}
		if off == i && p.Torn {
			t.Fatalf("truncate %d: unexpected torn at boundary", i)
		}
	}
}

func TestInteriorCorruptionFatal(t *testing.T) {
	_, full := buildJournal(t)
	// Corrupt a byte inside the first record (not in a torn tail).
	for _, off := range []int{0, 16, 44, 76, 108, len(full) / 4} {
		mut := append([]byte{}, full...)
		mut[off] ^= 0xff
		_, err := ReadPrefixBytes(mut)
		if err == nil || !IsFatal(err) {
			t.Fatalf("offset %d: want fatal, got %v", off, err)
		}
		vr := verify.VerifyBytes(mut)
		if !vr.Fatal {
			t.Fatalf("offset %d: verifier want fatal, got %+v", off, vr)
		}
	}
}

func TestCorruptSecondRecordFatal(t *testing.T) {
	_, full := buildJournal(t)
	// Locate start of second record.
	_, n1, err := codec.DecodeRecord(full)
	if err != nil {
		t.Fatal(err)
	}
	mut := append([]byte{}, full...)
	mut[n1+8] ^= 0x01 // flip in format_version of record 2
	_, err = ReadPrefixBytes(mut)
	if err == nil || !IsFatal(err) {
		t.Fatalf("want fatal, got %v", err)
	}
}

func TestCorruptLastCompleteRecordFatal(t *testing.T) {
	_, full := buildJournal(t)
	mut := append([]byte{}, full...)
	mut[len(mut)-1] ^= 0x01 // trailer length low byte
	_, err := ReadPrefixBytes(mut)
	if err == nil || !IsFatal(err) {
		t.Fatalf("want fatal on complete corrupt tail, got %v", err)
	}
}

func TestTornTailAccepted(t *testing.T) {
	_, full := buildJournal(t)
	_, n1, err := codec.DecodeRecord(full)
	if err != nil {
		t.Fatal(err)
	}
	// Keep first record + partial second.
	partial := full[:n1+10]
	p, err := ReadPrefixBytes(partial)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Torn || len(p.Records) != 1 || p.Bytes != int64(n1) {
		t.Fatalf("%+v", p)
	}
	if p.TornOffset != int64(n1) {
		t.Fatalf("torn offset %d want %d", p.TornOffset, n1)
	}
	vr := verify.VerifyBytes(partial)
	if !vr.Torn || vr.RecordCount != 1 || vr.Fatal {
		t.Fatalf("verify %+v", vr)
	}
}

func TestSequenceGapFatal(t *testing.T) {
	seg := NewMemSegment()
	w, _, err := OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	r1, err := w.Append(txid(1), codec.TypeObservation, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	// Manually encode sequence 3 chained from r1 (gap).
	enc, err := codec.EncodeRecord(codec.RecordFields{
		Sequence:           3,
		TransactionID:      txid(3),
		Type:               codec.TypeObservation,
		PreviousCommitment: r1.RecordCommitment,
		Payload:            []byte("gap"),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = seg.Append(enc)
	_, err = ReadPrefix(seg)
	if err == nil || !IsFatal(err) {
		t.Fatalf("want fatal gap, got %v", err)
	}
}

func TestCommitmentForkFatal(t *testing.T) {
	seg := NewMemSegment()
	w, _, err := OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(txid(1), codec.TypeObservation, []byte("a")); err != nil {
		t.Fatal(err)
	}
	var bogus codec.Digest
	bogus[0] = 0x99
	enc, err := codec.EncodeRecord(codec.RecordFields{
		Sequence:           2,
		TransactionID:      txid(2),
		Type:               codec.TypeObservation,
		PreviousCommitment: bogus,
		Payload:            []byte("fork"),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = seg.Append(enc)
	_, err = ReadPrefix(seg)
	if err == nil || !IsFatal(err) {
		t.Fatalf("want fatal fork, got %v", err)
	}
}
