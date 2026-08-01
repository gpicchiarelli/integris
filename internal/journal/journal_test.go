package journal

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal/verify"
)

func txid(b byte) codec.TransactionID {
	var id codec.TransactionID
	id[0] = b
	return id
}

func TestWriterReaderRoundTrip(t *testing.T) {
	seg := NewMemSegment()
	w, p, err := OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	if p.NextSequence != 1 || len(p.Records) != 0 {
		t.Fatalf("empty prefix: %+v", p)
	}
	r1, err := w.Append(txid(1), codec.TypeObservation, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := w.Append(txid(2), codec.TypeProgress, []byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	if r1.Sequence != 1 || r2.Sequence != 2 {
		t.Fatalf("sequences %d %d", r1.Sequence, r2.Sequence)
	}
	if r2.PreviousCommitment != r1.RecordCommitment {
		t.Fatal("chain")
	}

	got, err := ReadPrefix(seg)
	if err != nil {
		t.Fatal(err)
	}
	if got.Torn || len(got.Records) != 2 || got.Bytes != seg.Size() {
		t.Fatalf("prefix: %+v", got)
	}
	vr := verify.VerifyBytes(seg.Bytes())
	if vr.Fatal || vr.Torn || vr.RecordCount != 2 || vr.Bytes != got.Bytes {
		t.Fatalf("verify: %+v", vr)
	}
	if vr.HeadCommitment != got.HeadCommitment {
		t.Fatal("verifier head mismatch")
	}
}

func TestOpenWriterResumes(t *testing.T) {
	seg := NewMemSegment()
	w, _, err := OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(txid(1), codec.TypeObservation, []byte("a")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	w2, p, err := OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	if p.NextSequence != 2 || len(p.Records) != 1 {
		t.Fatalf("resume prefix: %+v", p)
	}
	r, err := w2.Append(txid(2), codec.TypeCheckpoint, []byte("b"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Sequence != 2 {
		t.Fatalf("seq=%d", r.Sequence)
	}
}

func TestRefuseAppendWithTornTail(t *testing.T) {
	seg := NewMemSegment()
	w, _, err := OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(txid(1), codec.TypeObservation, []byte("full")); err != nil {
		t.Fatal(err)
	}
	// Append incomplete garbage as torn tail.
	_ = seg.Append([]byte("INTJRN01XXXX"))
	_, err = w.Append(txid(2), codec.TypeObservation, []byte("nope"))
	if err == nil || err.(*Error).Kind != KindState {
		t.Fatalf("want state error, got %v", err)
	}
	p, err := ReadPrefix(seg)
	if err != nil || !p.Torn {
		t.Fatalf("want torn prefix, got err=%v p=%+v", err, p)
	}
	seg.Truncate(p.Bytes)
	if _, err := w.Append(txid(2), codec.TypeObservation, []byte("ok")); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyJournal(t *testing.T) {
	p, err := ReadPrefixBytes(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.NextSequence != 1 || p.Torn {
		t.Fatalf("%+v", p)
	}
	vr := verify.VerifyBytes(nil)
	if vr.RecordCount != 0 || vr.NextSequence != 1 {
		t.Fatalf("%+v", vr)
	}
}

func TestPropertyRandomChain(t *testing.T) {
	seg := NewMemSegment()
	w, _, err := OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	const n = 20
	for i := 0; i < n; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, i+1)
		if _, err := w.Append(txid(byte(i)), codec.TypeObservation, payload); err != nil {
			t.Fatal(err)
		}
	}
	p, err := ReadPrefix(seg)
	if err != nil || p.Torn || len(p.Records) != n {
		t.Fatalf("prefix err=%v torn=%v n=%d", err, p.Torn, len(p.Records))
	}
	for i, r := range p.Records {
		if r.Sequence != uint64(i+1) {
			t.Fatalf("seq at %d", i)
		}
		if i > 0 && r.PreviousCommitment != p.Records[i-1].RecordCommitment {
			t.Fatalf("chain at %d", i)
		}
	}
}
