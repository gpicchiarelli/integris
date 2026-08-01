package journal

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal/verify"
)

func FuzzReadPrefix(f *testing.F) {
	seg := NewMemSegment()
	w, _, err := OpenWriter(seg)
	if err != nil {
		f.Fatal(err)
	}
	_, _ = w.Append(txid(1), codec.TypeObservation, []byte("seed"))
	_, _ = w.Append(txid(2), codec.TypeProgress, []byte("data"))
	full := seg.Bytes()
	f.Add(full)
	f.Add(full[:len(full)/2])
	f.Add([]byte{})
	f.Add([]byte("INTJRN01"))
	f.Add(append(append([]byte{}, full...), 0x00))

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ReadPrefixBytes(data)
		vr := verify.VerifyBytes(data)
		if err != nil {
			if !IsFatal(err) {
				t.Fatalf("non-fatal error %v", err)
			}
			if !vr.Fatal {
				t.Fatalf("reader fatal but verifier not: reader=%v verify=%+v", err, vr)
			}
			return
		}
		if vr.Fatal {
			t.Fatalf("verifier fatal but reader ok: %+v", vr)
		}
		if p.Torn != vr.Torn || len(p.Records) != vr.RecordCount || p.Bytes != vr.Bytes {
			t.Fatalf("divergence reader=%+v verify=%+v", p, vr)
		}
		if p.HeadCommitment != vr.HeadCommitment || p.NextSequence != vr.NextSequence {
			t.Fatalf("head/seq divergence")
		}
		// Accepted prefix must re-verify cleanly with no torn when sliced.
		if p.Bytes > 0 {
			clean := verify.VerifyBytes(data[:p.Bytes])
			if clean.Fatal || clean.Torn || clean.RecordCount != vr.RecordCount {
				t.Fatalf("clean prefix verify %+v", clean)
			}
		}
	})
}
