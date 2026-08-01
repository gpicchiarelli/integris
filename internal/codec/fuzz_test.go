package codec

import "testing"

func FuzzDecodeRecord(f *testing.F) {
	enc, err := EncodeRecord(RecordFields{
		Sequence:           1,
		Type:               TypeObservation,
		PreviousCommitment: GenesisCommitment(),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(enc)
	f.Add(enc[:len(enc)/2])
	f.Add([]byte("INTJRN01"))
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})

	f.Fuzz(func(t *testing.T, data []byte) {
		rec, n, err := DecodeRecord(data)
		if err != nil {
			if _, ok := err.(*Error); !ok {
				t.Fatalf("unexpected error type %T: %v", err, err)
			}
			return
		}
		if n <= 0 || n > len(data) || n > MaxRecordBytes {
			t.Fatalf("invalid n=%d len=%d", n, len(data))
		}
		if int(rec.RecordLength) != n {
			t.Fatalf("RecordLength=%d n=%d", rec.RecordLength, n)
		}
		again, err := EncodeRecord(RecordFields{
			Sequence:           rec.Sequence,
			TransactionID:      rec.TransactionID,
			Type:               rec.Type,
			PreviousCommitment: rec.PreviousCommitment,
			Payload:            rec.Payload,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(again) != n {
			t.Fatalf("re-encode len %d want %d", len(again), n)
		}
		got, _, err := DecodeRecord(again)
		if err != nil {
			t.Fatal(err)
		}
		if got.RecordCommitment != rec.RecordCommitment {
			t.Fatal("commitment drift on round-trip")
		}
	})
}
