package verify

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
)

func TestVerifyGoldenVector(t *testing.T) {
	enc, err := codec.EncodeRecord(codec.RecordFields{
		Sequence:           1,
		Type:               codec.TypeEvidenceReference,
		PreviousCommitment: codec.GenesisCommitment(),
		Payload:            []byte("vector"),
	})
	if err != nil {
		t.Fatal(err)
	}
	res := VerifyBytes(enc)
	if res.Fatal || res.Torn || res.RecordCount != 1 {
		t.Fatalf("%+v", res)
	}
	rec, _, err := codec.DecodeRecord(enc)
	if err != nil {
		t.Fatal(err)
	}
	if res.HeadCommitment != rec.RecordCommitment {
		t.Fatal("commitment mismatch")
	}
}
