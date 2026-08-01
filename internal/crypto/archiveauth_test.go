package crypto_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/crypto"
)

func TestArchiveAuthProofRoundTrip(t *testing.T) {
	root := bytes.Repeat([]byte{0x44}, 32)
	var sid [16]byte
	sid[3] = 9
	key, err := crypto.ArchiveAuthKey(root, sid)
	if err != nil {
		t.Fatal(err)
	}
	var dig codec.Digest
	copy(dig[:], bytes.Repeat([]byte{0x7a}, 32))
	proof, err := crypto.ArchiveAuthProof(key, dig, sid)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.VerifyArchiveAuthProof(key, dig, sid, proof); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte{}, proof...)
	bad[0] ^= 1
	if err := crypto.VerifyArchiveAuthProof(key, dig, sid, bad); err == nil {
		t.Fatal("expected mismatch")
	}
}
