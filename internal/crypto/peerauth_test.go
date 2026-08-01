package crypto_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
)

func TestPeerAuthProof(t *testing.T) {
	root := bytes.Repeat([]byte{0x44}, 32)
	var sid [16]byte
	sid[0] = 8
	key, err := crypto.PeerAuthKey(root, sid)
	if err != nil {
		t.Fatal(err)
	}
	tr := crypto.NewTranscript()
	_ = tr.Append("negotiate", []byte{3})
	dig := tr.Digest()
	proof, err := crypto.PeerAuthProof(key, dig, sid, "i2r")
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.VerifyPeerAuthProof(key, dig, sid, "i2r", proof); err != nil {
		t.Fatal(err)
	}
	if err := crypto.VerifyPeerAuthProof(key, dig, sid, "r2i", proof); err == nil {
		t.Fatal("expected direction mismatch")
	}
	proof[0] ^= 1
	if err := crypto.VerifyPeerAuthProof(key, dig, sid, "i2r", proof); err == nil {
		t.Fatal("expected proof mismatch")
	}
}
