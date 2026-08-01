package crypto_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
)

func TestSessionAEADRoundTrip(t *testing.T) {
	root := bytes.Repeat([]byte{0x11}, 32)
	var sid [16]byte
	sid[0] = 9
	key, err := crypto.SessionAEADKey(root, sid)
	if err != nil {
		t.Fatal(err)
	}
	nonce := crypto.SequenceNonce(1)
	aad := []byte("aad-v1")
	ct, err := crypto.Seal(key, nonce, aad, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := crypto.Open(key, nonce, aad, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello" {
		t.Fatalf("%q", pt)
	}
	if _, err := crypto.Open(key, nonce, []byte("bad"), ct); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestSessionAEADKeyDomain(t *testing.T) {
	root := bytes.Repeat([]byte{0x22}, 32)
	var a, b [16]byte
	a[0] = 1
	b[0] = 2
	ka, _ := crypto.SessionAEADKey(root, a)
	kb, _ := crypto.SessionAEADKey(root, b)
	if bytes.Equal(ka, kb) {
		t.Fatal("session keys must differ")
	}
}

func TestTrafficKeyTranscriptBound(t *testing.T) {
	root := bytes.Repeat([]byte{0x33}, 32)
	var sid [16]byte
	sid[0] = 1
	tr := crypto.NewTranscript()
	_ = tr.Append("negotiate", []byte{3})
	k1, err := crypto.TrafficKey(root, tr.Digest(), sid, crypto.SuiteIDAEAD)
	if err != nil {
		t.Fatal(err)
	}
	tr2 := crypto.NewTranscript()
	_ = tr2.Append("negotiate", []byte{2})
	k2, err := crypto.TrafficKey(root, tr2.Digest(), sid, crypto.SuiteIDAEAD)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("different transcripts must yield different keys")
	}
}
