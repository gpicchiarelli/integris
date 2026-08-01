package crypto_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
)

func TestHKDFKnownAnswer(t *testing.T) {
	// RFC 5869 A.1 truncated check: IKDF with SHA-256, salt/info as published.
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	want, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	got, err := crypto.HKDFSHA256(ikm, salt, info, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
}

func TestChannelMACKeySymmetric(t *testing.T) {
	root := bytes.Repeat([]byte{0x42}, 32)
	a, err := crypto.ChannelMACKey(root, "integrisd-net", "integrisd-parser")
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypto.ChannelMACKey(root, "integrisd-parser", "integrisd-net")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("pair key not symmetric")
	}
	c, err := crypto.ChannelMACKey(root, "integrisd-net", "integrisd-auth")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Fatal("distinct pairs must differ")
	}
}

func TestTranscriptDomain(t *testing.T) {
	t1 := crypto.NewTranscript()
	if err := t1.Append("a", []byte("bc")); err != nil {
		t.Fatal(err)
	}
	t2 := crypto.NewTranscript()
	if err := t2.Append("ab", []byte("c")); err != nil {
		t.Fatal(err)
	}
	if t1.Digest() == t2.Digest() {
		t.Fatal("length-prefix collision")
	}
}
