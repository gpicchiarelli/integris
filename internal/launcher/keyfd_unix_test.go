//go:build unix

package launcher_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/gpicchiarelli/integris/internal/launcher"
)

func TestCreateKeyFDRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)
	f, kind, err := launcher.CreateKeyFD(key)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if kind != launcher.KeyTransportMemfd && kind != launcher.KeyTransportAnonFile {
		t.Fatalf("unexpected transport %q", kind)
	}
	got, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("got %x want %x", got, key)
	}
}

func TestCreateKeyFDRejectsShort(t *testing.T) {
	_, _, err := launcher.CreateKeyFD([]byte("short"))
	if err == nil {
		t.Fatal("expected error")
	}
}
