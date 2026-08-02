package remotesync_test

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/gpicchiarelli/integris/internal/remotesync"
)

func TestKeyringRoundTrip(t *testing.T) {
	a := make([]byte, remotesync.RootKeySize)
	b := make([]byte, remotesync.RootKeySize)
	_, _ = rand.Read(a)
	_, _ = rand.Read(b)
	kr := remotesync.PeerKeyring{"alice": a, "bob": b}
	enc, err := remotesync.EncodeKeyring(kr)
	if err != nil {
		t.Fatal(err)
	}
	single, got, err := remotesync.DecodeRootMaterial(enc)
	if err != nil || single != nil {
		t.Fatalf("single=%v err=%v", single, err)
	}
	if !bytes.Equal(got["alice"], a) || !bytes.Equal(got["bob"], b) {
		t.Fatalf("%v", got)
	}
}

func TestPeerAllowListHandshake(t *testing.T) {
	alice := make([]byte, remotesync.RootKeySize)
	bob := make([]byte, remotesync.RootKeySize)
	_, _ = rand.Read(alice)
	_, _ = rand.Read(bob)
	kr := remotesync.PeerKeyring{"alice": alice, "bob": bob}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()
		sess, _, err := remotesync.AcceptHandshakeKeyring(c, kr)
		if err != nil {
			errCh <- err
			return
		}
		_ = sess.Close()
		errCh <- nil
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := remotesync.DialHandshake(conn, alice, "alice")
	if err != nil {
		t.Fatal(err)
	}
	_ = sess.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestPeerAllowListUnknownRejected(t *testing.T) {
	alice := make([]byte, remotesync.RootKeySize)
	_, _ = rand.Read(alice)
	kr := remotesync.PeerKeyring{"alice": alice}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()
		_, _, err = remotesync.AcceptHandshakeKeyring(c, kr)
		errCh <- err
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = remotesync.DialHandshake(conn, alice, "eve")
	_ = conn.Close()
	if err == nil {
		t.Fatal("expected dial failure")
	}
	serveErr := <-errCh
	if serveErr == nil {
		t.Fatal("expected serve rejection")
	}
}
