package protocol_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/protocol"
	"github.com/gpicchiarelli/integris/internal/session"
)

// TestHostilePeerRefuseMatrix consolidates Driver-wire fail-closed cases for the
// M3 prelude (IP-C-0002 / IP-P-0001): hostile negotiate, auth, sequencing, MAC,
// and early data must not advance the victim session into ACTIVE.
func TestHostilePeerRefuseMatrix(t *testing.T) {
	mac := []byte("0123456789abcdef")
	root := bytes.Repeat([]byte{0xab}, 32)
	suites := []string{crypto.SuiteIDAEAD}

	type step struct {
		name       string
		setup      func(t *testing.T) (victim *protocol.Driver, raw []byte)
		wantFailed bool
	}

	cases := []step{
		{
			name: "unknown_suite_offer",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				var sid [16]byte
				sid[0] = 1
				victim := protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, sid, mac, true)
				body, err := protocol.EncodeNegotiateOfferBody([]session.Version{2, 3}, []string{"unknown-suite-only"})
				if err != nil {
					t.Fatal(err)
				}
				raw, err := protocol.NewDriver([]session.Version{2}, sid, mac, true).EncodeFrame(protocol.TypeNegotiateOffer, body)
				if err != nil {
					t.Fatal(err)
				}
				return victim, raw
			},
			wantFailed: true,
		},
		{
			name: "no_common_version",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				var sid [16]byte
				sid[0] = 2
				victim := protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, sid, mac, true)
				body, err := protocol.EncodeNegotiateOfferBody([]session.Version{1}, suites)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := protocol.NewDriver([]session.Version{1}, sid, mac, true).EncodeFrame(protocol.TypeNegotiateOffer, body)
				if err != nil {
					t.Fatal(err)
				}
				return victim, raw
			},
			wantFailed: true,
		},
		{
			name: "accept_suite_mismatch",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				var sid [16]byte
				sid[0] = 3
				victim := protocol.NewDriverWithSuites([]session.Version{3, 2}, suites, sid, mac, true)
				if err := victim.Session.Negotiate(); err != nil {
					t.Fatal(err)
				}
				body, err := protocol.EncodeNegotiateAcceptBody(3, "hostile-suite")
				if err != nil {
					t.Fatal(err)
				}
				raw, err := protocol.NewDriver([]session.Version{3}, sid, mac, true).EncodeFrame(protocol.TypeNegotiateAccept, body)
				if err != nil {
					t.Fatal(err)
				}
				return victim, raw
			},
			wantFailed: true,
		},
		{
			name: "accept_version_mismatch",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				var sid [16]byte
				sid[0] = 4
				victim := protocol.NewDriverWithSuites([]session.Version{3, 2}, suites, sid, mac, true)
				if err := victim.Session.Negotiate(); err != nil {
					t.Fatal(err)
				}
				body, err := protocol.EncodeNegotiateAcceptBody(2, crypto.SuiteIDAEAD)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := protocol.NewDriver([]session.Version{2}, sid, mac, true).EncodeFrame(protocol.TypeNegotiateAccept, body)
				if err != nil {
					t.Fatal(err)
				}
				return victim, raw
			},
			wantFailed: true,
		},
		{
			name: "truncated_offer_body",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				var sid [16]byte
				sid[0] = 5
				victim := protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, sid, mac, true)
				raw, err := protocol.NewDriver([]session.Version{2}, sid, mac, true).EncodeFrame(protocol.TypeNegotiateOffer, []byte{2, 3})
				if err != nil {
					t.Fatal(err)
				}
				return victim, raw
			},
		},
		{
			name: "session_id_mismatch",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				var sid, other [16]byte
				sid[0] = 6
				other[0] = 99
				victim := protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, sid, mac, true)
				raw, err := protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, other, mac, true).EncodeNegotiateOffer([]session.Version{2, 3})
				if err != nil {
					t.Fatal(err)
				}
				return victim, raw
			},
		},
		{
			name: "sequence_gap",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				var sid [16]byte
				sid[0] = 7
				victim := protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, sid, mac, true)
				body, err := protocol.EncodeNegotiateOfferBody([]session.Version{2, 3}, suites)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := protocol.Encode(protocol.Frame{
					Type: protocol.TypeNegotiateOffer, SessionID: sid, Sequence: 2,
					Body: body, Flags: protocol.FlagRequiresMAC,
				}, mac)
				if err != nil {
					t.Fatal(err)
				}
				return victim, raw
			},
		},
		{
			name: "mac_tamper",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				var sid [16]byte
				sid[0] = 8
				victim := protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, sid, mac, true)
				raw, err := protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, sid, mac, true).EncodeNegotiateOffer([]session.Version{2, 3})
				if err != nil {
					t.Fatal(err)
				}
				raw = append([]byte{}, raw...)
				raw[len(raw)-1] ^= 0xff
				return victim, raw
			},
		},
		{
			name: "unknown_critical_type",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				var sid [16]byte
				sid[0] = 9
				victim := protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, sid, mac, true)
				body, err := protocol.EncodeNegotiateOfferBody([]session.Version{2, 3}, suites)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := protocol.Encode(protocol.Frame{
					Type: protocol.TypeNegotiateOffer, SessionID: sid, Sequence: 1,
					Body: body, Flags: protocol.FlagRequiresMAC,
				}, mac)
				if err != nil {
					t.Fatal(err)
				}
				raw = append([]byte{}, raw...)
				raw[10], raw[11] = 0x99, 0x00
				copy(raw[len(raw)-32:], frameMAC(mac, raw[:len(raw)-32]))
				return victim, raw
			},
		},
		{
			name: "bad_peer_auth_hmac",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				victim, peer := negotiatedPair(t, mac, suites, 10)
				authKey, err := crypto.PeerAuthKey(root, victim.SessionID)
				if err != nil {
					t.Fatal(err)
				}
				victim.AuthKey = authKey
				peer.AuthKey = authKey
				peer.AuthDir = "i2r"
				raw, err := peer.EncodePeerAuth()
				if err != nil {
					t.Fatal(err)
				}
				raw = append([]byte{}, raw...)
				raw[42+3] ^= 0x01
				copy(raw[len(raw)-32:], frameMAC(mac, raw[:len(raw)-32]))
				return victim, raw
			},
			wantFailed: true,
		},
		{
			name: "invalid_peer_auth_direction",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				victim, _ := negotiatedPair(t, mac, suites, 11)
				authKey, err := crypto.PeerAuthKey(root, victim.SessionID)
				if err != nil {
					t.Fatal(err)
				}
				victim.AuthKey = authKey
				body := append([]byte("xxx"), bytes.Repeat([]byte{1}, 32)...)
				raw, err := protocol.NewDriver([]session.Version{3}, victim.SessionID, mac, true).EncodeFrame(protocol.TypePeerAuth, body)
				if err != nil {
					t.Fatal(err)
				}
				return victim, raw
			},
		},
		{
			name: "duplicate_peer_auth_i2r",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				victim, peer := negotiatedPair(t, mac, suites, 12)
				authKey, err := crypto.PeerAuthKey(root, victim.SessionID)
				if err != nil {
					t.Fatal(err)
				}
				victim.AuthKey, peer.AuthKey = authKey, authKey
				peer.AuthDir = "i2r"
				raw, err := peer.EncodePeerAuth()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := victim.DecodeAndHandle(raw); err != nil {
					t.Fatal(err)
				}
				proof, err := victim.Session.MakeAuthProof(authKey, victim.SessionID, "i2r")
				if err != nil {
					t.Fatal(err)
				}
				raw2, err := protocol.Encode(protocol.Frame{
					Type: protocol.TypePeerAuth, SessionID: victim.SessionID, Sequence: victim.RecvSeq,
					Body: protocol.EncodePeerAuthBody("i2r", proof), Flags: protocol.FlagRequiresMAC,
				}, mac)
				if err != nil {
					t.Fatal(err)
				}
				return victim, raw2
			},
			wantFailed: true,
		},
		{
			name: "bad_archive_auth",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				victim, peer := mutualPeerAuth(t, mac, root, suites, 13)
				archKey, err := crypto.ArchiveAuthKey(root, victim.SessionID)
				if err != nil {
					t.Fatal(err)
				}
				victim.ArchiveKey = archKey
				raw, err := peer.EncodeFrame(protocol.TypeArchiveAuth, bytes.Repeat([]byte{0x5a}, 32))
				if err != nil {
					t.Fatal(err)
				}
				return victim, raw
			},
			wantFailed: true,
		},
		{
			name: "data_before_activate",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				victim, peer := negotiatedPair(t, mac, suites, 14)
				raw, err := peer.EncodeFrame(protocol.TypeData, []byte("early"))
				if err != nil {
					t.Fatal(err)
				}
				return victim, raw
			},
		},
		{
			name: "aead_tamper_after_activate",
			setup: func(t *testing.T) (*protocol.Driver, []byte) {
				t.Helper()
				victim, peer := activatedPair(t, mac, root, suites, 15)
				if err := victim.InstallTrafficKey(root); err != nil {
					t.Fatal(err)
				}
				if err := peer.InstallTrafficKey(root); err != nil {
					t.Fatal(err)
				}
				raw, err := peer.EncodeFrame(protocol.TypeData, []byte("seal-me"))
				if err != nil {
					t.Fatal(err)
				}
				raw = append([]byte{}, raw...)
				raw[42] ^= 0x01
				copy(raw[len(raw)-32:], frameMAC(mac, raw[:len(raw)-32]))
				return victim, raw
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			victim, raw := tc.setup(t)
			before := victim.Session.State
			_, err := victim.DecodeAndHandle(raw)
			if err == nil {
				t.Fatalf("expected refuse from state %s", before)
			}
			if tc.wantFailed && victim.Session.State != session.StateFailed {
				t.Fatalf("want FAILED, got %s (err=%v)", victim.Session.State, err)
			}
			if before != session.StateActive && victim.Session.State == session.StateActive {
				t.Fatalf("hostile frame advanced to ACTIVE")
			}
		})
	}
}

func frameMAC(key, body []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(body)
	return m.Sum(nil)
}

func negotiatedPair(t *testing.T, mac []byte, suites []string, sid0 byte) (victim, peer *protocol.Driver) {
	t.Helper()
	var sid [16]byte
	sid[0] = sid0
	victim = protocol.NewDriverWithSuites([]session.Version{3, 2}, suites, sid, mac, true)
	peer = protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, sid, mac, true)
	offer, err := peer.EncodeNegotiateOffer([]session.Version{2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := victim.DecodeAndHandle(offer); err != nil {
		t.Fatal(err)
	}
	accept, err := victim.EncodeNegotiateAccept()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.DecodeAndHandle(accept); err != nil {
		t.Fatal(err)
	}
	return victim, peer
}

func mutualPeerAuth(t *testing.T, mac, root []byte, suites []string, sid0 byte) (victim, peer *protocol.Driver) {
	t.Helper()
	victim, peer = negotiatedPair(t, mac, suites, sid0)
	authKey, err := crypto.PeerAuthKey(root, victim.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	victim.AuthKey, peer.AuthKey = authKey, authKey
	peer.AuthDir, victim.AuthDir = "i2r", "r2i"
	raw, err := peer.EncodePeerAuth()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := victim.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	raw, err = victim.EncodePeerAuth()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	return victim, peer
}

func activatedPair(t *testing.T, mac, root []byte, suites []string, sid0 byte) (victim, peer *protocol.Driver) {
	t.Helper()
	victim, peer = mutualPeerAuth(t, mac, root, suites, sid0)
	archKey, err := crypto.ArchiveAuthKey(root, victim.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	victim.ArchiveKey, peer.ArchiveKey = archKey, archKey
	raw, err := peer.EncodeArchiveAuth()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := victim.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if victim.Session.State != session.StateArchiveAuthorized || peer.Session.State != session.StateArchiveAuthorized {
		t.Fatalf("archive auth incomplete: victim=%s peer=%s", victim.Session.State, peer.Session.State)
	}
	raw, err = peer.EncodeFrame(protocol.TypeActivate, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := victim.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if err := peer.Session.Activate(); err != nil {
		t.Fatal(err)
	}
	return victim, peer
}
