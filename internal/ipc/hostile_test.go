package ipc_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/ipc"
)

// TestHostileIPCRefuseMatrix consolidates fail-closed Decode/Encode cases for
// IP-A-0002 / VER-ARCH-001: forged MAC, truncation, role/nonce/sequence abuse,
// critical types, and post-close traffic must not be accepted as live frames.
func TestHostileIPCRefuseMatrix(t *testing.T) {
	key := []byte("0123456789abcdef")
	var nonce [16]byte
	nonce[0] = 0x2a

	type step struct {
		name     string
		setup    func(t *testing.T) (victim ipc.ChannelState, raw []byte, encode bool)
		wantCode string
	}

	cases := []step{
		{
			name: "tampered_mac",
			setup: func(t *testing.T) (ipc.ChannelState, []byte, bool) {
				t.Helper()
				send, err := ipc.NewAuthenticatedChannel(authority.RolePlan, authority.RoleApply, nonce, key)
				if err != nil {
					t.Fatal(err)
				}
				recv, err := ipc.NewAuthenticatedChannel(authority.RoleApply, authority.RolePlan, nonce, key)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := send.Encode(ipc.TypeRequest, []byte("x"))
				if err != nil {
					t.Fatal(err)
				}
				raw[len(raw)-1] ^= 0xff
				return recv, raw, false
			},
			wantCode: "mac",
		},
		{
			name: "wrong_mac_key",
			setup: func(t *testing.T) (ipc.ChannelState, []byte, bool) {
				t.Helper()
				send, err := ipc.NewAuthenticatedChannel(authority.RolePlan, authority.RoleApply, nonce, key)
				if err != nil {
					t.Fatal(err)
				}
				recv, err := ipc.NewAuthenticatedChannel(authority.RoleApply, authority.RolePlan, nonce, []byte("fedcba9876543210"))
				if err != nil {
					t.Fatal(err)
				}
				raw, err := send.Encode(ipc.TypeRequest, []byte("x"))
				if err != nil {
					t.Fatal(err)
				}
				return recv, raw, false
			},
			wantCode: "mac",
		},
		{
			name: "truncated_frame",
			setup: func(t *testing.T) (ipc.ChannelState, []byte, bool) {
				t.Helper()
				recv, err := ipc.NewAuthenticatedChannel(authority.RoleApply, authority.RolePlan, nonce, key)
				if err != nil {
					t.Fatal(err)
				}
				return recv, []byte{1, 2, 3, 4}, false
			},
			wantCode: "trunc",
		},
		{
			name: "bad_magic",
			setup: func(t *testing.T) (ipc.ChannelState, []byte, bool) {
				t.Helper()
				send, err := ipc.NewAuthenticatedChannel(authority.RolePlan, authority.RoleApply, nonce, key)
				if err != nil {
					t.Fatal(err)
				}
				recv, err := ipc.NewAuthenticatedChannel(authority.RoleApply, authority.RolePlan, nonce, key)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := send.Encode(ipc.TypeRequest, []byte("x"))
				if err != nil {
					t.Fatal(err)
				}
				raw[0] ^= 0x01
				return recv, raw, false
			},
			wantCode: "magic",
		},
		{
			name: "version_mismatch",
			setup: func(t *testing.T) (ipc.ChannelState, []byte, bool) {
				t.Helper()
				// Cleartext channels so a version bump is observed before MAC checks.
				send := ipc.NewChannel(authority.RolePlan, authority.RoleApply, nonce)
				recv := ipc.NewChannel(authority.RoleApply, authority.RolePlan, nonce)
				raw, err := send.Encode(ipc.TypeRequest, []byte("x"))
				if err != nil {
					t.Fatal(err)
				}
				raw[8] = 0xFF
				raw[9] = 0xFF
				return recv, raw, false
			},
			wantCode: "version",
		},
		{
			name: "nonce_mismatch",
			setup: func(t *testing.T) (ipc.ChannelState, []byte, bool) {
				t.Helper()
				var other [16]byte
				other[0] = 0x99
				send := ipc.NewChannel(authority.RolePlan, authority.RoleApply, nonce)
				recv := ipc.NewChannel(authority.RoleApply, authority.RolePlan, other)
				raw, err := send.Encode(ipc.TypeRequest, []byte("x"))
				if err != nil {
					t.Fatal(err)
				}
				return recv, raw, false
			},
			wantCode: "nonce",
		},
		{
			name: "role_mismatch",
			setup: func(t *testing.T) (ipc.ChannelState, []byte, bool) {
				t.Helper()
				send := ipc.NewChannel(authority.RoleNet, authority.RoleAuth, nonce)
				recv := ipc.NewChannel(authority.RoleParser, authority.RoleNet, nonce)
				raw, err := send.Encode(ipc.TypeRequest, []byte("x"))
				if err != nil {
					t.Fatal(err)
				}
				return recv, raw, false
			},
			wantCode: "role",
		},
		{
			name: "sequence_replay",
			setup: func(t *testing.T) (ipc.ChannelState, []byte, bool) {
				t.Helper()
				send := ipc.NewChannel(authority.RoleJournal, authority.RoleAudit, nonce)
				recv := ipc.NewChannel(authority.RoleAudit, authority.RoleJournal, nonce)
				raw, err := send.Encode(ipc.TypeRequest, []byte("a"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := recv.Decode(raw); err != nil {
					t.Fatal(err)
				}
				return recv, raw, false
			},
			wantCode: "sequence",
		},
		{
			name: "sequence_skip",
			setup: func(t *testing.T) (ipc.ChannelState, []byte, bool) {
				t.Helper()
				send := ipc.NewChannel(authority.RoleJournal, authority.RoleAudit, nonce)
				recv := ipc.NewChannel(authority.RoleAudit, authority.RoleJournal, nonce)
				if _, err := send.Encode(ipc.TypeRequest, []byte("a")); err != nil {
					t.Fatal(err)
				}
				raw, err := send.Encode(ipc.TypeRequest, []byte("b"))
				if err != nil {
					t.Fatal(err)
				}
				// Victim never saw seq=1; seq=2 must refuse.
				return recv, raw, false
			},
			wantCode: "sequence",
		},
		{
			name: "length_mismatch",
			setup: func(t *testing.T) (ipc.ChannelState, []byte, bool) {
				t.Helper()
				send := ipc.NewChannel(authority.RolePlan, authority.RoleApply, nonce)
				recv := ipc.NewChannel(authority.RoleApply, authority.RolePlan, nonce)
				raw, err := send.Encode(ipc.TypeRequest, []byte("abcd"))
				if err != nil {
					t.Fatal(err)
				}
				// Inflate declared payload length without extending bytes.
				raw[40] = 0xFF
				raw[41] = 0xFF
				raw[42] = 0
				raw[43] = 0
				return recv, raw, false
			},
			wantCode: "length",
		},
		{
			name: "type_critical",
			setup: func(t *testing.T) (ipc.ChannelState, []byte, bool) {
				t.Helper()
				send := ipc.NewChannel(authority.RolePlan, authority.RoleApply, nonce)
				recv := ipc.NewChannel(authority.RoleApply, authority.RolePlan, nonce)
				raw, err := send.Encode(ipc.TypeCritical, []byte("crit"))
				if err != nil {
					t.Fatal(err)
				}
				return recv, raw, false
			},
			wantCode: "critical",
		},
		{
			name: "post_close_decode",
			setup: func(t *testing.T) (ipc.ChannelState, []byte, bool) {
				t.Helper()
				send := ipc.NewChannel(authority.RoleSupervisor, authority.RoleNet, nonce)
				recv := ipc.NewChannel(authority.RoleNet, authority.RoleSupervisor, nonce)
				closeRaw, err := send.Encode(ipc.TypeClose, nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := recv.Decode(closeRaw); err != nil {
					t.Fatal(err)
				}
				// Replaying close after channel closed.
				return recv, closeRaw, false
			},
			wantCode: "closed",
		},
		{
			name: "post_close_encode",
			setup: func(t *testing.T) (ipc.ChannelState, []byte, bool) {
				t.Helper()
				ch := ipc.NewChannel(authority.RoleSupervisor, authority.RoleNet, nonce)
				if _, err := ch.Encode(ipc.TypeClose, nil); err != nil {
					t.Fatal(err)
				}
				return ch, nil, true
			},
			wantCode: "closed",
		},
		{
			name: "stream_truncated_prefix",
			setup: func(t *testing.T) (ipc.ChannelState, []byte, bool) {
				t.Helper()
				// Exercised below via ReadFrame; placeholder victim unused.
				return ipc.ChannelState{}, []byte{0x01, 0x00}, false
			},
			wantCode: "trunc",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "stream_truncated_prefix" {
				_, err := ipc.ReadFrame(bytes.NewReader([]byte{0x01, 0x00}), 0)
				if err == nil {
					t.Fatal("expected truncated stream refuse")
				}
				return
			}
			victim, raw, encode := tc.setup(t)
			var err error
			if encode {
				_, err = victim.Encode(ipc.TypeRequest, []byte("late"))
			} else {
				_, err = victim.Decode(raw)
			}
			var e *ipc.Error
			if err == nil || !asIPC(err, &e) || e.Code != tc.wantCode {
				t.Fatalf("got %v want code %q", err, tc.wantCode)
			}
			if !e.Close {
				t.Fatalf("expected Close=true for %q: %+v", tc.name, e)
			}
		})
	}
}
