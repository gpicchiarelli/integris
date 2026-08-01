// Package ipc implements a bounded local IPC frame codec for the M2 prelude
// (docs/security-architecture.md local IPC contract, IP-A-0002, IP-C-0001).
//
// Frames are length-prefixed, role-bound, sequenced, and size-capped before
// allocation. When ChannelState.MACKey is set, frames carry a provisional
// HMAC-SHA256 trailer (engineering only; not a release crypto claim).
package ipc

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/resource"
)

// Defaults for M1/M2 prelude.
const (
	ProtocolVersion uint16 = 1
	MaxFrameBytes          = 1 << 20
	MaxQueueDepth          = 1024
	HeaderBytes            = 44 // magic(8)+ver(2)+type(2)+nonce(16)+seq(8)+roles(4)+len(4)
	MACBytes               = 32 // HMAC-SHA256
)

// FrameMagic is INTIPC01.
var FrameMagic = [8]byte{'I', 'N', 'T', 'I', 'P', 'C', '0', '1'}

// MessageType classifies the frame.
type MessageType uint16

const (
	TypeRequest  MessageType = 1
	TypeResponse MessageType = 2
	TypeClose    MessageType = 3
	TypeCritical MessageType = 4 // unknown critical → close channel
)

// Frame is one decoded IPC frame.
type Frame struct {
	Version      uint16
	Type         MessageType
	SessionNonce [16]byte
	Sequence     uint64
	Sender       authority.ProcessRole
	Receiver     authority.ProcessRole
	Payload      []byte
}

// ChannelState tracks monotonic sequence and peer roles.
type ChannelState struct {
	LocalRole    authority.ProcessRole
	RemoteRole   authority.ProcessRole
	SessionNonce [16]byte
	NextSendSeq  uint64
	LastRecvSeq  uint64
	MaxFrame     uint32
	MaxQueue     uint64
	QueueDepth   uint64
	Closed       bool
	// MACKey, when non-nil, requires HMAC-SHA256 over header||payload (IP-C-0001 provisional).
	MACKey []byte
}

// NewChannel constructs a channel without MAC (test / pre-key).
func NewChannel(local, remote authority.ProcessRole, nonce [16]byte) ChannelState {
	return ChannelState{
		LocalRole:    local,
		RemoteRole:   remote,
		SessionNonce: nonce,
		NextSendSeq:  1,
		LastRecvSeq:  0,
		MaxFrame:     MaxFrameBytes,
		MaxQueue:     MaxQueueDepth,
	}
}

// NewAuthenticatedChannel constructs a channel that MACs every frame.
func NewAuthenticatedChannel(local, remote authority.ProcessRole, nonce [16]byte, macKey []byte) (ChannelState, error) {
	if len(macKey) < 16 {
		return ChannelState{}, fail("mac", "MAC key must be at least 16 bytes", false)
	}
	ch := NewChannel(local, remote, nonce)
	ch.MACKey = append([]byte{}, macKey...)
	return ch, nil
}

// Error is a typed IPC failure; channel must close on security-relevant codes.
type Error struct {
	Code    string
	Message string
	Close   bool
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Code + ": " + e.Message
}

func fail(code, msg string, close bool) error {
	return &Error{Code: code, Message: msg, Close: close}
}

func (ch *ChannelState) macLen() int {
	if len(ch.MACKey) > 0 {
		return MACBytes
	}
	return 0
}

// Encode builds a canonical frame for sending on ch.
func (ch *ChannelState) Encode(typ MessageType, payload []byte) ([]byte, error) {
	if ch.Closed {
		return nil, fail("closed", "channel closed", true)
	}
	if typ < TypeRequest || typ > TypeCritical {
		return nil, fail("type", "invalid message type", true)
	}
	if uint64(len(payload)) > uint64(ch.MaxFrame) {
		return nil, fail("limit", "payload exceeds MaxFrame", true)
	}
	total := HeaderBytes + len(payload) + ch.macLen()
	limits := resource.Limits{
		MaxBytes: uint64(ch.MaxFrame) + HeaderBytes + MACBytes, MaxCount: 1, MaxNesting: 1,
		MaxQueueDepth: ch.MaxQueue, MaxConcurrent: 1, MaxRetries: 1,
	}
	if err := limits.AdmitBytes(uint64(total)); err != nil {
		return nil, fail("limit", err.Error(), true)
	}
	seq := ch.NextSendSeq
	buf := make([]byte, 0, total)
	buf = append(buf, FrameMagic[:]...)
	var tmp [8]byte
	codec.PutU16LE(tmp[:2], ProtocolVersion)
	buf = append(buf, tmp[:2]...)
	codec.PutU16LE(tmp[:2], uint16(typ))
	buf = append(buf, tmp[:2]...)
	buf = append(buf, ch.SessionNonce[:]...)
	binary.LittleEndian.PutUint64(tmp[:], seq)
	buf = append(buf, tmp[:]...)
	codec.PutU16LE(tmp[:2], roleCode(ch.LocalRole))
	buf = append(buf, tmp[:2]...)
	codec.PutU16LE(tmp[:2], roleCode(ch.RemoteRole))
	buf = append(buf, tmp[:2]...)
	binary.LittleEndian.PutUint32(tmp[:4], uint32(len(payload)))
	buf = append(buf, tmp[:4]...)
	buf = append(buf, payload...)
	if len(ch.MACKey) > 0 {
		buf = append(buf, macSHA256(ch.MACKey, buf)...)
	}
	ch.NextSendSeq = seq + 1
	if typ == TypeClose {
		ch.Closed = true
	}
	return buf, nil
}

// Decode parses one frame and enforces role/nonce/sequence/queue/MAC policy.
func (ch *ChannelState) Decode(raw []byte) (Frame, error) {
	var zero Frame
	if ch.Closed {
		return zero, fail("closed", "channel closed", true)
	}
	need := HeaderBytes + ch.macLen()
	if len(raw) < need {
		return zero, fail("trunc", "frame too short", true)
	}
	if string(raw[0:8]) != string(FrameMagic[:]) {
		return zero, fail("magic", "bad frame magic", true)
	}
	ver := codec.U16LE(raw[8:10])
	if ver != ProtocolVersion {
		return zero, fail("version", fmt.Sprintf("unsupported version %d", ver), true)
	}
	typ := MessageType(codec.U16LE(raw[10:12]))
	var nonce [16]byte
	copy(nonce[:], raw[12:28])
	if nonce != ch.SessionNonce {
		return zero, fail("nonce", "session nonce mismatch", true)
	}
	seq := binary.LittleEndian.Uint64(raw[28:36])
	sender := roleFromCode(codec.U16LE(raw[36:38]))
	receiver := roleFromCode(codec.U16LE(raw[38:40]))
	payLen := binary.LittleEndian.Uint32(raw[40:44])
	expect := HeaderBytes + int(payLen) + ch.macLen()
	if expect != len(raw) {
		return zero, fail("length", "length mismatch", true)
	}
	if payLen > ch.MaxFrame {
		return zero, fail("limit", "frame exceeds MaxFrame", true)
	}
	if len(ch.MACKey) > 0 {
		body := raw[:HeaderBytes+int(payLen)]
		want := raw[len(raw)-MACBytes:]
		got := macSHA256(ch.MACKey, body)
		if subtle.ConstantTimeCompare(want, got) != 1 {
			ch.Closed = true
			return zero, fail("mac", "HMAC verification failed", true)
		}
	}
	if sender != ch.RemoteRole || receiver != ch.LocalRole {
		return zero, fail("role", "peer role mismatch", true)
	}
	if seq != ch.LastRecvSeq+1 {
		return zero, fail("sequence", fmt.Sprintf("expected %d got %d", ch.LastRecvSeq+1, seq), true)
	}
	if err := resource.DefaultLimits().AdmitQueue(ch.QueueDepth + 1); err != nil {
		return zero, fail("queue", "queue depth exceeded", true)
	}
	if typ == TypeCritical {
		ch.Closed = true
		return zero, fail("critical", "unknown critical message", true)
	}
	payload := append([]byte{}, raw[HeaderBytes:HeaderBytes+int(payLen)]...)
	ch.LastRecvSeq = seq
	ch.QueueDepth++
	if typ == TypeClose {
		ch.Closed = true
	}
	return Frame{
		Version: ver, Type: typ, SessionNonce: nonce, Sequence: seq,
		Sender: sender, Receiver: receiver, Payload: payload,
	}, nil
}

func macSHA256(key, body []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(body)
	return m.Sum(nil)
}

func roleCode(r authority.ProcessRole) uint16 {
	switch r {
	case authority.RoleSupervisor:
		return 1
	case authority.RoleNet:
		return 2
	case authority.RoleAuth:
		return 3
	case authority.RoleParser:
		return 4
	case authority.RoleIndex:
		return 5
	case authority.RolePlan:
		return 6
	case authority.RoleApply:
		return 7
	case authority.RoleJournal:
		return 8
	case authority.RoleAudit:
		return 9
	default:
		return 0
	}
}

func roleFromCode(c uint16) authority.ProcessRole {
	switch c {
	case 1:
		return authority.RoleSupervisor
	case 2:
		return authority.RoleNet
	case 3:
		return authority.RoleAuth
	case 4:
		return authority.RoleParser
	case 5:
		return authority.RoleIndex
	case 6:
		return authority.RolePlan
	case 7:
		return authority.RoleApply
	case 8:
		return authority.RoleJournal
	case 9:
		return authority.RoleAudit
	default:
		return ""
	}
}
