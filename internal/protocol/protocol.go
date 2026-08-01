// Package protocol implements the IP-P-0001 wire frame codec (engineering
// preview). Session AEAD is not claimed; HMAC-SHA256 is provisional per IP-C-0001.
package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/resource"
)

const (
	ProtocolVersion uint16 = 1
	HeaderBytes            = 42
	AuthBytes              = 32
	MaxBodyBytes           = 1 << 20
)

// FrameMagic is INTPRO01.
var FrameMagic = [8]byte{'I', 'N', 'T', 'P', 'R', 'O', '0', '1'}

// MessageType is an IP-P-0001 allow-list member.
type MessageType uint16

const (
	TypeNegotiateOffer  MessageType = 1
	TypeNegotiateAccept MessageType = 2
	TypePeerAuth        MessageType = 3
	TypeArchiveAuth     MessageType = 4
	TypeActivate        MessageType = 5
	TypeData            MessageType = 6
	TypeClose           MessageType = 7
	TypeFailure         MessageType = 8
)

// Flag bits.
const (
	FlagRequiresMAC uint16 = 1 << 0
)

// Frame is one decoded protocol frame.
type Frame struct {
	Version   uint16
	Type      MessageType
	Flags     uint16
	SessionID [16]byte
	Sequence  uint64
	Body      []byte
}

// Error is a typed protocol failure.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Code + ": " + e.Message
}

func fail(code, msg string) error { return &Error{Code: code, Message: msg} }

// CriticalUnknown reports whether t is outside the allow-list (fail closed).
func CriticalUnknown(t MessageType) bool {
	return !known(t)
}

func known(t MessageType) bool {
	return t >= TypeNegotiateOffer && t <= TypeFailure
}

// Encode builds a canonical frame. If macKey is non-nil or FlagRequiresMAC is
// set, a 32-byte HMAC-SHA256 authenticator is appended (key required).
func Encode(f Frame, macKey []byte) ([]byte, error) {
	if f.Version == 0 {
		f.Version = ProtocolVersion
	}
	if f.Version != ProtocolVersion {
		return nil, fail("version", "unsupported protocol version")
	}
	if !known(f.Type) {
		return nil, fail("type", "unknown message type")
	}
	if f.Flags&^FlagRequiresMAC != 0 {
		return nil, fail("flags", "reserved flags must be zero")
	}
	if len(f.Body) > MaxBodyBytes {
		return nil, fail("limit", "body exceeds MaxBodyBytes")
	}
	needMAC := f.Flags&FlagRequiresMAC != 0 || len(macKey) > 0
	if needMAC {
		f.Flags |= FlagRequiresMAC
		if len(macKey) < 16 {
			return nil, fail("mac", "MAC key required (min 16 bytes)")
		}
	}
	total := HeaderBytes + len(f.Body)
	if needMAC {
		total += AuthBytes
	}
	lim := resource.Limits{
		MaxBytes: MaxBodyBytes + HeaderBytes + AuthBytes, MaxCount: 1, MaxNesting: 1,
		MaxQueueDepth: 1, MaxConcurrent: 1, MaxRetries: 1,
	}
	if err := lim.AdmitBytes(uint64(total)); err != nil {
		return nil, fail("limit", err.Error())
	}

	buf := make([]byte, 0, total)
	buf = append(buf, FrameMagic[:]...)
	var tmp [8]byte
	codec.PutU16LE(tmp[:2], f.Version)
	buf = append(buf, tmp[:2]...)
	codec.PutU16LE(tmp[:2], uint16(f.Type))
	buf = append(buf, tmp[:2]...)
	codec.PutU16LE(tmp[:2], f.Flags)
	buf = append(buf, tmp[:2]...)
	binary.LittleEndian.PutUint32(tmp[:4], uint32(len(f.Body)))
	buf = append(buf, tmp[:4]...)
	buf = append(buf, f.SessionID[:]...)
	binary.LittleEndian.PutUint64(tmp[:], f.Sequence)
	buf = append(buf, tmp[:]...)
	buf = append(buf, f.Body...)
	if needMAC {
		buf = append(buf, macSHA256(macKey, buf)...)
	}
	return buf, nil
}

// Decode parses one frame. requireMAC forces authenticator verification.
func Decode(raw []byte, macKey []byte, requireMAC bool) (Frame, error) {
	var zero Frame
	min := HeaderBytes
	if requireMAC || len(macKey) > 0 {
		min += AuthBytes
	}
	if len(raw) < min {
		return zero, fail("trunc", "frame too short")
	}
	if string(raw[0:8]) != string(FrameMagic[:]) {
		return zero, fail("magic", "not INTPRO01")
	}
	ver := codec.U16LE(raw[8:10])
	if ver != ProtocolVersion {
		return zero, fail("version", fmt.Sprintf("unsupported %d", ver))
	}
	typ := MessageType(codec.U16LE(raw[10:12]))
	flags := codec.U16LE(raw[12:14])
	if flags&^FlagRequiresMAC != 0 {
		return zero, fail("flags", "reserved flags must be zero")
	}
	bodyLen := binary.LittleEndian.Uint32(raw[14:18])
	if bodyLen > MaxBodyBytes {
		return zero, fail("limit", "body_length exceeds MaxBodyBytes")
	}
	needMAC := requireMAC || flags&FlagRequiresMAC != 0 || len(macKey) > 0
	expect := HeaderBytes + int(bodyLen)
	if needMAC {
		expect += AuthBytes
	}
	if len(raw) != expect {
		return zero, fail("length", "frame length mismatch")
	}
	if !known(typ) {
		return zero, fail("critical", "unknown critical message type")
	}
	if needMAC {
		if len(macKey) < 16 {
			return zero, fail("mac", "MAC key required")
		}
		body := raw[:HeaderBytes+int(bodyLen)]
		want := raw[len(raw)-AuthBytes:]
		got := macSHA256(macKey, body)
		if subtle.ConstantTimeCompare(want, got) != 1 {
			return zero, fail("mac", "authenticator mismatch")
		}
	}
	var sid [16]byte
	copy(sid[:], raw[18:34])
	seq := binary.LittleEndian.Uint64(raw[34:42])
	body := append([]byte{}, raw[42:42+int(bodyLen)]...)
	return Frame{
		Version: ver, Type: typ, Flags: flags, SessionID: sid, Sequence: seq, Body: body,
	}, nil
}

func macSHA256(key, body []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(body)
	return m.Sum(nil)
}
