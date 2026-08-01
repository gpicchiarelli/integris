package protocol

import (
	"fmt"

	"github.com/gpicchiarelli/integris/internal/session"
)

// Driver maps IP-P-0001 control frames onto the session state machine.
// Send and receive sequences are independent (per direction).
// This is not session AEAD; MAC is provisional (IP-C-0001).
type Driver struct {
	Session    session.Session
	SessionID  [16]byte
	SendSeq    uint64
	RecvSeq    uint64
	MACKey     []byte
	RequireMAC bool
}

// NewDriver constructs a driver in NEW with the peer's offered versions.
func NewDriver(offered []session.Version, sessionID [16]byte, macKey []byte, requireMAC bool) *Driver {
	return &Driver{
		Session:    session.New(offered),
		SessionID:  sessionID,
		SendSeq:    1,
		RecvSeq:    1,
		MACKey:     append([]byte{}, macKey...),
		RequireMAC: requireMAC,
	}
}

// Handle applies one inbound decoded frame to the session.
func (d *Driver) Handle(f Frame) error {
	if d == nil {
		return fail("driver", "nil driver")
	}
	if f.SessionID != d.SessionID {
		return fail("session", "session id mismatch")
	}
	if f.Sequence != d.RecvSeq {
		return fail("sequence", fmt.Sprintf("expected recv %d got %d", d.RecvSeq, f.Sequence))
	}
	if CriticalUnknown(f.Type) {
		return fail("critical", "unknown message type")
	}
	switch f.Type {
	case TypeNegotiateOffer:
		if len(f.Body) > 0 && d.Session.State == session.StateNew {
			vers := make([]session.Version, len(f.Body))
			for i, b := range f.Body {
				vers[i] = session.Version(b)
			}
			d.Session.Offered = vers
		}
		if d.Session.State == session.StateNew {
			if err := d.Session.Negotiate(); err != nil {
				return err
			}
		}
	case TypeNegotiateAccept:
		if d.Session.State == session.StateNew {
			if err := d.Session.Negotiate(); err != nil {
				return err
			}
		}
	case TypePeerAuth:
		if err := d.Session.Authenticate(); err != nil {
			return err
		}
	case TypeArchiveAuth:
		if err := d.Session.AuthorizeArchive(); err != nil {
			return err
		}
	case TypeActivate:
		if err := d.Session.Activate(); err != nil {
			return err
		}
	case TypeData:
		if err := d.Session.AcceptNext(); err != nil {
			return err
		}
	case TypeClose:
		if err := d.Session.Close(); err != nil {
			return err
		}
	case TypeFailure:
		d.Session.State = session.StateFailed
		return fail("peer", "peer failure frame")
	default:
		return fail("type", "unhandled message type")
	}
	d.RecvSeq++
	return nil
}

// EncodeFrame builds the next outbound frame and advances SendSeq on success.
func (d *Driver) EncodeFrame(typ MessageType, body []byte) ([]byte, error) {
	if d == nil {
		return nil, fail("driver", "nil driver")
	}
	f := Frame{
		Type: typ, SessionID: d.SessionID, Sequence: d.SendSeq, Body: body,
	}
	if d.RequireMAC || len(d.MACKey) > 0 {
		f.Flags = FlagRequiresMAC
	}
	raw, err := Encode(f, d.MACKey)
	if err != nil {
		return nil, err
	}
	d.SendSeq++
	return raw, nil
}

// DecodeAndHandle decodes raw bytes then Handle.
func (d *Driver) DecodeAndHandle(raw []byte) (Frame, error) {
	var zero Frame
	f, err := Decode(raw, d.MACKey, d.RequireMAC)
	if err != nil {
		return zero, err
	}
	if err := d.Handle(f); err != nil {
		return f, err
	}
	return f, nil
}
