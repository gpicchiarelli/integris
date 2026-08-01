package protocol

import (
	"encoding/binary"
	"fmt"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/session"
)

// Driver maps IP-P-0001 control frames onto the session state machine.
// Send and receive sequences are independent (per direction).
// Optional AEADKey seals TypeData bodies (IP-C-0002 provisional).
type Driver struct {
	Session    session.Session
	SessionID  [16]byte
	SendSeq    uint64
	RecvSeq    uint64
	MACKey     []byte
	AEADKey    []byte
	AuthKey    []byte // provisional peer-auth HMAC key; enables proof on TypePeerAuth
	AuthDir    string // direction this peer proves on EncodePeerAuth ("i2r"|"r2i")
	ArchiveKey []byte // provisional archive-auth HMAC key; enables proof on TypeArchiveAuth
	RequireMAC bool
	// LastPlaintext is set when TypeData is opened under AEADKey (or cleartext).
	// When TrackDataChunks is set, this is the chunk payload only.
	LastPlaintext []byte
	// TrackDataChunks enables contiguous TypeData chunk offset enforcement
	// (IP-P-0001 resumable transfer prelude). Off by default for opaque bodies.
	TrackDataChunks bool
	NextDataOffset  uint64 // next expected inbound chunk offset
	NextSendOffset  uint64 // next EncodeDataChunk outbound offset
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

// NewDriverWithSuites constructs a driver that requires a common crypto suite
// and binds a negotiation transcript for traffic-key derivation.
func NewDriverWithSuites(offered []session.Version, suites []string, sessionID [16]byte, macKey []byte, requireMAC bool) *Driver {
	d := NewDriver(offered, sessionID, macKey, requireMAC)
	d.Session = session.NewWithSuites(offered, suites)
	d.Session.Transcript = crypto.NewTranscript()
	return d
}

// SetAEADKey installs a provisional session traffic key (32 bytes).
func (d *Driver) SetAEADKey(key []byte) error {
	if d == nil {
		return fail("driver", "nil driver")
	}
	if len(key) != crypto.AEADKeySize {
		return fail("aead", fmt.Sprintf("key must be %d bytes", crypto.AEADKeySize))
	}
	d.AEADKey = append([]byte{}, key...)
	return nil
}

// InstallTrafficKey derives and installs an AEAD key from the session transcript
// after Activate (IP-C-0002). Both peers must share rootKey and transcript.
func (d *Driver) InstallTrafficKey(rootKey []byte) error {
	if d == nil {
		return fail("driver", "nil driver")
	}
	if d.Session.State != session.StateActive {
		return fail("state", "InstallTrafficKey requires ACTIVE")
	}
	if d.Session.Transcript == nil {
		return fail("transcript", "transcript required")
	}
	if d.Session.SelectedSuite == "" {
		return fail("suite", "no selected suite")
	}
	key, err := crypto.TrafficKey(rootKey, d.Session.Transcript.Digest(), d.SessionID, d.Session.SelectedSuite)
	if err != nil {
		return fail("aead", err.Error())
	}
	return d.SetAEADKey(key)
}

func (d *Driver) dataAAD(typ MessageType, seq uint64) []byte {
	buf := make([]byte, 0, 8+2+16+8)
	buf = append(buf, FrameMagic[:]...)
	var tmp [8]byte
	binary.LittleEndian.PutUint16(tmp[:2], uint16(typ))
	buf = append(buf, tmp[:2]...)
	buf = append(buf, d.SessionID[:]...)
	binary.LittleEndian.PutUint64(tmp[:], seq)
	buf = append(buf, tmp[:]...)
	return buf
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
		if d.Session.State == session.StateNew {
			if len(f.Body) > 0 {
				vers, suites, err := ParseNegotiateOfferBody(f.Body)
				if err != nil {
					return err
				}
				d.Session.Offered = vers
				if len(suites) > 0 {
					d.Session.OfferedSuites = suites
				}
			}
			if err := d.Session.Negotiate(); err != nil {
				return err
			}
		}
	case TypeNegotiateAccept:
		var (
			wireVers  session.Version
			wireSuite string
			hasBody   = len(f.Body) > 0
		)
		if hasBody {
			var err error
			wireVers, wireSuite, err = ParseNegotiateAcceptBody(f.Body)
			if err != nil {
				return err
			}
		}
		if d.Session.State == session.StateNew {
			if err := d.Session.Negotiate(); err != nil {
				return err
			}
		}
		if hasBody {
			if err := d.Session.ConfirmAccept(wireVers, wireSuite); err != nil {
				return err
			}
		}
	case TypePeerAuth:
		if len(d.AuthKey) > 0 {
			dir, proof, err := ParsePeerAuthBody(f.Body)
			if err != nil {
				return err
			}
			if err := d.Session.AuthenticateProof(d.AuthKey, d.SessionID, dir, proof); err != nil {
				return err
			}
		} else if err := d.Session.Authenticate(); err != nil {
			return err
		}
	case TypeArchiveAuth:
		if len(d.ArchiveKey) > 0 {
			if err := d.Session.AuthorizeArchiveProof(d.ArchiveKey, d.SessionID, f.Body); err != nil {
				return err
			}
		} else if err := d.Session.AuthorizeArchive(); err != nil {
			return err
		}
	case TypeActivate:
		if err := d.Session.Activate(); err != nil {
			return err
		}
	case TypeData:
		body := f.Body
		if len(d.AEADKey) > 0 {
			pt, err := crypto.Open(d.AEADKey, crypto.SequenceNonce(f.Sequence), d.dataAAD(TypeData, f.Sequence), f.Body)
			if err != nil {
				return fail("aead", err.Error())
			}
			body = pt
		}
		if d.TrackDataChunks {
			off, data, err := ParseDataChunkBody(body)
			if err != nil {
				return err
			}
			if off != d.NextDataOffset {
				if off < d.NextDataOffset {
					return fail("chunk", fmt.Sprintf("replay/overlap offset %d want %d", off, d.NextDataOffset))
				}
				return fail("chunk", fmt.Sprintf("gap offset %d want %d", off, d.NextDataOffset))
			}
			d.LastPlaintext = data
			d.NextDataOffset = off + uint64(len(data))
		} else {
			d.LastPlaintext = append([]byte{}, body...)
		}
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

// EncodeNegotiateOffer builds TypeNegotiateOffer with versions and suite IDs.
// Suites default to Session.OfferedSuites when non-empty, else session.LocalSuites.
func (d *Driver) EncodeNegotiateOffer(vers []session.Version) ([]byte, error) {
	if d == nil {
		return nil, fail("driver", "nil driver")
	}
	suites := d.Session.OfferedSuites
	if len(suites) == 0 {
		suites = session.LocalSuites
	}
	body, err := EncodeNegotiateOfferBody(vers, suites)
	if err != nil {
		return nil, err
	}
	return d.EncodeFrame(TypeNegotiateOffer, body)
}

// EncodeNegotiateAccept builds TypeNegotiateAccept with the selected version
// and suite. Negotiates first when still in NEW.
func (d *Driver) EncodeNegotiateAccept() ([]byte, error) {
	if d == nil {
		return nil, fail("driver", "nil driver")
	}
	if d.Session.State == session.StateNew {
		if err := d.Session.Negotiate(); err != nil {
			return nil, err
		}
	}
	if d.Session.State != session.StateNegotiated {
		return nil, fail("state", "EncodeNegotiateAccept requires NEGOTIATED")
	}
	body, err := EncodeNegotiateAcceptBody(d.Session.Selected, d.Session.SelectedSuite)
	if err != nil {
		return nil, err
	}
	return d.EncodeFrame(TypeNegotiateAccept, body)
}

// EncodeDataChunk builds TypeData with a chunk envelope at NextSendOffset and
// advances the send offset on success. Requires TrackDataChunks for the peer
// to enforce contiguity; the envelope is still well-formed without it.
func (d *Driver) EncodeDataChunk(data []byte) ([]byte, error) {
	if d == nil {
		return nil, fail("driver", "nil driver")
	}
	body, err := EncodeDataChunkBody(d.NextSendOffset, data)
	if err != nil {
		return nil, err
	}
	raw, err := d.EncodeFrame(TypeData, body)
	if err != nil {
		return nil, err
	}
	d.NextSendOffset += uint64(len(data))
	return raw, nil
}

// EncodeFrame builds the next outbound frame and advances SendSeq on success.
func (d *Driver) EncodeFrame(typ MessageType, body []byte) ([]byte, error) {
	if d == nil {
		return nil, fail("driver", "nil driver")
	}
	seq := d.SendSeq
	if typ == TypeData && len(d.AEADKey) > 0 {
		ct, err := crypto.Seal(d.AEADKey, crypto.SequenceNonce(seq), d.dataAAD(TypeData, seq), body)
		if err != nil {
			return nil, fail("aead", err.Error())
		}
		body = ct
	}
	f := Frame{
		Type: typ, SessionID: d.SessionID, Sequence: seq, Body: body,
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

// EncodePeerAuth builds a TypePeerAuth frame whose body is direction||HMAC
// over the frozen negotiation digest, then applies the proof locally so the
// sender session matches the peer after DecodeAndHandle (independent sequences).
func (d *Driver) EncodePeerAuth() ([]byte, error) {
	if d == nil {
		return nil, fail("driver", "nil driver")
	}
	if len(d.AuthKey) == 0 {
		return nil, fail("auth", "AuthKey required")
	}
	dir := d.AuthDir
	if dir == "" {
		dir = "i2r"
	}
	proof, err := d.Session.MakeAuthProof(d.AuthKey, d.SessionID, dir)
	if err != nil {
		return nil, err
	}
	raw, err := d.EncodeFrame(TypePeerAuth, EncodePeerAuthBody(dir, proof))
	if err != nil {
		return nil, err
	}
	if err := d.Session.AuthenticateProof(d.AuthKey, d.SessionID, dir, proof); err != nil {
		return nil, err
	}
	return raw, nil
}

// EncodeArchiveAuth builds a TypeArchiveAuth frame with an HMAC proof over the
// frozen post-peer-auth digest, then applies it locally (independent sequences).
func (d *Driver) EncodeArchiveAuth() ([]byte, error) {
	if d == nil {
		return nil, fail("driver", "nil driver")
	}
	if len(d.ArchiveKey) == 0 {
		return nil, fail("archive", "ArchiveKey required")
	}
	proof, err := d.Session.MakeArchiveProof(d.ArchiveKey, d.SessionID)
	if err != nil {
		return nil, err
	}
	raw, err := d.EncodeFrame(TypeArchiveAuth, proof)
	if err != nil {
		return nil, err
	}
	if err := d.Session.AuthorizeArchiveProof(d.ArchiveKey, d.SessionID, proof); err != nil {
		return nil, err
	}
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
