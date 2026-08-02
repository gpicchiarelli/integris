package remotesync

import (
	"encoding/binary"
	"net"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/protocol"
	"github.com/gpicchiarelli/integris/internal/session"
)

// sessionSeal is sealed post-handshake state conferred from auth → net.
// Net never receives the push root key.
type sessionSeal struct {
	SessionID [16]byte
	MACKey    []byte
	AEADKey   []byte
	SendSeq   uint64
	RecvSeq   uint64
	Selected  session.Version
	Suite     string
}

func sealFromDriver(d *protocol.Driver) (sessionSeal, error) {
	var zero sessionSeal
	if d == nil {
		return zero, fail(KindInternal, "nil driver")
	}
	if d.Session.State != session.StateActive {
		return zero, fail(KindHandshake, "seal requires ACTIVE")
	}
	if len(d.AEADKey) != crypto.AEADKeySize || len(d.MACKey) < 16 {
		return zero, fail(KindAuth, "incomplete sealed keys")
	}
	return sessionSeal{
		SessionID: d.SessionID,
		MACKey:    append([]byte{}, d.MACKey...),
		AEADKey:   append([]byte{}, d.AEADKey...),
		SendSeq:   d.SendSeq,
		RecvSeq:   d.RecvSeq,
		Selected:  d.Session.Selected,
		Suite:     d.Session.SelectedSuite,
	}, nil
}

func encodeSeal(s sessionSeal) ([]byte, error) {
	if len(s.MACKey) > 255 || len(s.AEADKey) > 255 || len(s.Suite) > 255 {
		return nil, fail(KindProtocol, "seal field too long")
	}
	b := make([]byte, 0, 64+len(s.MACKey)+len(s.AEADKey)+len(s.Suite))
	b = append(b, s.SessionID[:]...)
	b = append(b, byte(len(s.MACKey)))
	b = append(b, s.MACKey...)
	b = append(b, byte(len(s.AEADKey)))
	b = append(b, s.AEADKey...)
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], s.SendSeq)
	b = append(b, tmp[:]...)
	binary.LittleEndian.PutUint64(tmp[:], s.RecvSeq)
	b = append(b, tmp[:]...)
	b = append(b, byte(s.Selected))
	b = append(b, byte(len(s.Suite)))
	b = append(b, s.Suite...)
	return b, nil
}

func decodeSeal(p []byte) (sessionSeal, error) {
	var zero sessionSeal
	if len(p) < 16+1+1+8+8+1+1 {
		return zero, fail(KindProtocol, "short seal")
	}
	copy(zero.SessionID[:], p[:16])
	p = p[16:]
	n := int(p[0])
	p = p[1:]
	if len(p) < n {
		return zero, fail(KindProtocol, "short seal mac")
	}
	zero.MACKey = append([]byte{}, p[:n]...)
	p = p[n:]
	if len(p) < 1 {
		return zero, fail(KindProtocol, "short seal aead len")
	}
	n = int(p[0])
	p = p[1:]
	if len(p) < n+8+8+1+1 {
		return zero, fail(KindProtocol, "short seal aead")
	}
	zero.AEADKey = append([]byte{}, p[:n]...)
	p = p[n:]
	zero.SendSeq = binary.LittleEndian.Uint64(p[:8])
	p = p[8:]
	zero.RecvSeq = binary.LittleEndian.Uint64(p[:8])
	p = p[8:]
	zero.Selected = session.Version(p[0])
	p = p[1:]
	n = int(p[0])
	p = p[1:]
	if len(p) != n {
		return zero, fail(KindProtocol, "seal suite length")
	}
	zero.Suite = string(p)
	return zero, nil
}

// SessionFromSeal rebuilds an ACTIVE serve session without the push root key.
func SessionFromSeal(conn net.Conn, sealRaw []byte) (*Session, error) {
	seal, err := decodeSeal(sealRaw)
	if err != nil {
		return nil, err
	}
	suites := []string{seal.Suite}
	if seal.Suite == "" {
		suites = []string{crypto.SuiteIDAEAD}
	}
	d := protocol.NewDriverWithSuites(offeredVersions, suites, seal.SessionID, seal.MACKey, true)
	d.Session.State = session.StateActive
	d.Session.Selected = seal.Selected
	d.Session.SelectedSuite = seal.Suite
	d.Session.PeerAuthenticated = true
	d.Session.AuthI2R = true
	d.Session.AuthR2I = true
	d.Session.ArchiveAuthorized = true
	d.SendSeq = seal.SendSeq
	d.RecvSeq = seal.RecvSeq
	if err := d.SetAEADKey(seal.AEADKey); err != nil {
		return nil, wrap(KindAuth, "aead", err)
	}
	return &Session{Conn: conn, Driver: d, Root: nil, Role: "serve"}, nil
}
