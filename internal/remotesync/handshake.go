package remotesync

import (
	"net"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/protocol"
	"github.com/gpicchiarelli/integris/internal/session"
)

var offeredVersions = []session.Version{3, 2}

// Session is an authenticated ACTIVE protocol driver bound to a connection.
type Session struct {
	Conn   net.Conn
	Driver *protocol.Driver
	Root   []byte
	Role   string // "push" or "serve"
}

// Close sends TypeClose best-effort and closes the connection.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	if s.Driver != nil && s.Driver.Session.State == session.StateActive {
		_ = send(s.Conn, s.Driver, protocol.TypeClose, nil)
	}
	if s.Conn != nil {
		return s.Conn.Close()
	}
	return nil
}

// DialHandshake connects as push initiator and completes mutual auth + AEAD.
// When peerID is non-empty, an unauthenticated peer prologue is written first
// so the responder can select a per-peer PSK (M2i).
func DialHandshake(conn net.Conn, root []byte, peerID string) (*Session, error) {
	if len(root) != RootKeySize {
		return nil, failf(KindInvalidArgument, "root key must be %d bytes", RootKeySize)
	}
	if peerID != "" {
		if err := WritePeerPrologue(conn, peerID); err != nil {
			return nil, err
		}
	}
	macKey, err := deriveMACKey(root, peerID)
	if err != nil {
		return nil, wrap(KindAuth, "mac key", err)
	}
	sid, err := newSessionID()
	if err != nil {
		return nil, err
	}
	suites := []string{crypto.SuiteIDAEAD}
	alice := protocol.NewDriverWithSuites(offeredVersions, suites, sid, macKey, true)

	if err := alice.Session.Negotiate(); err != nil {
		return nil, wrap(KindHandshake, "negotiate local", err)
	}
	raw, err := alice.EncodeNegotiateOffer(offeredVersions)
	if err != nil {
		return nil, wrap(KindHandshake, "offer", err)
	}
	if err := WriteFrame(conn, raw); err != nil {
		return nil, err
	}

	raw, err = ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	if _, err := alice.DecodeAndHandle(raw); err != nil {
		return nil, wrap(KindHandshake, "accept", err)
	}

	authKey, err := crypto.PeerAuthKey(root, sid)
	if err != nil {
		return nil, wrap(KindAuth, "peer key", err)
	}
	archKey, err := crypto.ArchiveAuthKey(root, sid)
	if err != nil {
		return nil, wrap(KindAuth, "archive key", err)
	}
	alice.AuthKey = authKey
	alice.ArchiveKey = archKey
	alice.AuthDir = "i2r"

	raw, err = alice.EncodePeerAuth()
	if err != nil {
		return nil, wrap(KindAuth, "peer auth i2r", err)
	}
	if err := WriteFrame(conn, raw); err != nil {
		return nil, err
	}
	raw, err = ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	if _, err := alice.DecodeAndHandle(raw); err != nil {
		return nil, wrap(KindAuth, "peer auth r2i", err)
	}

	raw, err = alice.EncodeArchiveAuth()
	if err != nil {
		return nil, wrap(KindAuth, "archive auth", err)
	}
	if err := WriteFrame(conn, raw); err != nil {
		return nil, err
	}

	if err := alice.Session.Activate(); err != nil {
		return nil, wrap(KindHandshake, "activate local", err)
	}
	if err := send(conn, alice, protocol.TypeActivate, nil); err != nil {
		return nil, err
	}
	if err := alice.InstallTrafficKey(root); err != nil {
		return nil, wrap(KindAuth, "traffic key", err)
	}
	return &Session{Conn: conn, Driver: alice, Root: append([]byte{}, root...), Role: "push"}, nil
}

// AcceptHandshake completes the serve-side handshake on an accepted connection
// using a single shared root key (no peer prologue).
func AcceptHandshake(conn net.Conn, root []byte) (*Session, error) {
	return acceptHandshake(conn, root, "")
}

// AcceptHandshakeKeyring reads a peer prologue, selects the PSK, then handshakes.
// peerID is set whenever the prologue was read successfully (including unknown/deny).
func AcceptHandshakeKeyring(conn net.Conn, kr PeerKeyring) (sess *Session, peerID string, err error) {
	if err := ValidateKeyring(kr); err != nil {
		return nil, "", err
	}
	peerID, err = ReadPeerPrologue(conn)
	if err != nil {
		return nil, "", err
	}
	root, ok := kr[peerID]
	if !ok {
		return nil, peerID, failf(KindAuth, "unknown peer id %s", PeerIDDigest(peerID))
	}
	sess, err = acceptHandshake(conn, root, peerID)
	return sess, peerID, err
}

func acceptHandshake(conn net.Conn, root []byte, peerID string) (*Session, error) {
	if len(root) != RootKeySize {
		return nil, failf(KindInvalidArgument, "root key must be %d bytes", RootKeySize)
	}
	macKey, err := deriveMACKey(root, peerID)
	if err != nil {
		return nil, wrap(KindAuth, "mac key", err)
	}

	raw, err := ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	f, err := protocol.Decode(raw, macKey, true)
	if err != nil {
		return nil, wrap(KindHandshake, "decode offer", err)
	}
	suites := []string{crypto.SuiteIDAEAD}
	bob := protocol.NewDriverWithSuites(offeredVersions, suites, f.SessionID, macKey, true)
	if err := bob.Handle(f); err != nil {
		return nil, wrap(KindHandshake, "offer", err)
	}
	raw, err = bob.EncodeNegotiateAccept()
	if err != nil {
		return nil, wrap(KindHandshake, "accept", err)
	}
	if err := WriteFrame(conn, raw); err != nil {
		return nil, err
	}

	authKey, err := crypto.PeerAuthKey(root, f.SessionID)
	if err != nil {
		return nil, wrap(KindAuth, "peer key", err)
	}
	archKey, err := crypto.ArchiveAuthKey(root, f.SessionID)
	if err != nil {
		return nil, wrap(KindAuth, "archive key", err)
	}
	bob.AuthKey = authKey
	bob.ArchiveKey = archKey
	bob.AuthDir = "r2i"

	raw, err = ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		return nil, wrap(KindAuth, "peer auth i2r", err)
	}
	raw, err = bob.EncodePeerAuth()
	if err != nil {
		return nil, wrap(KindAuth, "peer auth r2i", err)
	}
	if err := WriteFrame(conn, raw); err != nil {
		return nil, err
	}

	raw, err = ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		return nil, wrap(KindAuth, "archive auth", err)
	}

	raw, err = ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		return nil, wrap(KindHandshake, "activate", err)
	}
	if err := bob.InstallTrafficKey(root); err != nil {
		return nil, wrap(KindAuth, "traffic key", err)
	}
	return &Session{Conn: conn, Driver: bob, Root: append([]byte{}, root...), Role: "serve"}, nil
}

// sendData sends an application payload as TypeData (AEAD when keyed).
func (s *Session) sendData(payload []byte) error {
	if s == nil || s.Driver == nil {
		return fail(KindInternal, "nil session")
	}
	return send(s.Conn, s.Driver, protocol.TypeData, payload)
}

// recvData waits for the next TypeData (or Close/Failure).
func (s *Session) recvData() ([]byte, error) {
	f, err := recv(s.Conn, s.Driver)
	if err != nil {
		return nil, err
	}
	switch f.Type {
	case protocol.TypeData:
		return append([]byte{}, s.Driver.LastPlaintext...), nil
	case protocol.TypeClose:
		return nil, fail(KindTransport, "peer closed")
	case protocol.TypeFailure:
		return nil, fail(KindProtocol, "peer failure")
	default:
		return nil, failf(KindProtocol, "unexpected type %d after ACTIVE", f.Type)
	}
}
