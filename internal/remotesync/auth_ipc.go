//go:build unix

package remotesync

import (
	"io"
	"net"
	"os"

	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/observability"
)

const (
	msgHSConn byte = 0xa0
	msgHSSeal byte = 0xa1
)

// AcceptHandshakeViaAuthIPC performs the serve handshake in the auth role.
// Net sends the accepted TCP FD to auth, receives a sealed session + FD back,
// and never holds the push root key.
func AcceptHandshakeViaAuthIPC(conn net.Conn, authSock *os.File, ch *ipc.ChannelState) (*Session, error) {
	if ch == nil {
		return nil, fail(KindInvalidArgument, "nil auth channel")
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fail(KindTransport, "auth handshake requires TCP")
	}
	f, err := tcp.File()
	if err != nil {
		return nil, wrap(KindTransport, "tcp file", err)
	}
	_ = tcp.Close()

	req, err := ch.Encode(ipc.TypeRequest, []byte{msgHSConn})
	if err != nil {
		_ = f.Close()
		return nil, wrap(KindTransport, "ipc encode", err)
	}
	if err := ipc.WriteFrame(authSock, req); err != nil {
		_ = f.Close()
		return nil, wrap(KindTransport, "ipc write", err)
	}
	if err := ipc.SendFDFile(authSock, f); err != nil {
		_ = f.Close()
		return nil, wrap(KindTransport, "send tcp fd", err)
	}
	_ = f.Close()

	respRaw, err := ipc.ReadFrame(authSock, 0)
	if err != nil {
		return nil, wrap(KindTransport, "ipc read", err)
	}
	frame, err := ch.Decode(respRaw)
	if err != nil {
		return nil, wrap(KindTransport, "ipc decode", err)
	}
	if frame.Type != ipc.TypeResponse || len(frame.Payload) < 2 || frame.Payload[0] != msgHSSeal {
		return nil, fail(KindProtocol, "expected handshake seal")
	}
	seal := append([]byte{}, frame.Payload[1:]...)
	back, err := ipc.RecvFDFile(authSock)
	if err != nil {
		return nil, wrap(KindTransport, "recv tcp fd", err)
	}
	fc, err := net.FileConn(back)
	_ = back.Close()
	if err != nil {
		return nil, wrap(KindTransport, "fileconn", err)
	}
	return SessionFromSeal(fc, seal)
}

// AuthAuditPeer is an optional auth→audit link for peer admit/deny (M2i).
// When Side is set (M3b), each emit snapshots the current ExtraPeer endpoint
// so peer-FD rebind can refresh the audit socket without restarting auth.
type AuthAuditPeer struct {
	RW   io.ReadWriter
	Ch   *ipc.ChannelState
	Side func() (io.ReadWriter, *ipc.ChannelState)
}

// ServeAuthHandshakeIPC handles one or more handshake FD exchanges (auth role).
// rootMaterial is either a 32-byte shared PSK or an INTPEER1 keyring blob (M2i).
// audit is best-effort; handshake outcome does not depend on the sink.
func ServeAuthHandshakeIPC(rootMaterial []byte, authSock *os.File, ch *ipc.ChannelState, once bool, audit AuthAuditPeer) error {
	if ch == nil {
		return fail(KindInvalidArgument, "nil ipc channel")
	}
	single, kr, err := DecodeRootMaterial(rootMaterial)
	if err != nil {
		return err
	}
	wire := &ipcWire{rw: authSock, ch: ch}
	for {
		req, err := wire.readRequest()
		if err != nil {
			return err
		}
		if len(req) != 1 || req[0] != msgHSConn {
			_ = wire.respond(mustResult(false, "expected hs conn"))
			return fail(KindProtocol, "expected hs conn")
		}
		f, err := ipc.RecvFDFile(authSock)
		if err != nil {
			return wrap(KindTransport, "recv tcp fd", err)
		}
		fc, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			return wrap(KindTransport, "fileconn", err)
		}

		var sess *Session
		var peerID string
		if kr != nil {
			sess, peerID, err = AcceptHandshakeKeyring(fc, kr)
			if err != nil {
				_ = bestEffortPeerAudit(audit, false, peerID)
				_ = fc.Close()
				_ = wire.respond(mustResult(false, err.Error()))
				if once {
					return err
				}
				continue
			}
			_ = bestEffortPeerAudit(audit, true, peerID)
		} else {
			sess, err = AcceptHandshake(fc, single)
			if err != nil {
				_ = fc.Close()
				_ = wire.respond(mustResult(false, err.Error()))
				if once {
					return err
				}
				continue
			}
		}
		seal, err := sealFromDriver(sess.Driver)
		if err != nil {
			sess.Conn = nil
			_ = fc.Close()
			_ = wire.respond(mustResult(false, err.Error()))
			return err
		}
		raw, err := encodeSeal(seal)
		if err != nil {
			sess.Conn = nil
			_ = fc.Close()
			return err
		}
		tcpFile, err := fc.(*net.TCPConn).File()
		if err != nil {
			sess.Conn = nil
			_ = fc.Close()
			return wrap(KindTransport, "tcp file", err)
		}
		sess.Conn = nil
		_ = fc.Close()

		payload := append([]byte{msgHSSeal}, raw...)
		if err := wire.respond(payload); err != nil {
			_ = tcpFile.Close()
			return err
		}
		if err := ipc.SendFDFile(authSock, tcpFile); err != nil {
			_ = tcpFile.Close()
			return wrap(KindTransport, "send tcp fd", err)
		}
		_ = tcpFile.Close()
		if once {
			// Do not exit before net drains the seal+SCM_RIGHTS exchange and
			// finishes the session; early close races the sealed TCP FD handoff.
			for {
				if _, err := ipc.ReadFrame(authSock, 0); err != nil {
					return nil
				}
			}
		}
	}
}

func bestEffortPeerAudit(audit AuthAuditPeer, admit bool, peerID string) error {
	if peerID == "" {
		return nil
	}
	rw, ch := audit.RW, audit.Ch
	if audit.Side != nil {
		rw, ch = audit.Side()
	}
	if rw == nil || ch == nil {
		return nil
	}
	return EmitAuditEvent(rw, ch, peerAdmitEvent(admit, peerID))
}

func peerAdmitEvent(admit bool, peerID string) observability.Event {
	digest := PeerIDDigest(peerID)
	if admit {
		return observability.Event{
			ID:            "auth.peer.admit",
			Channel:       observability.ChannelSecurity,
			Severity:      observability.SeverityInfo,
			Component:     "integrisd-auth",
			CauseCategory: "peer_admit",
			Redaction:     observability.RedactionPublic,
			Message:       digest,
		}
	}
	return observability.Event{
		ID:            "auth.peer.deny",
		Channel:       observability.ChannelSecurity,
		Severity:      observability.SeverityWarning,
		Component:     "integrisd-auth",
		CauseCategory: "peer_deny",
		Redaction:     observability.RedactionPublic,
		Message:       digest,
	}
}
