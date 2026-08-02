package remotesync

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/localsync"
	"github.com/gpicchiarelli/integris/internal/observability"
)

// ipcWire is a bidirectional authenticated IPC link to the peer role.
type ipcWire struct {
	rw io.ReadWriter
	ch *ipc.ChannelState
}

func (w *ipcWire) request(payload []byte) ([]byte, error) {
	raw, err := w.ch.Encode(ipc.TypeRequest, payload)
	if err != nil {
		return nil, wrap(KindTransport, "ipc encode", err)
	}
	if err := ipc.WriteFrame(w.rw, raw); err != nil {
		return nil, wrap(KindTransport, "ipc write", err)
	}
	respRaw, err := ipc.ReadFrame(w.rw, 0)
	if err != nil {
		return nil, wrap(KindTransport, "ipc read", err)
	}
	frame, err := w.ch.Decode(respRaw)
	if err != nil {
		return nil, wrap(KindTransport, "ipc decode", err)
	}
	if frame.Type != ipc.TypeResponse {
		return nil, fail(KindProtocol, "ipc: expected response")
	}
	return frame.Payload, nil
}

func (w *ipcWire) respond(payload []byte) error {
	raw, err := w.ch.Encode(ipc.TypeResponse, payload)
	if err != nil {
		return wrap(KindTransport, "ipc encode", err)
	}
	return ipc.WriteFrame(w.rw, raw)
}

func (w *ipcWire) readRequest() ([]byte, error) {
	raw, err := ipc.ReadFrame(w.rw, 0)
	if err != nil {
		return nil, wrap(KindTransport, "ipc read", err)
	}
	frame, err := w.ch.Decode(raw)
	if err != nil {
		return nil, wrap(KindTransport, "ipc decode", err)
	}
	if frame.Type != ipc.TypeRequest {
		return nil, fail(KindProtocol, "ipc: expected request")
	}
	return frame.Payload, nil
}

// HandleConnViaApplyIPC serves one TCP push, forwarding staging/apply to the
// apply role over authenticated local IPC (M2a). Net must not touch archives.
func HandleConnViaApplyIPC(conn net.Conn, rootKey []byte, ipcRW io.ReadWriter, ch *ipc.ChannelState) error {
	if ch == nil {
		return fail(KindInvalidArgument, "nil ipc channel")
	}
	sess, err := AcceptHandshake(conn, rootKey)
	if err != nil {
		return err
	}
	return HandleActiveConnViaApplyIPC(sess, ipcRW, ch)
}

// HandleActiveConnViaApplyIPC serves the data plane for an already-ACTIVE session
// (M2c: handshake completed by integrisd-auth).
func HandleActiveConnViaApplyIPC(sess *Session, ipcRW io.ReadWriter, ch *ipc.ChannelState) error {
	if sess == nil || ch == nil {
		return fail(KindInvalidArgument, "nil session or channel")
	}
	defer sess.Close()
	wire := &ipcWire{rw: ipcRW, ch: ch}

	raw, err := sess.recvData()
	if err != nil {
		return err
	}
	if len(raw) == 0 || raw[0] != msgManifest {
		return fail(KindProtocol, "expected manifest")
	}
	resp, err := wire.request(raw)
	if err != nil {
		return err
	}
	if err := sess.sendData(resp); err != nil {
		return err
	}

	entries, err := decodeManifest(raw)
	if err != nil {
		return err
	}
	filesExpected := 0
	for _, e := range entries {
		if e.Type == localsync.EntryFile {
			filesExpected++
		}
	}
	for i := 0; i < filesExpected; i++ {
		raw, err := sess.recvData()
		if err != nil {
			_, _ = wire.request([]byte{msgIPCAbort})
			return err
		}
		if len(raw) > 0 && raw[0] == msgFile {
			resp, err := wire.request(raw)
			if err != nil {
				return err
			}
			if len(resp) > 0 && resp[0] == msgResult {
				ok, msg, derr := decodeResult(resp)
				if derr != nil {
					return derr
				}
				if !ok {
					return respondErr(sess, fail(KindApply, msg))
				}
			}
			continue
		}
		if len(raw) == 0 || raw[0] != msgFileBegin {
			return respondErr(sess, fail(KindProtocol, "expected file begin"))
		}
		ack, err := wire.request(raw)
		if err != nil {
			return err
		}
		if err := sess.sendData(ack); err != nil {
			return err
		}
		begin, err := decodeFileBegin(raw)
		if err != nil {
			return err
		}
		offset, err := decodeFileAck(ack)
		if err != nil {
			return err
		}
		for offset < begin.Size {
			chunk, err := sess.recvData()
			if err != nil {
				_, _ = wire.request([]byte{msgIPCAbort})
				return err
			}
			if len(chunk) > 0 && chunk[0] == msgFileEnd {
				return respondErr(sess, fail(KindProtocol, "unexpected file end before size complete"))
			}
			resp, err := wire.request(chunk)
			if err != nil {
				return err
			}
			if len(resp) == 1+8 && resp[0] == msgFileAck {
				offset, err = decodeFileAck(resp)
				if err != nil {
					return err
				}
				continue
			}
			if len(resp) > 0 && resp[0] == msgResult {
				ok, msg, derr := decodeResult(resp)
				if derr != nil {
					return derr
				}
				if !ok {
					return respondErr(sess, fail(KindApply, msg))
				}
			}
			coff, data, err := decodeFileChunk(chunk)
			if err != nil {
				return err
			}
			offset = coff + uint64(len(data))
		}
		endRaw, err := sess.recvData()
		if err != nil {
			_, _ = wire.request([]byte{msgIPCAbort})
			return err
		}
		resp, err := wire.request(endRaw)
		if err != nil {
			return err
		}
		if len(resp) > 0 && resp[0] == msgResult {
			ok, msg, derr := decodeResult(resp)
			if derr != nil {
				return derr
			}
			if !ok {
				return respondErr(sess, fail(KindApply, msg))
			}
		}
	}

	raw, err = sess.recvData()
	if err != nil {
		return err
	}
	if len(raw) != 1 || raw[0] != msgCommit {
		return fail(KindProtocol, "expected commit")
	}
	resp, err = wire.request(raw)
	if err != nil {
		return err
	}
	return sess.sendData(resp)
}

const msgIPCAbort byte = 0xff

// AuditPeer is an optional apply→audit IPC link (M2e), or apply→journal
// when journal relays audit (M2f).
type AuditPeer struct {
	RW   io.ReadWriter
	Ch   *ipc.ChannelState
	Done bool // emit AuditDone after commit (once-mode)
}

// ApplyIPCExtras optional apply-side peers (journal and/or audit).
type ApplyIPCExtras struct {
	Audit   AuditPeer
	Journal localsync.JournalSession // when set, localsync appends via this session
}

// ServeApplyIPC handles one push's staging/apply over IPC (apply role).
// destDir, when non-nil, is a conferred allow-root directory FD for openat
// staging (M3e); destination remains the Sync root label.
func ServeApplyIPC(destination string, destDir *os.File, ipcRW io.ReadWriter, ch *ipc.ChannelState) error {
	return ServeApplyIPCExtras(destination, destDir, ipcRW, ch, ApplyIPCExtras{})
}

// ServeApplyIPCWithAudit is ServeApplyIPC plus best-effort audit emission (M2e).
func ServeApplyIPCWithAudit(destination string, destDir *os.File, ipcRW io.ReadWriter, ch *ipc.ChannelState, audit AuditPeer) error {
	return ServeApplyIPCExtras(destination, destDir, ipcRW, ch, ApplyIPCExtras{Audit: audit})
}

// ServeApplyIPCExtras is ServeApplyIPC with optional journal IPC and audit (M2e/M2f).
func ServeApplyIPCExtras(destination string, destDir *os.File, ipcRW io.ReadWriter, ch *ipc.ChannelState, extras ApplyIPCExtras) error {
	if ch == nil {
		return fail(KindInvalidArgument, "nil ipc channel")
	}
	store, err := openLocalStoreAt(destination, destDir)
	if err != nil {
		return err
	}
	defer store.close()
	wire := &ipcWire{rw: ipcRW, ch: ch}
	audit := extras.Audit
	var auditWire *ipcWire
	if audit.RW != nil && audit.Ch != nil {
		auditWire = &ipcWire{rw: audit.RW, ch: audit.Ch}
	}

	for {
		req, err := wire.readRequest()
		if err != nil {
			store.persistActive()
			return err
		}
		if len(req) == 0 {
			_ = wire.respond(mustResult(false, "empty ipc request"))
			continue
		}
		switch req[0] {
		case msgManifest:
			entries, err := decodeManifest(req)
			if err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			if err := store.prepareDirs(entries); err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			if err := wire.respond(encodeManifestOK()); err != nil {
				return err
			}
		case msgFile:
			fw, err := decodeFile(req)
			if err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			if err := store.stageLegacy(fw); err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			if err := wire.respond(mustResult(true, "ok")); err != nil {
				return err
			}
		case msgFileBegin:
			begin, err := decodeFileBegin(req)
			if err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			off, err := store.beginFile(begin)
			if err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			if err := wire.respond(encodeFileAck(off)); err != nil {
				return err
			}
		case msgFileChunk:
			coff, data, err := decodeFileChunk(req)
			if err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			if err := store.writeChunk(coff, data); err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			if err := wire.respond(encodeFileAck(store.off)); err != nil {
				return err
			}
		case msgFileEnd:
			rel, dig, err := decodeFileEnd(req)
			if err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			// Already-complete begin left store inactive; verify matching end.
			if !store.active {
				if rel != store.lastBegin.Rel || dig != store.lastBegin.Digest {
					err := fail(KindProtocol, "file end mismatch")
					_ = wire.respond(mustResult(false, err.Error()))
					return err
				}
				if err := wire.respond(mustResult(true, "ok")); err != nil {
					return err
				}
				continue
			}
			if err := store.endFile(rel, dig); err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			if err := wire.respond(mustResult(true, "ok")); err != nil {
				return err
			}
		case msgDestManifest:
			entries, err := decodeDestManifest(req)
			if err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			store.setDestManifest(entries)
			if err := wire.respond(mustResult(true, "ok")); err != nil {
				return err
			}
		case msgCommit:
			cerr := store.commit(extras.Journal)
			if cerr != nil {
				_ = bestEffortAudit(auditWire, auditCommitEvent(false, 0))
				_ = wire.respond(mustResult(false, cerr.Error()))
				return cerr
			}
			ok, err := encodeResult(true, "ok")
			if err != nil {
				return err
			}
			if err := wire.respond(ok); err != nil {
				return err
			}
			_ = bestEffortAudit(auditWire, auditCommitEvent(true, 0))
			if audit.Done && auditWire != nil {
				_ = EmitAuditDone(auditWire.rw, auditWire.ch)
			}
			return nil
		case msgIPCAbort:
			store.persistActive()
			_ = wire.respond(mustResult(false, "aborted"))
			return fail(KindTransport, "peer aborted transfer")
		default:
			msg := fmt.Sprintf("unknown ipc op %d", req[0])
			_ = wire.respond(mustResult(false, msg))
			return fail(KindProtocol, msg)
		}
	}
}

func bestEffortAudit(wire *ipcWire, e observability.Event) error {
	if wire == nil {
		return nil
	}
	return EmitAuditEvent(wire.rw, wire.ch, e)
}

func mustResult(ok bool, msg string) []byte {
	b, err := encodeResult(ok, msg)
	if err != nil {
		return []byte{msgResult, 0, 0, 0}
	}
	return b
}
