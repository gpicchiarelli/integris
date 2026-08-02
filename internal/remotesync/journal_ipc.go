package remotesync

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/localsync"
)

// Journal IPC opcodes (apply → journal). Distinct from app/auth/parser/audit tags.
const (
	msgJrnOpen   byte = 0xd0
	msgJrnAppend byte = 0xd1
	msgJrnClose  byte = 0xd2
)

const maxJrnPrefixBytes = 8 << 20 // 8 MiB accepted-prefix bound for Open response

// IPCJournalSession is a localsync.JournalSession over authenticated IPC.
type IPCJournalSession struct {
	RW io.ReadWriter
	Ch *ipc.ChannelState
}

// Open implements localsync.JournalSession.
func (s *IPCJournalSession) Open() (journal.Prefix, error) {
	if s == nil || s.RW == nil || s.Ch == nil {
		return journal.Prefix{}, fail(KindInvalidArgument, "nil journal session")
	}
	wire := &ipcWire{rw: s.RW, ch: s.Ch}
	resp, err := wire.request([]byte{msgJrnOpen})
	if err != nil {
		return journal.Prefix{}, err
	}
	if len(resp) < 1+4 || resp[0] != msgJrnOpen {
		ok, msg, derr := decodeResult(resp)
		if derr == nil && !ok {
			return journal.Prefix{}, fail(KindProtocol, msg)
		}
		return journal.Prefix{}, fail(KindProtocol, "bad journal open response")
	}
	n := binary.LittleEndian.Uint32(resp[1:5])
	if int(n) > maxJrnPrefixBytes || len(resp) < 5+int(n) {
		return journal.Prefix{}, fail(KindProtocol, "bad journal open length")
	}
	return journal.ReadPrefixBytes(resp[5 : 5+int(n)])
}

// Append implements localsync.JournalSession.
func (s *IPCJournalSession) Append(id codec.TransactionID, t codec.RecordType, payload []byte) error {
	if s == nil || s.RW == nil || s.Ch == nil {
		return fail(KindInvalidArgument, "nil journal session")
	}
	if !codec.ValidRecordType(t) {
		return fail(KindInvalidArgument, "invalid journal record type")
	}
	if len(payload) > codec.MaxPayloadBytes {
		return fail(KindInvalidArgument, "journal payload too large")
	}
	req := make([]byte, 0, 1+16+2+len(payload))
	req = append(req, msgJrnAppend)
	req = append(req, id[:]...)
	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], uint16(t))
	req = append(req, tmp[:]...)
	req = append(req, payload...)
	wire := &ipcWire{rw: s.RW, ch: s.Ch}
	resp, err := wire.request(req)
	if err != nil {
		return err
	}
	ok, msg, err := decodeResult(resp)
	if err != nil {
		return err
	}
	if !ok {
		return fail(KindApply, msg)
	}
	return nil
}

// Close implements localsync.JournalSession (releases the remote writer for this Sync).
func (s *IPCJournalSession) Close() error {
	if s == nil || s.RW == nil || s.Ch == nil {
		return nil
	}
	wire := &ipcWire{rw: s.RW, ch: s.Ch}
	resp, err := wire.request([]byte{msgJrnClose})
	if err != nil {
		return err
	}
	ok, msg, err := decodeResult(resp)
	if err != nil {
		return err
	}
	if !ok {
		return fail(KindProtocol, msg)
	}
	return nil
}

// JournalAuditRelay optionally forwards redacted audit events (best-effort).
type JournalAuditRelay struct {
	RW io.ReadWriter
	Ch *ipc.ChannelState
}

// ServeJournalIPC owns the journal file and serves Open/Append/Close to apply.
// destDir, when non-nil, reopens the journal via openat (M3f CapEnter-safe).
// When audit is non-nil, msgAuditEvent/msgAuditDone are relayed best-effort.
// Once-mode exits after AuditDone (with audit) or first JrnClose (without audit).
func ServeJournalIPC(journalPath string, destDir *os.File, applyRW io.ReadWriter, applyCh *ipc.ChannelState, audit JournalAuditRelay, once bool) error {
	if applyCh == nil {
		return fail(KindInvalidArgument, "nil journal channel")
	}
	if destDir == nil {
		if err := os.MkdirAll(filepath.Dir(journalPath), 0o700); err != nil {
			return wrap(KindInternal, "journal mkdir", err)
		}
	}
	wire := &ipcWire{rw: applyRW, ch: applyCh}
	var auditWire *ipcWire
	if audit.RW != nil && audit.Ch != nil {
		auditWire = &ipcWire{rw: audit.RW, ch: audit.Ch}
	}

	sess := localsync.OpenFileJournalAt(journalPath, destDir)
	opened := false
	defer func() { _ = sess.Close() }()

	for {
		req, err := wire.readRequest()
		if err != nil {
			return err
		}
		if len(req) == 0 {
			_ = wire.respond(mustResult(false, "empty journal request"))
			continue
		}
		switch req[0] {
		case msgJrnOpen:
			if opened {
				_ = sess.Close()
				opened = false
			}
			prefix, err := sess.Open()
			if err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			opened = true
			if prefix.Bytes > maxJrnPrefixBytes {
				err := fail(KindProtocol, "journal prefix too large")
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			raw, err := localsync.AcceptedPrefixBytes(sess, prefix.Bytes)
			if err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			resp := []byte{msgJrnOpen}
			var tmp [4]byte
			binary.LittleEndian.PutUint32(tmp[:], uint32(len(raw)))
			resp = append(resp, tmp[:]...)
			resp = append(resp, raw...)
			if err := wire.respond(resp); err != nil {
				return err
			}
		case msgJrnAppend:
			if !opened {
				_ = wire.respond(mustResult(false, "journal not open"))
				continue
			}
			if len(req) < 1+16+2 {
				_ = wire.respond(mustResult(false, "short journal append"))
				continue
			}
			var id codec.TransactionID
			copy(id[:], req[1:17])
			t := codec.RecordType(binary.LittleEndian.Uint16(req[17:19]))
			payload := req[19:]
			if err := sess.Append(id, t, payload); err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return err
			}
			if err := wire.respond(mustResult(true, "ok")); err != nil {
				return err
			}
		case msgJrnClose:
			if opened {
				_ = sess.Close()
				opened = false
			}
			if err := wire.respond(mustResult(true, "ok")); err != nil {
				return err
			}
			// Once-mode exits on AuditDone (apply always sends it after commit when
			// journal is the extra peer), not on JrnClose.
		case msgAuditEvent, msgAuditDone:
			if auditWire == nil {
				_ = wire.respond(mustResult(true, "audit disabled"))
				if once && req[0] == msgAuditDone {
					return nil
				}
				continue
			}
			resp, err := auditWire.request(req)
			if err != nil {
				_ = wire.respond(mustResult(true, "audit relay failed"))
				if once && req[0] == msgAuditDone {
					return nil
				}
				continue
			}
			if err := wire.respond(resp); err != nil {
				return err
			}
			if once && req[0] == msgAuditDone {
				return nil
			}
		default:
			_ = wire.respond(mustResult(false, "unknown journal op"))
			return failf(KindProtocol, "unknown journal op %d", req[0])
		}
	}
}

