package remotesync

import (
	"io"
	"sync"
	"time"

	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/observability"
)

// Audit IPC opcodes (apply → audit). Distinct from app/auth/parser tags.
const (
	msgAuditEvent byte = 0xc0
	msgAuditDone  byte = 0xc1
)

// EmitAuditEvent sends one redacted observability event to the audit role.
// Failures are returned to the caller; push success MUST NOT depend on them
// (operational sink is not an IC-1 persistence barrier).
func EmitAuditEvent(rw io.ReadWriter, ch *ipc.ChannelState, e observability.Event) error {
	if rw == nil || ch == nil {
		return fail(KindInvalidArgument, "nil audit channel")
	}
	body, err := observability.EncodeCanonical(e)
	if err != nil {
		return wrap(KindInvalidArgument, "audit encode", err)
	}
	wire := &ipcWire{rw: rw, ch: ch}
	resp, err := wire.request(append([]byte{msgAuditEvent}, body...))
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

// EmitAuditDone signals end-of-session to audit (once-mode exit).
func EmitAuditDone(rw io.ReadWriter, ch *ipc.ChannelState) error {
	if rw == nil || ch == nil {
		return fail(KindInvalidArgument, "nil audit channel")
	}
	wire := &ipcWire{rw: rw, ch: ch}
	resp, err := wire.request([]byte{msgAuditDone})
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

// ServeAuditSink appends validated audit events to sink (audit role).
// sink should be opened before confinement so writes use a conferred FD.
func ServeAuditSink(sink io.Writer, ipcRW io.ReadWriter, ch *ipc.ChannelState, once bool) error {
	return ServeAuditSinkExtra(sink, ipcRW, ch, nil, nil, once)
}

// ServeAuditSinkExtra is ServeAuditSink plus an optional second peer (auth→audit M2i).
// Primary Done ends once-mode; the extra peer is best-effort and does not exit once-mode.
func ServeAuditSinkExtra(sink io.Writer, primaryRW io.ReadWriter, primaryCh *ipc.ChannelState, extraRW io.ReadWriter, extraCh *ipc.ChannelState, once bool) error {
	if extraRW == nil || extraCh == nil {
		return ServeAuditSinkExtraDyn(sink, primaryRW, primaryCh, nil, once)
	}
	return ServeAuditSinkExtraDyn(sink, primaryRW, primaryCh, func() (io.ReadWriter, *ipc.ChannelState) {
		return extraRW, extraCh
	}, once)
}

// ServeAuditSinkExtraDyn refreshes the auth ExtraPeer endpoint after peer-FD
// rebind (M3a). When extraSide is nil, only the primary journal peer is served.
func ServeAuditSinkExtraDyn(sink io.Writer, primaryRW io.ReadWriter, primaryCh *ipc.ChannelState, extraSide func() (io.ReadWriter, *ipc.ChannelState), once bool) error {
	if sink == nil || primaryCh == nil {
		return fail(KindInvalidArgument, "nil audit sink or channel")
	}
	var mu sync.Mutex
	write := func(body []byte) error {
		mu.Lock()
		defer mu.Unlock()
		_, err := sink.Write(append(append([]byte{}, body...), '\n'))
		return err
	}
	if extraSide != nil {
		go func() {
			var lastRW io.ReadWriter
			for {
				extraRW, extraCh := extraSide()
				if extraRW == nil || extraCh == nil {
					time.Sleep(20 * time.Millisecond)
					continue
				}
				if extraRW == lastRW {
					// Endpoint unchanged after EOF — wait for rebind.
					time.Sleep(20 * time.Millisecond)
					continue
				}
				lastRW = extraRW
				_ = serveAuditLoop(extraRW, extraCh, write, false)
			}
		}()
	}
	return serveAuditLoop(primaryRW, primaryCh, write, once)
}

func serveAuditLoop(ipcRW io.ReadWriter, ch *ipc.ChannelState, write func([]byte) error, once bool) error {
	wire := &ipcWire{rw: ipcRW, ch: ch}
	for {
		req, err := wire.readRequest()
		if err != nil {
			return err
		}
		if len(req) == 0 {
			_ = wire.respond(mustResult(false, "empty audit request"))
			continue
		}
		switch req[0] {
		case msgAuditEvent:
			if len(req) < 2 {
				_ = wire.respond(mustResult(false, "empty audit event"))
				continue
			}
			body := req[1:]
			if len(body) > 4096 {
				_ = wire.respond(mustResult(false, "audit event too large"))
				continue
			}
			if err := write(body); err != nil {
				_ = wire.respond(mustResult(false, err.Error()))
				return wrap(KindInternal, "audit sink", err)
			}
			if err := wire.respond(mustResult(true, "ok")); err != nil {
				return err
			}
		case msgAuditDone:
			if err := wire.respond(mustResult(true, "ok")); err != nil {
				return err
			}
			if once {
				return nil
			}
		default:
			_ = wire.respond(mustResult(false, "unknown audit op"))
			return failf(KindProtocol, "unknown audit op %d", req[0])
		}
	}
}

func auditCommitEvent(ok bool, files int) observability.Event {
	sev := observability.SeverityInfo
	msg := "push commit ok"
	cause := "commit_ok"
	if !ok {
		sev = observability.SeverityError
		msg = "push commit failed"
		cause = "commit_fail"
	}
	_ = files
	return observability.Event{
		ID:            "push.commit",
		Channel:       observability.ChannelAudit,
		Severity:      sev,
		Component:     "integrisd-apply",
		CauseCategory: cause,
		Redaction:     observability.RedactionPublic,
		Message:       msg,
	}
}
