package remotesync

import (
	"io"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/localsync"
)

// planGate binds a push session to a canonical manifest authorized by integrisd-plan.
type planGate struct {
	files    map[string]localsync.Entry
	expected int
	seen     map[string]struct{}
	digest   codec.Digest
	active   string // rel of in-flight chunked file
}

func authorizeManifest(raw []byte) (canonical []byte, gate planGate, err error) {
	entries, err := decodeManifest(raw)
	if err != nil {
		return nil, planGate{}, err
	}
	canonical, err = encodeManifest(entries)
	if err != nil {
		return nil, planGate{}, err
	}
	gate = planGate{
		files:  make(map[string]localsync.Entry),
		seen:   make(map[string]struct{}),
		digest: codec.SHA256(canonical),
	}
	for _, e := range entries {
		switch e.Type {
		case localsync.EntryDir:
			continue
		case localsync.EntryFile:
			if e.Rel == "" || !e.HasDigest {
				return nil, planGate{}, fail(KindProtocol, "plan: incomplete file entry")
			}
			if _, dup := gate.files[e.Rel]; dup {
				return nil, planGate{}, failf(KindProtocol, "plan: duplicate file %s", e.Rel)
			}
			gate.files[e.Rel] = e
			gate.expected++
		default:
			return nil, planGate{}, failf(KindProtocol, "plan: unsupported entry %s", e.Type)
		}
	}
	return canonical, gate, nil
}

func (g *planGate) checkFile(fw fileWire) error {
	if g == nil || g.files == nil {
		return fail(KindProtocol, "plan: no authorized manifest")
	}
	e, ok := g.files[fw.Rel]
	if !ok {
		return failf(KindProtocol, "plan: unexpected file %s", fw.Rel)
	}
	if e.Digest != fw.Digest || e.Mode != fw.Mode || uint64(len(fw.Data)) != uint64(e.Size) {
		return failf(KindProtocol, "plan: file %s does not match manifest", fw.Rel)
	}
	if _, seen := g.seen[fw.Rel]; seen {
		return failf(KindProtocol, "plan: duplicate transfer %s", fw.Rel)
	}
	g.seen[fw.Rel] = struct{}{}
	return nil
}

func (g *planGate) checkBegin(b fileBegin) error {
	if g == nil || g.files == nil {
		return fail(KindProtocol, "plan: no authorized manifest")
	}
	e, ok := g.files[b.Rel]
	if !ok {
		return failf(KindProtocol, "plan: unexpected file %s", b.Rel)
	}
	if e.Digest != b.Digest || e.Mode != b.Mode || uint64(e.Size) != b.Size {
		return failf(KindProtocol, "plan: begin %s does not match manifest", b.Rel)
	}
	if _, seen := g.seen[b.Rel]; seen {
		return failf(KindProtocol, "plan: duplicate transfer %s", b.Rel)
	}
	g.active = b.Rel
	return nil
}

func (g *planGate) checkEnd(rel string, dig codec.Digest) error {
	if g == nil || g.active == "" {
		return fail(KindProtocol, "plan: no active file")
	}
	if rel != g.active {
		return failf(KindProtocol, "plan: end %s != active %s", rel, g.active)
	}
	e := g.files[rel]
	if e.Digest != dig {
		return failf(KindProtocol, "plan: end digest mismatch %s", rel)
	}
	g.seen[rel] = struct{}{}
	g.active = ""
	return nil
}

func (g *planGate) checkCommit() error {
	if g == nil || g.files == nil {
		return fail(KindProtocol, "plan: no authorized manifest")
	}
	if g.active != "" {
		return fail(KindProtocol, "plan: commit with active file")
	}
	if len(g.seen) != g.expected {
		return failf(KindProtocol, "plan: commit with %d/%d files", len(g.seen), g.expected)
	}
	return nil
}

// ServePlanBridge authorizes parser→plan app messages against a canonical
// manifest, then forwards to apply (M2g). Plan holds neither archive roots nor PSK.
func ServePlanBridge(parserRW, applyRW io.ReadWriter, parserCh, applyCh *ipc.ChannelState, once bool) error {
	if parserCh == nil || applyCh == nil {
		return fail(KindInvalidArgument, "nil plan channel")
	}
	return ServePlanBridgeDyn(parserRW, parserCh, func() (io.ReadWriter, *ipc.ChannelState) {
		return applyRW, applyCh
	}, once)
}

// ServePlanBridgeDyn refreshes the apply endpoint per forward (M2r peer-FD rebind).
func ServePlanBridgeDyn(parserRW io.ReadWriter, parserCh *ipc.ChannelState, applySide func() (io.ReadWriter, *ipc.ChannelState), once bool) error {
	if parserCh == nil || applySide == nil {
		return fail(KindInvalidArgument, "nil plan channel")
	}
	fromParser := &ipcWire{rw: parserRW, ch: parserCh}
	var gate *planGate
	for {
		req, err := fromParser.readRequest()
		if err != nil {
			return err
		}
		if len(req) == 0 {
			_ = fromParser.respond(mustResult(false, "empty plan request"))
			continue
		}
		applyRW, applyCh := applySide()
		if applyRW == nil || applyCh == nil {
			return fail(KindInvalidArgument, "nil apply endpoint")
		}
		toApply := &ipcWire{rw: applyRW, ch: applyCh}
		switch req[0] {
		case msgManifest:
			canonical, g, err := authorizeManifest(req)
			if err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				if once {
					return err
				}
				continue
			}
			resp, err := toApply.request(canonical)
			if err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				return err
			}
			gate = &g
			if err := fromParser.respond(resp); err != nil {
				return err
			}
		case msgFile:
			fw, err := decodeFile(req)
			if err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				return err
			}
			if err := gate.checkFile(fw); err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				if once {
					return err
				}
				continue
			}
			resp, err := toApply.request(req)
			if err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				return err
			}
			if err := fromParser.respond(resp); err != nil {
				return err
			}
		case msgFileBegin:
			begin, err := decodeFileBegin(req)
			if err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				return err
			}
			if err := gate.checkBegin(begin); err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				if once {
					return err
				}
				continue
			}
			resp, err := toApply.request(req)
			if err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				return err
			}
			if err := fromParser.respond(resp); err != nil {
				return err
			}
		case msgFileChunk:
			if gate == nil || gate.active == "" {
				_ = fromParser.respond(mustResult(false, "plan: chunk without begin"))
				continue
			}
			resp, err := toApply.request(req)
			if err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				return err
			}
			if err := fromParser.respond(resp); err != nil {
				return err
			}
		case msgFileEnd:
			rel, dig, err := decodeFileEnd(req)
			if err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				return err
			}
			if err := gate.checkEnd(rel, dig); err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				if once {
					return err
				}
				continue
			}
			resp, err := toApply.request(req)
			if err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				return err
			}
			if err := fromParser.respond(resp); err != nil {
				return err
			}
		case msgCommit:
			if err := gate.checkCommit(); err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				if once {
					return err
				}
				continue
			}
			resp, err := toApply.request(req)
			if err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				return err
			}
			if err := fromParser.respond(resp); err != nil {
				return err
			}
			gate = nil
			if once {
				return nil
			}
		case msgIPCAbort:
			gate = nil
			resp, err := toApply.request(req)
			if err != nil {
				_ = fromParser.respond(mustResult(false, err.Error()))
				return err
			}
			_ = fromParser.respond(resp)
			return fail(KindTransport, "peer aborted transfer")
		default:
			_ = fromParser.respond(mustResult(false, "unknown plan op"))
			return failf(KindProtocol, "unknown plan op %d", req[0])
		}
	}
}
