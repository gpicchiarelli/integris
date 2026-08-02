package remotesync

import (
	"encoding/binary"
	"io"

	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/localsync"
)

// msgParseBundle prefixes an apply response with parser metadata for net.
// Layout: type | u32 filesExpected | applyResponse...
const msgParseBundle byte = 0xb0

func wrapParseBundle(files uint32, applyResp []byte) []byte {
	b := []byte{msgParseBundle}
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], files)
	b = append(b, tmp[:]...)
	return append(b, applyResp...)
}

func unwrapParseBundle(p []byte) (files uint32, applyResp []byte, err error) {
	if len(p) < 1+4 || p[0] != msgParseBundle {
		return 0, nil, fail(KindProtocol, "bad parse bundle")
	}
	files = binary.LittleEndian.Uint32(p[1:5])
	return files, append([]byte{}, p[5:]...), nil
}

// validateAppMessage decodes push application messages without side effects.
func validateAppMessage(p []byte) error {
	if len(p) == 0 {
		return fail(KindProtocol, "empty app message")
	}
	switch p[0] {
	case msgManifest:
		_, err := decodeManifest(p)
		return err
	case msgFile:
		_, err := decodeFile(p)
		return err
	case msgFileBegin:
		_, err := decodeFileBegin(p)
		return err
	case msgFileChunk:
		_, _, err := decodeFileChunk(p)
		return err
	case msgFileEnd:
		_, _, err := decodeFileEnd(p)
		return err
	case msgCommit:
		if len(p) != 1 {
			return fail(KindProtocol, "bad commit")
		}
		return nil
	case msgIPCAbort:
		return nil
	default:
		return failf(KindProtocol, "unknown app op %d", p[0])
	}
}

func manifestFileCount(p []byte) (int, error) {
	entries, err := decodeManifest(p)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.Type == localsync.EntryFile {
			n++
		}
	}
	return n, nil
}

// ServeParserBridge validates net→parser requests and forwards them to apply
// (M2d). Parser holds neither PSK nor archive roots.
func ServeParserBridge(netRW, applyRW io.ReadWriter, netCh, applyCh *ipc.ChannelState, once bool) error {
	if netCh == nil || applyCh == nil {
		return fail(KindInvalidArgument, "nil parser channel")
	}
	return ServeParserBridgeDyn(netRW, netCh, func() (io.ReadWriter, *ipc.ChannelState) {
		return applyRW, applyCh
	}, once)
}

// ServeParserBridgeDyn is ServeParserBridge with a dynamic apply endpoint
// (M2q: peer-FD rebind refreshes apply RW/channel between requests).
func ServeParserBridgeDyn(netRW io.ReadWriter, netCh *ipc.ChannelState, applySide func() (io.ReadWriter, *ipc.ChannelState), once bool) error {
	if netCh == nil || applySide == nil {
		return fail(KindInvalidArgument, "nil parser channel")
	}
	fromNet := &ipcWire{rw: netRW, ch: netCh}
	for {
		req, err := fromNet.readRequest()
		if err != nil {
			return err
		}
		if err := validateAppMessage(req); err != nil {
			_ = fromNet.respond(mustResult(false, err.Error()))
			if once {
				return err
			}
			continue
		}
		applyRW, applyCh := applySide()
		if applyRW == nil || applyCh == nil {
			return fail(KindInvalidArgument, "nil apply endpoint")
		}
		toApply := &ipcWire{rw: applyRW, ch: applyCh}
		resp, err := toApply.request(req)
		if err != nil {
			_ = fromNet.respond(mustResult(false, err.Error()))
			return err
		}
		out := resp
		if len(req) > 0 && req[0] == msgManifest {
			n, err := manifestFileCount(req)
			if err != nil {
				_ = fromNet.respond(mustResult(false, err.Error()))
				return err
			}
			out = wrapParseBundle(uint32(n), resp)
		}
		if err := fromNet.respond(out); err != nil {
			return err
		}
		if len(req) > 0 && req[0] == msgCommit {
			if once {
				return nil
			}
			// Next push session: apply ServeApplyIPC also loops after commit.
		}
	}
}

// HandleActiveConnViaParserIPC is the net data plane when talking to parser (M2d).
func HandleActiveConnViaParserIPC(sess *Session, parserRW io.ReadWriter, ch *ipc.ChannelState) error {
	if sess == nil || ch == nil {
		return fail(KindInvalidArgument, "nil session or channel")
	}
	defer sess.Close()
	wire := &ipcWire{rw: parserRW, ch: ch}

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
	filesExpected, tcpResp, err := unwrapParseBundle(resp)
	if err != nil {
		return err
	}
	if err := sess.sendData(tcpResp); err != nil {
		return err
	}

	for i := 0; i < int(filesExpected); i++ {
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
