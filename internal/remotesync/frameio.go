package remotesync

import (
	"encoding/binary"
	"io"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/protocol"
)

// ReadFrame reads one self-delimiting IP-P-0001 frame from r.
func ReadFrame(r io.Reader) ([]byte, error) {
	hdr := make([]byte, protocol.HeaderBytes)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, wrap(KindTransport, "read header", err)
	}
	if string(hdr[0:8]) != string(protocol.FrameMagic[:]) {
		return nil, fail(KindProtocol, "bad frame magic")
	}
	bodyLen := binary.LittleEndian.Uint32(hdr[14:18])
	if bodyLen > protocol.MaxBodyBytes {
		return nil, fail(KindProtocol, "body_length exceeds MaxBodyBytes")
	}
	flags := codec.U16LE(hdr[12:14])
	needMAC := flags&protocol.FlagRequiresMAC != 0
	total := protocol.HeaderBytes + int(bodyLen)
	if needMAC {
		total += protocol.AuthBytes
	}
	raw := make([]byte, total)
	copy(raw, hdr)
	if _, err := io.ReadFull(r, raw[protocol.HeaderBytes:]); err != nil {
		return nil, wrap(KindTransport, "read body", err)
	}
	return raw, nil
}

// WriteFrame writes a complete encoded frame to w.
func WriteFrame(w io.Writer, raw []byte) error {
	if len(raw) < protocol.HeaderBytes {
		return fail(KindProtocol, "short frame write")
	}
	n, err := w.Write(raw)
	if err != nil {
		return wrap(KindTransport, "write frame", err)
	}
	if n != len(raw) {
		return fail(KindTransport, "short frame write")
	}
	return nil
}

func send(w io.Writer, d *protocol.Driver, typ protocol.MessageType, body []byte) error {
	raw, err := d.EncodeFrame(typ, body)
	if err != nil {
		return wrap(KindProtocol, "encode", err)
	}
	return WriteFrame(w, raw)
}

func recv(r io.Reader, d *protocol.Driver) (protocol.Frame, error) {
	raw, err := ReadFrame(r)
	if err != nil {
		return protocol.Frame{}, err
	}
	f, err := d.DecodeAndHandle(raw)
	if err != nil {
		return f, wrap(KindProtocol, "handle", err)
	}
	return f, nil
}
