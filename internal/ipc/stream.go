package ipc

import (
	"encoding/binary"
	"io"
)

// WriteFrame writes one length-prefixed frame to w (u32 LE length + raw).
// Length is checked against MaxFrameBytes + HeaderBytes + MACBytes.
func WriteFrame(w io.Writer, raw []byte) error {
	if w == nil {
		return fail("io", "nil writer", true)
	}
	max := MaxFrameBytes + HeaderBytes + MACBytes
	if len(raw) == 0 || len(raw) > max {
		return fail("limit", "frame length out of bounds", true)
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(raw)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fail("io", err.Error(), true)
	}
	if _, err := w.Write(raw); err != nil {
		return fail("io", err.Error(), true)
	}
	return nil
}

// ReadFrame reads one length-prefixed frame from r.
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	if r == nil {
		return nil, fail("io", "nil reader", true)
	}
	if max <= 0 {
		max = MaxFrameBytes + HeaderBytes + MACBytes
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fail("io", err.Error(), true)
	}
	n := int(binary.LittleEndian.Uint32(hdr[:]))
	if n <= 0 || n > max {
		return nil, fail("limit", "framed length out of bounds", true)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fail("io", err.Error(), true)
	}
	return buf, nil
}
