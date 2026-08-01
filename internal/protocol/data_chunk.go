package protocol

import (
	"encoding/binary"
	"fmt"
)

// Data chunk envelope for TypeData (IP-P-0001 resumable transfer prelude):
//
//	u64 offset || u32 length || data[length]
const (
	DataChunkHeaderBytes = 12
	MaxDataChunkBytes    = MaxBodyBytes - DataChunkHeaderBytes
)

// EncodeDataChunkBody packs a contiguous content chunk for TypeData.
func EncodeDataChunkBody(offset uint64, data []byte) ([]byte, error) {
	if len(data) > MaxDataChunkBytes {
		return nil, fail("chunk", fmt.Sprintf("chunk length %d exceeds max", len(data)))
	}
	if offset > ^uint64(0)-uint64(len(data)) {
		return nil, fail("chunk", "offset+length overflow")
	}
	out := make([]byte, DataChunkHeaderBytes+len(data))
	binary.LittleEndian.PutUint64(out[0:8], offset)
	binary.LittleEndian.PutUint32(out[8:12], uint32(len(data)))
	copy(out[DataChunkHeaderBytes:], data)
	return out, nil
}

// ParseDataChunkBody decodes EncodeDataChunkBody output.
func ParseDataChunkBody(body []byte) (offset uint64, data []byte, err error) {
	if len(body) < DataChunkHeaderBytes {
		return 0, nil, fail("chunk", "truncated data chunk")
	}
	offset = binary.LittleEndian.Uint64(body[0:8])
	n := binary.LittleEndian.Uint32(body[8:12])
	if DataChunkHeaderBytes+int(n) != len(body) {
		return 0, nil, fail("chunk", "length mismatch")
	}
	if n > MaxDataChunkBytes {
		return 0, nil, fail("chunk", "chunk length exceeds max")
	}
	if offset > ^uint64(0)-uint64(n) {
		return 0, nil, fail("chunk", "offset+length overflow")
	}
	data = append([]byte{}, body[DataChunkHeaderBytes:]...)
	return offset, data, nil
}
