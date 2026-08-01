package codec

// PutU16LE writes v as little-endian into b, which must have length >= 2.
func PutU16LE(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

// PutU32LE writes v as little-endian into b, which must have length >= 4.
func PutU32LE(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// PutU64LE writes v as little-endian into b, which must have length >= 8.
func PutU64LE(b []byte, v uint64) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}

// U16LE reads a little-endian uint16 from b, which must have length >= 2.
func U16LE(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

// U32LE reads a little-endian uint32 from b, which must have length >= 4.
func U32LE(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// U64LE reads a little-endian uint64 from b, which must have length >= 8.
func U64LE(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
