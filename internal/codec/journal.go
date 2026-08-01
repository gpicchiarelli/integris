package codec

import "bytes"

// Journal envelope constants (IP-F-0001 format version 1).
const (
	FormatVersion uint16 = 1
	HeaderLength  uint16 = 108

	// Fixed overhead: header (108) + commitment (32) + trailer magic (8) + length (4).
	RecordOverhead = 152

	MaxPayloadBytes        = 1 << 20 // 1 MiB
	MaxRecordBytes         = RecordOverhead + MaxPayloadBytes
	MaxJournalSegmentBytes = 1 << 30 // 1 GiB advisory
	TransactionIDSize      = 16
	minFramingBytes        = 16 // magic + version + header_length + record_length
)

// RecordMagic is the 8-byte journal record prefix INTJRN01.
var RecordMagic = [8]byte{'I', 'N', 'T', 'J', 'R', 'N', '0', '1'}

// TrailerMagic is the 8-byte journal record trailer INTJRN0T.
var TrailerMagic = [8]byte{'I', 'N', 'T', 'J', 'R', 'N', '0', 'T'}

// RecordType is a journal payload class code.
type RecordType uint16

const (
	TypeObservation       RecordType = 1
	TypePlanDigest        RecordType = 2
	TypeAuthorization     RecordType = 3
	TypeProgress          RecordType = 4
	TypeConfirmation      RecordType = 5
	TypeCancellation      RecordType = 6
	TypeQuarantine        RecordType = 7
	TypeRecovery          RecordType = 8
	TypeCheckpoint        RecordType = 9
	TypeEvidenceReference RecordType = 10
)

// ValidRecordType reports whether t is in the v1 allow-list.
func ValidRecordType(t RecordType) bool {
	return t >= TypeObservation && t <= TypeEvidenceReference
}

// TransactionID is an opaque 16-byte identifier.
type TransactionID = [TransactionIDSize]byte

// RecordFields are the abstract inputs required to encode a journal record.
type RecordFields struct {
	Sequence           uint64
	TransactionID      TransactionID
	Type               RecordType
	PreviousCommitment Digest
	Payload            []byte
}

// Record is a fully decoded, commitment-validated journal record.
type Record struct {
	Sequence           uint64
	TransactionID      TransactionID
	Type               RecordType
	PayloadDigest      Digest
	PreviousCommitment Digest
	Payload            []byte
	RecordCommitment   Digest
	RecordLength       uint32
}

// EncodeRecord encodes fields into a canonical journal record envelope.
// payload length is checked against MaxPayloadBytes before allocation.
func EncodeRecord(f RecordFields) ([]byte, error) {
	if f.Sequence == 0 {
		return nil, nonCanonical("sequence", "must be >= 1")
	}
	if !ValidRecordType(f.Type) {
		return nil, unsupported("record_type", "unknown or zero type")
	}
	if f.Sequence == 1 {
		if f.PreviousCommitment != GenesisCommitment() {
			return nil, nonCanonical("previous_commitment", "genesis must be zero digest")
		}
	}
	payloadLen := len(f.Payload)
	if payloadLen > MaxPayloadBytes {
		return nil, limit("payload", "exceeds MaxPayloadBytes")
	}
	recordLen := RecordOverhead + payloadLen
	if recordLen > MaxRecordBytes {
		return nil, limit("record_length", "exceeds MaxRecordBytes")
	}
	if err := admitRecordBytes(uint64(recordLen)); err != nil {
		return nil, err
	}

	payloadDigest := SHA256(f.Payload)
	out := make([]byte, recordLen)

	copy(out[0:8], RecordMagic[:])
	PutU16LE(out[8:10], FormatVersion)
	PutU16LE(out[10:12], HeaderLength)
	PutU32LE(out[12:16], uint32(recordLen))
	PutU64LE(out[16:24], f.Sequence)
	copy(out[24:40], f.TransactionID[:])
	PutU16LE(out[40:42], uint16(f.Type))
	PutU16LE(out[42:44], 0) // reserved
	copy(out[44:76], payloadDigest[:])
	copy(out[76:108], f.PreviousCommitment[:])
	copy(out[108:108+payloadLen], f.Payload)

	commitment := SHA256(commitmentPreimage(
		uint32(recordLen),
		f.Sequence,
		f.TransactionID,
		f.Type,
		payloadDigest,
		f.PreviousCommitment,
		f.Payload,
	))
	off := 108 + payloadLen
	copy(out[off:off+32], commitment[:])
	copy(out[off+32:off+40], TrailerMagic[:])
	PutU32LE(out[off+40:off+44], uint32(recordLen))
	return out, nil
}

// DecodeRecord decodes one canonical journal record from b.
// Trailing bytes after the record are ignored. n is the record byte length.
// KindIncomplete means the buffer cannot form the declared record (torn candidate).
// Other kinds are fatal for stream readers.
func DecodeRecord(b []byte) (Record, int, error) {
	var zero Record
	if len(b) < 8 {
		return zero, 0, incomplete("record", "truncated before magic")
	}
	if !bytes.Equal(b[0:8], RecordMagic[:]) {
		return zero, 0, nonCanonical("magic", "not RecordMagic")
	}
	if len(b) < minFramingBytes {
		return zero, 0, incomplete("record", "truncated before record_length")
	}

	version := U16LE(b[8:10])
	if version != FormatVersion {
		return zero, 0, unsupported("format_version", "unsupported journal format version")
	}
	headerLen := U16LE(b[10:12])
	if headerLen != HeaderLength {
		return zero, 0, nonCanonical("header_length", "must equal 108 for version 1")
	}
	recordLen := U32LE(b[12:16])
	if recordLen < RecordOverhead {
		return zero, 0, nonCanonical("record_length", "below minimum")
	}
	if recordLen > MaxRecordBytes {
		return zero, 0, limit("record_length", "exceeds MaxRecordBytes")
	}
	if len(b) < int(recordLen) {
		return zero, 0, incomplete("record", "truncated before full record")
	}

	seq := U64LE(b[16:24])
	if seq == 0 {
		return zero, 0, nonCanonical("sequence", "must be >= 1")
	}
	var txid TransactionID
	copy(txid[:], b[24:40])
	rtype := RecordType(U16LE(b[40:42]))
	if !ValidRecordType(rtype) {
		return zero, 0, unsupported("record_type", "unknown or zero type")
	}
	reserved := U16LE(b[42:44])
	if reserved != 0 {
		return zero, 0, nonCanonical("reserved", "must be zero")
	}

	payloadLen := int(recordLen) - RecordOverhead
	if payloadLen < 0 || payloadLen > MaxPayloadBytes {
		return zero, 0, limit("payload", "derived length out of bounds")
	}
	// Admit full record size before allocating the payload copy (INT-IC3-0002).
	if err := admitRecordBytes(uint64(recordLen)); err != nil {
		return zero, 0, err
	}

	var payloadDigest Digest
	copy(payloadDigest[:], b[44:76])
	var prev Digest
	copy(prev[:], b[76:108])
	payload := make([]byte, payloadLen)
	copy(payload, b[108:108+payloadLen])

	if SHA256(payload) != payloadDigest {
		return zero, 0, digestErr("payload_digest", "mismatch")
	}
	if seq == 1 && prev != GenesisCommitment() {
		return zero, 0, nonCanonical("previous_commitment", "genesis must be zero digest")
	}

	off := 108 + payloadLen
	var commitment Digest
	copy(commitment[:], b[off:off+32])
	if !bytes.Equal(b[off+32:off+40], TrailerMagic[:]) {
		return zero, 0, nonCanonical("trailer_magic", "not TrailerMagic")
	}
	trailerLen := U32LE(b[off+40 : off+44])
	if trailerLen != recordLen {
		return zero, 0, nonCanonical("record_length", "trailer duplicate mismatch")
	}

	expected := SHA256(commitmentPreimage(recordLen, seq, txid, rtype, payloadDigest, prev, payload))
	if expected != commitment {
		return zero, 0, digestErr("record_commitment", "mismatch")
	}

	return Record{
		Sequence:           seq,
		TransactionID:      txid,
		Type:               rtype,
		PayloadDigest:      payloadDigest,
		PreviousCommitment: prev,
		Payload:            payload,
		RecordCommitment:   commitment,
		RecordLength:       recordLen,
	}, int(recordLen), nil
}

func commitmentPreimage(
	recordLen uint32,
	seq uint64,
	txid TransactionID,
	rtype RecordType,
	payloadDigest Digest,
	prev Digest,
	payload []byte,
) []byte {
	// magic(8)+ver(2)+hdr(2)+rlen(4)+seq(8)+txid(16)+type(2)+res(2)+pdig(32)+prev(32)+payload
	n := 8 + 2 + 2 + 4 + 8 + TransactionIDSize + 2 + 2 + DigestSize + DigestSize + len(payload)
	buf := make([]byte, n)
	copy(buf[0:8], RecordMagic[:])
	PutU16LE(buf[8:10], FormatVersion)
	PutU16LE(buf[10:12], HeaderLength)
	PutU32LE(buf[12:16], recordLen)
	PutU64LE(buf[16:24], seq)
	copy(buf[24:40], txid[:])
	PutU16LE(buf[40:42], uint16(rtype))
	PutU16LE(buf[42:44], 0)
	copy(buf[44:76], payloadDigest[:])
	copy(buf[76:108], prev[:])
	copy(buf[108:], payload)
	return buf
}
