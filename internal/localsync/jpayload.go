package localsync

import (
	"encoding/binary"
	"fmt"

	"github.com/gpicchiarelli/integris/internal/codec"
)

const payloadVersion byte = 1

func putU16(b []byte, v uint16) []byte {
	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], v)
	return append(b, tmp[:]...)
}

func putU32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

func putU64(b []byte, v uint64) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	return append(b, tmp[:]...)
}

func putBytes(b []byte, p []byte) ([]byte, error) {
	if len(p) > 65535 {
		return nil, fmt.Errorf("localsync: payload field too long")
	}
	b = putU16(b, uint16(len(p)))
	return append(b, p...), nil
}

func takeU16(b []byte) (uint16, []byte, error) {
	if len(b) < 2 {
		return 0, nil, fmt.Errorf("localsync: short payload")
	}
	return binary.LittleEndian.Uint16(b[:2]), b[2:], nil
}

func takeU32(b []byte) (uint32, []byte, error) {
	if len(b) < 4 {
		return 0, nil, fmt.Errorf("localsync: short payload")
	}
	return binary.LittleEndian.Uint32(b[:4]), b[4:], nil
}

func takeU64(b []byte) (uint64, []byte, error) {
	if len(b) < 8 {
		return 0, nil, fmt.Errorf("localsync: short payload")
	}
	return binary.LittleEndian.Uint64(b[:8]), b[8:], nil
}

func takeBytes(b []byte) ([]byte, []byte, error) {
	n, rest, err := takeU16(b)
	if err != nil {
		return nil, nil, err
	}
	if uint16(len(rest)) < n {
		return nil, nil, fmt.Errorf("localsync: short payload bytes")
	}
	return rest[:n], rest[n:], nil
}

func encodeObservation(src, dst string) ([]byte, error) {
	b := []byte{payloadVersion}
	var err error
	if b, err = putBytes(b, []byte(src)); err != nil {
		return nil, err
	}
	if b, err = putBytes(b, []byte(dst)); err != nil {
		return nil, err
	}
	return b, nil
}

func decodeObservation(p []byte) (src, dst string, err error) {
	if len(p) < 1 || p[0] != payloadVersion {
		return "", "", fmt.Errorf("localsync: bad observation version")
	}
	rest := p[1:]
	var sb, db []byte
	if sb, rest, err = takeBytes(rest); err != nil {
		return "", "", err
	}
	if db, rest, err = takeBytes(rest); err != nil {
		return "", "", err
	}
	if len(rest) != 0 {
		return "", "", fmt.Errorf("localsync: trailing observation bytes")
	}
	return string(sb), string(db), nil
}

func encodePlanDigest(d codec.Digest, opCount uint32) []byte {
	b := []byte{payloadVersion}
	b = append(b, d[:]...)
	return putU32(b, opCount)
}

func decodePlanDigest(p []byte) (codec.Digest, uint32, error) {
	var d codec.Digest
	if len(p) < 1+32+4 || p[0] != payloadVersion {
		return d, 0, fmt.Errorf("localsync: bad plan_digest payload")
	}
	copy(d[:], p[1:33])
	n := binary.LittleEndian.Uint32(p[33:37])
	if len(p) != 37 {
		return d, 0, fmt.Errorf("localsync: trailing plan_digest bytes")
	}
	return d, n, nil
}

func encodeAuthz(planDig codec.Digest) []byte {
	const label = "local-unidirectional-v1"
	b := []byte{payloadVersion}
	b = append(b, byte(len(label)))
	b = append(b, label...)
	b = append(b, planDig[:]...)
	return b
}

func encodeProgress(opIndex uint32, action Action, rel string, bytesCum uint64) ([]byte, error) {
	b := []byte{payloadVersion}
	b = putU32(b, opIndex)
	var err error
	if b, err = putBytes(b, []byte(action)); err != nil {
		return nil, err
	}
	if b, err = putBytes(b, []byte(rel)); err != nil {
		return nil, err
	}
	b = putU64(b, bytesCum)
	return b, nil
}

func decodeProgress(p []byte) (opIndex uint32, action Action, rel string, bytesCum uint64, err error) {
	if len(p) < 1 || p[0] != payloadVersion {
		return 0, "", "", 0, fmt.Errorf("localsync: bad progress version")
	}
	rest := p[1:]
	if opIndex, rest, err = takeU32(rest); err != nil {
		return 0, "", "", 0, err
	}
	var ab, rb []byte
	if ab, rest, err = takeBytes(rest); err != nil {
		return 0, "", "", 0, err
	}
	if rb, rest, err = takeBytes(rest); err != nil {
		return 0, "", "", 0, err
	}
	if bytesCum, rest, err = takeU64(rest); err != nil {
		return 0, "", "", 0, err
	}
	if len(rest) != 0 {
		return 0, "", "", 0, fmt.Errorf("localsync: trailing progress bytes")
	}
	return opIndex, Action(ab), string(rb), bytesCum, nil
}

func encodeConfirmation(planDig codec.Digest, completed, skipped uint32, bytes uint64) []byte {
	b := []byte{payloadVersion}
	b = append(b, planDig[:]...)
	b = putU32(b, completed)
	b = putU32(b, skipped)
	return putU64(b, bytes)
}

func encodeCancellation(reason string) ([]byte, error) {
	b := []byte{payloadVersion}
	return putBytes(b, []byte(reason))
}

func encodeRecovery(nextOp uint32, reason string) ([]byte, error) {
	b := []byte{payloadVersion}
	b = putU32(b, nextOp)
	return putBytes(b, []byte(reason))
}
