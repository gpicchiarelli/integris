package plan

import (
	"github.com/gpicchiarelli/integris/internal/codec"
)

// encodePlan builds the canonical binary plan document and returns bytes plus
// the plan_body_digest (SHA-256 of all preceding canonical bytes).
func encodePlan(
	manifestDigest codec.Digest,
	capDigest codec.Digest,
	cfgDigest codec.Digest,
	entries []Entry,
	destructiveDigest codec.Digest,
) ([]byte, codec.Digest, error) {
	if uint64(len(entries)) > uint64(^uint32(0)) {
		return nil, codec.Digest{}, limit("entry_count", "exceeds u32")
	}

	bodyLen, err := measurePlanBody(entries)
	if err != nil {
		return nil, codec.Digest{}, err
	}
	// magic(8)+ver(2)+3*digest(96)+count(4)+entries+destructive(32)+body_digest(32)
	total := 8 + 2 + 96 + 4 + bodyLen + 32 + 32
	buf := make([]byte, 0, total)

	buf = append(buf, PlanMagic[:]...)
	var tmp [4]byte
	codec.PutU16LE(tmp[:2], PlanVersion)
	buf = append(buf, tmp[:2]...)
	buf = append(buf, manifestDigest[:]...)
	buf = append(buf, capDigest[:]...)
	buf = append(buf, cfgDigest[:]...)
	codec.PutU32LE(tmp[:], uint32(len(entries)))
	buf = append(buf, tmp[:]...)

	for _, e := range entries {
		enc, err := encodeEntry(e)
		if err != nil {
			return nil, codec.Digest{}, err
		}
		buf = append(buf, enc...)
	}
	buf = append(buf, destructiveDigest[:]...)

	digest := codec.SHA256(buf)
	buf = append(buf, digest[:]...)
	return buf, digest, nil
}

func measurePlanBody(entries []Entry) (int, error) {
	n := 0
	for _, e := range entries {
		enc, err := encodeEntry(e)
		if err != nil {
			return 0, err
		}
		n += len(enc)
	}
	return n, nil
}

func encodeEntry(e Entry) ([]byte, error) {
	if len(e.Path) > int(^uint16(0)) {
		return nil, limit("path_component_count", "exceeds u16")
	}
	// count(2) + per-comp (2+len) + cap(2)+act(2)+res(2)+rep(2)+aux(32)
	size := 2 + 2 + 2 + 2 + 2 + codec.DigestSize
	for _, c := range e.Path {
		if len(c) > int(^uint16(0)) {
			return nil, limit("component", "exceeds u16 length")
		}
		size += 2 + len(c)
	}
	buf := make([]byte, 0, size)
	var tmp [2]byte
	codec.PutU16LE(tmp[:], uint16(len(e.Path)))
	buf = append(buf, tmp[:]...)
	for _, c := range e.Path {
		codec.PutU16LE(tmp[:], uint16(len(c)))
		buf = append(buf, tmp[:]...)
		buf = append(buf, c...)
	}
	codec.PutU16LE(tmp[:], uint16(e.CapabilityID))
	buf = append(buf, tmp[:]...)
	codec.PutU16LE(tmp[:], uint16(e.Action))
	buf = append(buf, tmp[:]...)
	codec.PutU16LE(tmp[:], uint16(e.Result))
	buf = append(buf, tmp[:]...)
	codec.PutU16LE(tmp[:], e.RepresentationID)
	buf = append(buf, tmp[:]...)
	buf = append(buf, e.AuxDigest[:]...)
	return buf, nil
}

// encodeDestructiveSubset returns the canonical encoding of the destructive
// entry subset used as destructive_summary_digest preimage (IP-S-0002).
func encodeDestructiveSubset(entries []Entry) []byte {
	var buf []byte
	for _, e := range entries {
		if !IsDestructive(e.Action) {
			continue
		}
		enc, err := encodeEntry(e)
		if err != nil {
			// Caller validated entries; treat as empty contribution.
			continue
		}
		buf = append(buf, enc...)
	}
	return buf
}

// Digest returns the plan body digest. Prefer Plan.Digest from Build; this
// recomputes SHA-256 over all bytes except the trailing digest field.
func Digest(p Plan) codec.Digest {
	if len(p.Bytes) < codec.DigestSize {
		return codec.SHA256(p.Bytes)
	}
	return codec.SHA256(p.Bytes[:len(p.Bytes)-codec.DigestSize])
}
