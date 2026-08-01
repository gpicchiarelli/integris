package journal

import (
	"io"

	"github.com/gpicchiarelli/integris/internal/codec"
)

// Prefix is the longest accepted valid journal prefix.
type Prefix struct {
	Records        []codec.Record
	Bytes          int64
	HeadCommitment codec.Digest
	NextSequence   uint64
	Torn           bool
	TornOffset     int64
	Quarantine     []byte // tail bytes after accepted prefix when Torn
}

// ReadPrefix scans seg for the longest fully delimited, canonical,
// commitment-valid, strictly monotonic prefix.
//
// A torn incomplete final record yields Prefix.Torn=true with the prior
// records accepted and Quarantine holding the incomplete tail.
// Interior corruption returns a KindFatal error; Records may be empty.
func ReadPrefix(seg Segment) (Prefix, error) {
	size := seg.Size()
	if size < 0 {
		return Prefix{}, fatal(0, "negative segment size", nil)
	}
	if size == 0 {
		return Prefix{NextSequence: 1}, nil
	}

	var (
		out      Prefix
		offset   int64
		expected uint64 = 1
		prev     codec.Digest
	)
	out.NextSequence = 1

	for offset < size {
		remaining := size - offset
		// Bound the peek buffer: never allocate more than MaxRecordBytes.
		want := remaining
		if want > int64(codec.MaxRecordBytes) {
			want = int64(codec.MaxRecordBytes)
		}
		buf := make([]byte, want)
		n, err := seg.ReadAt(buf, offset)
		if n == 0 && err != nil {
			if err == io.EOF {
				break
			}
			return Prefix{}, fatal(offset, "read failed", err)
		}
		buf = buf[:n]

		rec, recLen, derr := codec.DecodeRecord(buf)
		if derr != nil {
			je := classifyDecode(offset, derr)
			if je.Kind == KindTornTail {
				out.Torn = true
				out.TornOffset = offset
				qLen := remaining
				if qLen > int64(codec.MaxRecordBytes) {
					qLen = int64(codec.MaxRecordBytes)
				}
				out.Quarantine = make([]byte, qLen)
				n, rerr := seg.ReadAt(out.Quarantine, offset)
				if n >= 0 {
					out.Quarantine = out.Quarantine[:n]
				}
				if rerr != nil && rerr != io.EOF && n == 0 {
					return Prefix{}, fatal(offset, "quarantine read failed", rerr)
				}
				return out, nil
			}
			return Prefix{}, je
		}

		// Chain and monotonicity checks (fatal on violation).
		if rec.Sequence != expected {
			return Prefix{}, fatal(offset, "sequence gap or restart", nil)
		}
		if expected == 1 {
			if rec.PreviousCommitment != codec.GenesisCommitment() {
				return Prefix{}, fatal(offset, "genesis previous_commitment mismatch", nil)
			}
		} else if rec.PreviousCommitment != prev {
			return Prefix{}, fatal(offset, "previous_commitment fork", nil)
		}

		out.Records = append(out.Records, rec)
		out.Bytes += int64(recLen)
		out.HeadCommitment = rec.RecordCommitment
		out.NextSequence = rec.Sequence + 1
		prev = rec.RecordCommitment
		expected++
		offset += int64(recLen)
	}
	return out, nil
}

// ReadPrefixBytes is ReadPrefix over an in-memory byte slice.
func ReadPrefixBytes(data []byte) (Prefix, error) {
	seg := &MemSegment{buf: append([]byte{}, data...)}
	return ReadPrefix(seg)
}
