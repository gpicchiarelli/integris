package journal

import (
	"github.com/gpicchiarelli/integris/internal/codec"
)

// Writer appends canonical records to a Segment. It never overwrites the
// committed prefix. The new sequence is exposed only after Append returns.
type Writer struct {
	seg            Segment
	nextSeq        uint64
	prevCommitment codec.Digest
	closed         bool
}

// OpenWriter recovers writer state from the longest valid prefix of seg.
// A torn tail is allowed: the writer continues after the accepted prefix and
// does not repair or overwrite quarantine bytes (caller must truncate/rotate).
func OpenWriter(seg Segment) (*Writer, Prefix, error) {
	p, err := ReadPrefix(seg)
	if err != nil {
		return nil, Prefix{}, err
	}
	w := &Writer{
		seg:            seg,
		nextSeq:        p.NextSequence,
		prevCommitment: p.HeadCommitment,
	}
	if p.NextSequence == 1 {
		w.prevCommitment = codec.GenesisCommitment()
	}
	return w, p, nil
}

// NextSequence returns the sequence number that will be assigned next.
func (w *Writer) NextSequence() uint64 {
	return w.nextSeq
}

// HeadCommitment returns the commitment of the last committed record, or
// genesis zeros when the journal is empty.
func (w *Writer) HeadCommitment() codec.Digest {
	return w.prevCommitment
}

// Append encodes and appends one record. Payload is copied into the envelope;
// the caller retains ownership of payload.
func (w *Writer) Append(txid codec.TransactionID, rtype codec.RecordType, payload []byte) (codec.Record, error) {
	var zero codec.Record
	if w == nil || w.closed {
		return zero, &Error{Kind: KindClosed, Message: "writer closed"}
	}
	if w.seg.Size() > 0 && w.nextSeq == 1 {
		// Non-empty segment with nextSeq 1 implies unreadable fatal state was
		// somehow bypassed; refuse.
		return zero, &Error{Kind: KindState, Message: "refusing append on inconsistent empty head"}
	}
	// Refuse append while a torn quarantine remains beyond Bytes.
	// Callers must Truncate to the accepted prefix before continuing.
	p, err := ReadPrefix(w.seg)
	if err != nil {
		return zero, err
	}
	if p.Torn {
		return zero, &Error{
			Kind:    KindState,
			Offset:  p.TornOffset,
			Message: "torn tail present; truncate quarantine before append",
		}
	}
	if p.NextSequence != w.nextSeq {
		return zero, &Error{Kind: KindState, Message: "writer sequence diverged from segment"}
	}

	fields := codec.RecordFields{
		Sequence:           w.nextSeq,
		TransactionID:      txid,
		Type:               rtype,
		PreviousCommitment: w.prevCommitment,
		Payload:            payload,
	}
	enc, err := codec.EncodeRecord(fields)
	if err != nil {
		return zero, err
	}
	if w.seg.Size()+int64(len(enc)) > codec.MaxJournalSegmentBytes {
		return zero, &Error{
			Kind:    KindFatal,
			Message: "append would exceed MaxJournalSegmentBytes",
		}
	}
	if err := w.seg.Append(enc); err != nil {
		return zero, err
	}
	if err := w.seg.Sync(); err != nil {
		return zero, err
	}
	rec, _, err := codec.DecodeRecord(enc)
	if err != nil {
		return zero, fatal(w.seg.Size()-int64(len(enc)), "encoded record failed self-decode", err)
	}
	w.prevCommitment = rec.RecordCommitment
	w.nextSeq++
	return rec, nil
}

// Close marks the writer unusable. It does not close the underlying Segment.
func (w *Writer) Close() error {
	w.closed = true
	return nil
}
