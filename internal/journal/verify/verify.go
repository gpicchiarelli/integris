// Package verify is a read-only journal verifier that depends only on
// internal/codec (public format constants) and not on journal writer state.
package verify

import (
	"github.com/gpicchiarelli/integris/internal/codec"
)

// Result is the longest valid prefix accepted by the independent verifier.
type Result struct {
	RecordCount    int
	Bytes          int64
	HeadCommitment codec.Digest
	NextSequence   uint64
	Torn           bool
	TornOffset     int64
	Fatal          bool
	FatalOffset    int64
	Err            error
}

// VerifyBytes scans data for the longest valid journal prefix using only codec
// decode helpers. It does not import the journal writer package.
func VerifyBytes(data []byte) Result {
	res := Result{NextSequence: 1}
	if len(data) == 0 {
		return res
	}

	var (
		offset   int
		expected uint64 = 1
		prev     codec.Digest
	)

	for offset < len(data) {
		rec, n, err := codec.DecodeRecord(data[offset:])
		if err != nil {
			if codec.AsKind(err, codec.KindIncomplete) {
				res.Torn = true
				res.TornOffset = int64(offset)
				res.Err = err
				return res
			}
			res.Fatal = true
			res.FatalOffset = int64(offset)
			res.Err = err
			return res
		}
		if rec.Sequence != expected {
			res.Fatal = true
			res.FatalOffset = int64(offset)
			res.Err = errSeq
			return res
		}
		if expected == 1 {
			if rec.PreviousCommitment != codec.GenesisCommitment() {
				res.Fatal = true
				res.FatalOffset = int64(offset)
				res.Err = errGenesis
				return res
			}
		} else if rec.PreviousCommitment != prev {
			res.Fatal = true
			res.FatalOffset = int64(offset)
			res.Err = errFork
			return res
		}
		res.RecordCount++
		res.Bytes += int64(n)
		res.HeadCommitment = rec.RecordCommitment
		res.NextSequence = rec.Sequence + 1
		prev = rec.RecordCommitment
		expected++
		offset += n
	}
	return res
}

type verifyError string

func (e verifyError) Error() string { return string(e) }

const (
	errSeq     verifyError = "verify: sequence gap or restart"
	errGenesis verifyError = "verify: genesis previous_commitment mismatch"
	errFork    verifyError = "verify: previous_commitment fork"
)
