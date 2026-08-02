package localsync

import (
	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
)

// txnState is reconstructed from a journal prefix for one local sync transaction.
type txnState struct {
	ID          codec.TransactionID
	Source      string
	Destination string
	PlanDigest  codec.Digest
	HasPlan     bool
	OpCount     uint32
	// NextOp is the next plan index to apply (0-based). Progress records bump it.
	NextOp     int
	BytesCum   uint64
	Confirmed  bool
	Cancelled  bool
	Authorized bool
}

// inspectPrefix derives the latest incomplete or confirmed local-sync txn state.
func inspectPrefix(p journal.Prefix) (txnState, bool) {
	var cur txnState
	var found bool
	for _, rec := range p.Records {
		switch rec.Type {
		case codec.TypeObservation:
			src, dst, err := decodeObservation(rec.Payload)
			if err != nil {
				continue
			}
			cur = txnState{ID: rec.TransactionID, Source: src, Destination: dst}
			found = true
		case codec.TypePlanDigest:
			if rec.TransactionID != cur.ID {
				continue
			}
			d, n, err := decodePlanDigest(rec.Payload)
			if err != nil {
				continue
			}
			cur.PlanDigest = d
			cur.OpCount = n
			cur.HasPlan = true
			cur.NextOp = 0
			cur.BytesCum = 0
			cur.Confirmed = false
			cur.Cancelled = false
		case codec.TypeAuthorization:
			if rec.TransactionID == cur.ID {
				cur.Authorized = true
			}
		case codec.TypeProgress:
			if rec.TransactionID != cur.ID {
				continue
			}
			idx, _, _, bytesCum, err := decodeProgress(rec.Payload)
			if err != nil {
				continue
			}
			cur.NextOp = int(idx) + 1
			cur.BytesCum = bytesCum
		case codec.TypeConfirmation:
			if rec.TransactionID == cur.ID {
				cur.Confirmed = true
			}
		case codec.TypeCancellation:
			if rec.TransactionID == cur.ID {
				cur.Cancelled = true
			}
		case codec.TypeRecovery:
			if rec.TransactionID == cur.ID {
				// recovery is informational; NextOp comes from progress
			}
		}
	}
	if !found || cur.Cancelled {
		return txnState{}, false
	}
	return cur, true
}
