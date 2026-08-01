package recovery

import (
	"bytes"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/observability"
)

func emit(policy Policy, id, cause, message string, txid codec.TransactionID) {
	if policy.Events == nil {
		return
	}
	sev := observability.SeverityWarning
	ch := observability.ChannelSecurity
	if id == "recovery.confirmed" {
		sev = observability.SeverityInfo
		ch = observability.ChannelOperational
	}
	_ = policy.Events.Emit(observability.Event{
		ID:            observability.EventID(id),
		Channel:       ch,
		Severity:      sev,
		Component:     "recovery",
		TransactionID: txid,
		CauseCategory: cause,
		Redaction:     observability.RedactionInternal,
		Message:       message,
	})
}

// abstractFlags refine TLA+ variables from journal + observations.
type abstractFlags struct {
	txid               codec.TransactionID
	hasTx              bool
	planDigestSeen     bool
	authorized         bool
	contentReceived    bool
	prepared           bool
	contentVerified    bool
	publicationStarted bool
	published          bool
	confirmationCount  int
	cancelled          bool
	quarantined        bool
	recoveryRecords    int
	binding            *AuthorizationBinding
	contradiction      string
}

// Recover reconstructs transaction state from a longest-valid journal prefix
// and filesystem observations. It never widens authority or invents
// authorization/publication. io may be nil when no side effects are required;
// confirmation and staging mutations require a non-nil PersistIO.
func Recover(prefix journal.Prefix, obs FSObservation, policy Policy, io PersistIO) (Outcome, error) {
	flags, err := scanPrefix(prefix)
	if err != nil {
		return Outcome{}, err
	}

	out := Outcome{
		TornTail:      prefix.Torn,
		TransactionID: flags.txid,
		Authorized:    flags.authorized,
		Confirmations: flags.confirmationCount,
		Binding:       flags.binding,
	}

	// Identity mismatch with recorded authorization → stop closed.
	if flags.binding != nil {
		if flags.binding.RootIdentity != obs.RootIdentity || flags.binding.VolumeIdentity != obs.VolumeIdentity {
			out.State = StateIrrecoverable
			out.IdempotentNoop = true
			out.RecoveryCount = 1
			emit(policy, "recovery.irrecoverable", "identity", "root/volume identity mismatch", flags.txid)
			return out, identityErr("root/volume identity mismatch with authorization")
		}
	}

	if flags.contradiction != "" {
		out.State = StateIrrecoverable
		out.IdempotentNoop = true
		out.RecoveryCount = 1
		emit(policy, "recovery.irrecoverable", "records", flags.contradiction, flags.txid)
		return out, fatal("records", flags.contradiction, nil)
	}

	if flags.confirmationCount > 1 {
		out.State = StateIrrecoverable
		out.IdempotentNoop = true
		out.RecoveryCount = 1
		emit(policy, "recovery.irrecoverable", "confirmation", "more than one confirmation record", flags.txid)
		return out, fatal("confirmation", "more than one confirmation record", nil)
	}

	// Publication is observed, never invented from journal alone.
	linearized := obs.PublicationLinearized && obs.PublishedContentMatches
	if linearized {
		if !flags.authorized || !flags.prepared || !flags.contentVerified || !flags.contentReceived {
			out.State = StateIrrecoverable
			out.IdempotentNoop = true
			out.RecoveryCount = 1
			emit(policy, "recovery.irrecoverable", "publication", "publication without authorization chain", flags.txid)
			return out, fatal("publication", "linearized publication without authorization/preparation chain", nil)
		}
		flags.published = true
		flags.publicationStarted = true
	} else if obs.PublicationStarted || flags.publicationStarted {
		flags.publicationStarted = true
	}
	out.Published = flags.published

	// Empty / nothing durable: no recovery work.
	if len(prefix.Records) == 0 && !prefix.Torn && !obs.StagingPresent && !obs.PublicationStarted && !obs.PublicationLinearized {
		out.State = StateCreated
		out.IdempotentNoop = true
		out.Actions = []Action{{Kind: ActionNoop}}
		return out, nil
	}

	needsRecovery := !terminalFromFlags(flags) || prefix.Torn ||
		(obs.StagingPresent && !flags.published) ||
		(flags.publicationStarted && !flags.published)

	if !needsRecovery && terminalFromFlags(flags) {
		out.State = stateFromFlags(flags)
		out.IdempotentNoop = true
		out.RecoveryCount = 1
		out.Actions = []Action{{Kind: ActionNoop}}
		return out, nil
	}

	out.Actions = append(out.Actions, Action{Kind: ActionEnterRecovering})
	out.State = StateRecovering

	// Already confirmed: remain CONFIRMED (at most once).
	if flags.confirmationCount == 1 {
		if !flags.published {
			// Confirmation without publication evidence is contradictory.
			out.State = StateIrrecoverable
			out.IdempotentNoop = true
			out.RecoveryCount = 1
			emit(policy, "recovery.irrecoverable", "confirmation", "confirmation without publication", flags.txid)
			return out, fatal("confirmation", "confirmation without publication evidence", nil)
		}
		out.State = StateConfirmed
		out.IdempotentNoop = true
		out.RecoveryCount = 1
		return out, nil
	}

	if flags.cancelled && !flags.publicationStarted && !flags.published {
		if err := maybeCleanup(policy, io, &out, obs); err != nil {
			return out, err
		}
		out.State = StateCancelled
		out.IdempotentNoop = true
		out.RecoveryCount = 1
		return out, nil
	}

	if flags.quarantined && !flags.published {
		if err := maybeQuarantine(policy, io, &out, obs); err != nil {
			return out, err
		}
		out.State = StateQuarantined
		out.IdempotentNoop = true
		out.RecoveryCount = 1
		return out, nil
	}

	// Published path: optionally confirm once.
	if flags.published {
		out.State = StatePublished
		if policy.AllowConfirm && io != nil {
			if err := confirmOnce(flags.txid, io, &out); err != nil {
				return out, err
			}
			out.State = StateConfirmed
			out.Confirmations = 1
			emit(policy, "recovery.confirmed", "confirm", "confirmation appended", flags.txid)
		}
		out.IdempotentNoop = true
		out.RecoveryCount = 1
		return out, nil
	}

	// Not linearized: do not invent PUBLISHED; quarantine/cancel staging.
	if err := maybeQuarantine(policy, io, &out, obs); err != nil {
		return out, err
	}
	out.State = StateQuarantined
	out.IdempotentNoop = true
	out.RecoveryCount = 1
	out.Published = false
	return out, nil
}

func terminalFromFlags(f abstractFlags) bool {
	if f.confirmationCount == 1 && f.published {
		return true
	}
	if f.cancelled && !f.publicationStarted {
		return true
	}
	if f.quarantined && !f.published && !f.publicationStarted {
		return true
	}
	return false
}

func stateFromFlags(f abstractFlags) State {
	if f.confirmationCount == 1 && f.published {
		return StateConfirmed
	}
	if f.cancelled {
		return StateCancelled
	}
	if f.quarantined {
		return StateQuarantined
	}
	if f.published {
		return StatePublished
	}
	return StateQuarantined
}

func scanPrefix(prefix journal.Prefix) (abstractFlags, error) {
	var f abstractFlags
	for _, rec := range prefix.Records {
		if !f.hasTx {
			f.txid = rec.TransactionID
			f.hasTx = true
		} else if rec.TransactionID != f.txid {
			f.contradiction = "multiple transaction ids in prefix"
			return f, nil
		}
		switch rec.Type {
		case codec.TypePlanDigest:
			f.planDigestSeen = true
		case codec.TypeAuthorization:
			if f.authorized {
				f.contradiction = "duplicate authorization"
				return f, nil
			}
			b, err := DecodeAuthorizationPayload(rec.Payload)
			if err != nil {
				return f, err
			}
			f.binding = &b
			f.authorized = true
		case codec.TypeProgress:
			if len(rec.Payload) < 2 {
				f.contradiction = "progress payload too short"
				return f, nil
			}
			code := ProgressCode(codec.U16LE(rec.Payload[:2]))
			switch code {
			case ProgressContentReceived:
				f.contentReceived = true
			case ProgressPrepared:
				f.prepared = true
			case ProgressVerified:
				f.contentVerified = true
			case ProgressPublishing:
				f.publicationStarted = true
			default:
				f.contradiction = "unknown progress code"
				return f, nil
			}
		case codec.TypeConfirmation:
			f.confirmationCount++
		case codec.TypeCancellation:
			f.cancelled = true
		case codec.TypeQuarantine:
			f.quarantined = true
		case codec.TypeRecovery:
			f.recoveryRecords++
		case codec.TypeObservation, codec.TypeCheckpoint, codec.TypeEvidenceReference:
			// Informational; no flag change.
		default:
			f.contradiction = "unsupported record type in recovery scan"
			return f, nil
		}
	}

	// Authorization without prior plan digest is allowed if plan digest is
	// embedded in the binding; require binding plan digest non-zero when authorized.
	if f.authorized && f.binding != nil && !f.planDigestSeen {
		if f.binding.PlanDigest == (codec.Digest{}) {
			f.contradiction = "authorization missing plan digest binding"
		}
	}
	// Model: published requires preparation chain — checked when observing linearization.
	if f.prepared && !f.contentReceived {
		f.contradiction = "prepared without content received"
	}
	if f.contentVerified && !(f.prepared && f.contentReceived) {
		f.contradiction = "verified without preparation chain"
	}
	if f.publicationStarted && !(f.authorized && f.contentVerified) {
		f.contradiction = "publication started without authorization/verification"
	}
	return f, nil
}

func maybeCleanup(policy Policy, io PersistIO, out *Outcome, obs FSObservation) error {
	if !policy.AllowStagingCleanup || io == nil || !obs.StagingPresent {
		return nil
	}
	if err := io.Checkpoint(LabelPStageCreate); err != nil {
		return err
	}
	if err := io.CleanupStaging(); err != nil {
		return ioErr(LabelPStageCreate, err)
	}
	out.Actions = append(out.Actions, Action{Kind: ActionCleanupStaging, Label: LabelPStageCreate})
	return nil
}

func maybeQuarantine(policy Policy, io PersistIO, out *Outcome, obs FSObservation) error {
	if !policy.AllowStagingCleanup || io == nil {
		return nil
	}
	if !obs.StagingPresent && !obs.PublicationStarted {
		return nil
	}
	if err := io.Checkpoint(LabelPPublishRename); err != nil {
		return err
	}
	if err := io.QuarantineStaging(); err != nil {
		return ioErr(LabelPPublishRename, err)
	}
	out.Actions = append(out.Actions, Action{Kind: ActionQuarantineStaging, Label: LabelPPublishRename})
	return nil
}

func confirmOnce(txid codec.TransactionID, io PersistIO, out *Outcome) error {
	if err := io.Checkpoint(LabelPConfirmPre); err != nil {
		return err
	}
	if err := io.AppendConfirmation(txid, nil); err != nil {
		return ioErr(LabelPConfirmPre, err)
	}
	if err := io.Checkpoint(LabelPConfirmPost); err != nil {
		return err
	}
	out.Actions = append(out.Actions, Action{Kind: ActionConfirm, Label: LabelPConfirmPost})
	return nil
}

// RecoverAgain re-enters recovery on the same inputs. It is identical to Recover
// and exists so callers can document idempotent re-entry (IP-S-0003).
func RecoverAgain(prefix journal.Prefix, obs FSObservation, policy Policy, io PersistIO) (Outcome, error) {
	return Recover(prefix, obs, policy, io)
}

// SameBinding reports whether two digests are equal (test helper surface).
func SameBinding(a, b codec.Digest) bool {
	return bytes.Equal(a[:], b[:])
}
