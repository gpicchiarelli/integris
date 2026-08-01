package recovery

import (
	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/observability"
)

// State is a transaction state from formal/transaction and the transaction spec.
type State string

const (
	StateCreated          State = "CREATED"
	StateAuthenticated    State = "AUTHENTICATED"
	StateManifestVerified State = "MANIFEST_VERIFIED"
	StatePlanned          State = "PLANNED"
	StateAuthorized       State = "AUTHORIZED"
	StateContentReceived  State = "CONTENT_RECEIVED"
	StatePrepared         State = "PREPARED"
	StateVerified         State = "VERIFIED"
	StatePublishing       State = "PUBLISHING"
	StatePublished        State = "PUBLISHED"
	StateConfirmed        State = "CONFIRMED"
	StateSuspended        State = "SUSPENDED"
	StateCancelled        State = "CANCELLED"
	StateQuarantined      State = "QUARANTINED"
	StateRecovering       State = "RECOVERING"
	StateIrrecoverable    State = "IRRECOVERABLE"
)

// CrashLabel names a persistence boundary for fault injection (IP-S-0003).
type CrashLabel string

const (
	LabelJAppendPre      CrashLabel = "J-APPEND-PRE"
	LabelJAppendMid      CrashLabel = "J-APPEND-MID"
	LabelJAppendPost     CrashLabel = "J-APPEND-POST"
	LabelJMetaPost       CrashLabel = "J-META-POST"
	LabelPStageCreate    CrashLabel = "P-STAGE-CREATE"
	LabelPStageSync      CrashLabel = "P-STAGE-SYNC"
	LabelPPublishRename  CrashLabel = "P-PUBLISH-RENAME"
	LabelPPublishDirSync CrashLabel = "P-PUBLISH-DIRSYNC"
	LabelPConfirmPre     CrashLabel = "P-CONFIRM-PRE"
	LabelPConfirmPost    CrashLabel = "P-CONFIRM-POST"
)

// AllCrashLabels is the minimum M1 catalog.
var AllCrashLabels = []CrashLabel{
	LabelJAppendPre,
	LabelJAppendMid,
	LabelJAppendPost,
	LabelJMetaPost,
	LabelPStageCreate,
	LabelPStageSync,
	LabelPPublishRename,
	LabelPPublishDirSync,
	LabelPConfirmPre,
	LabelPConfirmPost,
}

// ProgressCode is the M1 TypeProgress payload discriminator (u16le at offset 0).
type ProgressCode uint16

const (
	ProgressContentReceived ProgressCode = 1
	ProgressPrepared        ProgressCode = 2
	ProgressVerified        ProgressCode = 3
	ProgressPublishing      ProgressCode = 4
)

// AuthorizationBinding is the M1 TypeAuthorization payload layout (192 bytes).
const AuthorizationPayloadSize = 192

// AuthorizationBinding fields extracted from a TypeAuthorization payload.
type AuthorizationBinding struct {
	PlanDigest             codec.Digest
	ConfigurationDigest    codec.Digest
	CapabilityVectorDigest codec.Digest
	RootIdentity           codec.Digest
	VolumeIdentity         codec.Digest
	AuthDigest             codec.Digest
}

// DecodeAuthorizationPayload parses a 192-byte authorization payload.
func DecodeAuthorizationPayload(p []byte) (AuthorizationBinding, error) {
	var zero AuthorizationBinding
	if len(p) != AuthorizationPayloadSize {
		return zero, stateErr("authorization payload must be 192 bytes")
	}
	var b AuthorizationBinding
	copy(b.PlanDigest[:], p[0:32])
	copy(b.ConfigurationDigest[:], p[32:64])
	copy(b.CapabilityVectorDigest[:], p[64:96])
	copy(b.RootIdentity[:], p[96:128])
	copy(b.VolumeIdentity[:], p[128:160])
	copy(b.AuthDigest[:], p[160:192])
	return b, nil
}

// EncodeAuthorizationPayload encodes a binding for tests and harnesses.
func EncodeAuthorizationPayload(b AuthorizationBinding) []byte {
	out := make([]byte, AuthorizationPayloadSize)
	copy(out[0:32], b.PlanDigest[:])
	copy(out[32:64], b.ConfigurationDigest[:])
	copy(out[64:96], b.CapabilityVectorDigest[:])
	copy(out[96:128], b.RootIdentity[:])
	copy(out[128:160], b.VolumeIdentity[:])
	copy(out[160:192], b.AuthDigest[:])
	return out
}

// EncodeProgressPayload encodes a TypeProgress payload.
func EncodeProgressPayload(code ProgressCode) []byte {
	out := make([]byte, 2)
	codec.PutU16LE(out, uint16(code))
	return out
}

// FSObservation is the caller-supplied filesystem observation under the archive root.
type FSObservation struct {
	RootIdentity            codec.Digest
	VolumeIdentity          codec.Digest
	StagingPresent          bool
	PublicationStarted      bool
	PublicationLinearized   bool
	PublishedContentMatches bool // published bytes consistent with authorization chain
}

// Policy controls recovery side effects. Destructive actions default disabled.
type Policy struct {
	// AllowStagingCleanup permits existence-tolerant staging removal/quarantine.
	AllowStagingCleanup bool
	// AllowConfirm permits appending a confirmation record when published and
	// not yet confirmed. Default false (Go profile: destructive defaults off).
	AllowConfirm bool
	// Events receives optional redacted operational/security events. Emission
	// failures never fail Recover (observability is not integrity evidence).
	Events observability.Sink
}

// ActionKind names an effect performed during recovery (harness accounting).
type ActionKind string

const (
	ActionEnterRecovering   ActionKind = "enter_recovering"
	ActionCleanupStaging    ActionKind = "cleanup_staging"
	ActionQuarantineStaging ActionKind = "quarantine_staging"
	ActionConfirm           ActionKind = "confirm"
	ActionNoop              ActionKind = "noop"
)

// Action is one recorded recovery effect.
type Action struct {
	Kind  ActionKind
	Label CrashLabel
}

// Outcome is the result of Recover.
type Outcome struct {
	State          State
	Actions        []Action
	IdempotentNoop bool // true when a second Recover must be a no-op at this state
	TornTail       bool
	TransactionID  codec.TransactionID
	Authorized     bool
	Published      bool
	Confirmations  int
	RecoveryCount  int // abstract recoveryCount after this call (0 or 1+)
	Binding        *AuthorizationBinding
}

// Terminal reports whether s is a stable terminal/side state for RecoverAgain.
func Terminal(s State) bool {
	switch s {
	case StatePublished, StateConfirmed, StateCancelled, StateQuarantined, StateIrrecoverable:
		return true
	default:
		return false
	}
}
