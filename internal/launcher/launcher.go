// Package launcher starts supervised child role processes per IP-A-0003.
// Only this package may import os/exec (see docs/go-profile.md).
package launcher

import (
	"os"
	"time"

	"github.com/gpicchiarelli/integris/internal/authority"
)

// Env keys conferred in engineering mode only (no MAC key material).
const (
	EnvRole          = "INTEGRIS_ROLE"
	EnvPeer          = "INTEGRIS_PEER"
	EnvNonce         = "INTEGRIS_NONCE_HEX"
	EnvMode          = "INTEGRIS_LAUNCH_MODE"
	EnvKeyTransport  = "INTEGRIS_KEY_TRANSPORT"
	EnvConfer        = "INTEGRIS_CONFER"
	EnvSlots         = "INTEGRIS_SLOTS"
	EnvAllowRoots    = "INTEGRIS_ALLOW_ROOTS"
	EnvAllowRootFDs  = "INTEGRIS_ALLOW_ROOT_FDS"
	EnvStubMode      = "INTEGRIS_STUB_MODE"
	EnvListenAddr    = "INTEGRIS_LISTEN_ADDR"
	EnvOnce          = "INTEGRIS_ONCE"
	EnvReadyPath     = "INTEGRIS_READY_PATH"
	EnvHasRootKey    = "INTEGRIS_HAS_ROOT_KEY"
	EnvExtraPeer     = "INTEGRIS_EXTRA_PEER"
	ModeEngineering  = "engineering"
	ModeRelease      = "release" // M2k strict launch; not a product IC-1 claim
	StubModeRespond  = "respond"
	StubModeInitiate = "initiate"
	// Hold modes (M2n): one IPC exchange, then RecvPeerFDFile on the key
	// channel, swap IPC, second exchange. Used with Runtime.RestartOne.
	StubModeHoldRespond  = "hold-respond"
	StubModeHoldInitiate = "hold-initiate"
	// IPCFileFD is the child's inherited IPC socket (ExtraFiles[0] → fd 3).
	IPCFileFD = 3
	// KeyFileFD is the child's inherited sealed MAC-key FD when using the
	// legacy ExtraFiles path (ExtraFiles[1] → fd 4).
	KeyFileFD = 4
	// RootKeyFileFD is the optional push-root key FD when KeyViaExtraFiles and
	// Request.RootKey are set (ExtraFiles[2] → fd 5).
	RootKeyFileFD = 5
	// KeyChannelFDSCM is a dedicated socketpair end for SCM_RIGHTS key FDs (M2l).
	// Layout: fd3=primary IPC, fd4=key channel, [fd5=extra IPC], then allow-roots.
	KeyChannelFDSCM = 4
	// ExtraPeerSocketFDSCM is the ExtraPeer IPC socket when keys use SCM_RIGHTS.
	ExtraPeerSocketFDSCM = 5
	// Allow-root directory FDs (FreeBSD Capsicum) follow the socket, key, and
	// optional root key: ExtraFiles[i] → fd 3+i.
)

// ExtraPeerSocketFD is the inherited FD for ExtraSocket when KeyViaExtraFiles.
// Layout: fd3=primary sock, fd4=primary key, [fd5=root key], then extra sock/key.
func ExtraPeerSocketFD(hasRootKey bool) int {
	if hasRootKey {
		return 6
	}
	return 5
}

// ExtraPeerKeyFD is the inherited FD for ExtraMACKey (adjacent to ExtraPeerSocketFD).
func ExtraPeerKeyFD(hasRootKey bool) int {
	return ExtraPeerSocketFD(hasRootKey) + 1
}

// Error is a typed launcher failure.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Code + ": " + e.Message
}

func fail(code, msg string) error { return &Error{Code: code, Message: msg} }

// ExecRequest starts an absolute engineering helper binary without IPC
// (crash stubs, probes). No shell; no PATH search.
type ExecRequest struct {
	Executable      string
	Args            []string
	Env             []string // additional env; ModeEngineering is always set
	Dir             string
	EngineeringMode bool
}

// Request describes one child start. Exactly one of EngineeringMode or
// ReleaseMode must be set (M2k). ReleaseMode is a fail-closed engineering
// preview of release-shaped launch — not an IC-1 production claim.
type Request struct {
	Executable      string
	Role            authority.ProcessRole
	Peer            authority.ProcessRole
	Nonce           [16]byte
	MACKey          []byte
	Socket          *os.File
	EngineeringMode bool
	// ReleaseMode selects INTEGRIS_LAUNCH_MODE=release with stricter child
	// confinement checks. Mutually exclusive with EngineeringMode.
	ReleaseMode bool
	// KeyViaExtraFiles selects the legacy ExtraFiles fd4 key path.
	// Default (false) confers the MAC key via SCM_RIGHTS after start
	// (ExtraFiles is socket-only); caller must SendFD Handle.KeyFD then Close it.
	KeyViaExtraFiles bool
	// Confer and SlotKinds are non-secret inventory labels for role-semantic probes.
	Confer    []authority.Capability
	SlotKinds []string
	// AllowRoots are absolute archive path allow-list entries. Start
	// EvalSymlinks them fail-closed before env/FD conferral (M5m); children
	// also normalize (M5l / stub).
	AllowRoots []string
	// StubMode selects role-stub IPC behavior (respond default, or initiate).
	StubMode    string
	WaitTimeout time.Duration
	WorkDir     string
	// RootKey is an optional sealed push PSK conferred to a child (typically
	// integrisd-auth) via ExtraFiles when KeyViaExtraFiles. Never in the environment.
	RootKey []byte
	// ExtraPeer / ExtraSocket / ExtraMACKey confer a second IPC endpoint
	// (M2c: net↔apply while primary peer is auth). With KeyViaExtraFiles=false
	// (M2l default for integrisd), sockets are ExtraFiles and MAC keys use SCM.
	ExtraPeer   authority.ProcessRole
	ExtraSocket *os.File
	ExtraMACKey []byte
	// ListenAddr / Once / ReadyPath are non-secret net-role listen controls.
	ListenAddr string
	Once       bool
	ReadyPath  string
}
