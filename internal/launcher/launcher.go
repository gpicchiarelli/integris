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
	EnvRole         = "INTEGRIS_ROLE"
	EnvPeer         = "INTEGRIS_PEER"
	EnvNonce        = "INTEGRIS_NONCE_HEX"
	EnvMode         = "INTEGRIS_LAUNCH_MODE"
	ModeEngineering = "engineering"
	// IPCFileFD is the child's inherited IPC socket (ExtraFiles[0] → fd 3).
	IPCFileFD = 3
	// KeyFileFD is the child's inherited MAC-key pipe (ExtraFiles[1] → fd 4).
	KeyFileFD = 4
)

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

// Request describes one child start. Destructive defaults: EngineeringMode must
// be explicit; release mode is refused by this IP revision.
type Request struct {
	Executable      string
	Role            authority.ProcessRole
	Peer            authority.ProcessRole
	Nonce           [16]byte
	MACKey          []byte
	Socket          *os.File
	EngineeringMode bool
	WaitTimeout     time.Duration
	WorkDir         string
}
