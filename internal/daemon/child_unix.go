//go:build unix

package daemon

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/launcher"
)

// ChildEnv is the conferred launch environment for a role worker.
type ChildEnv struct {
	Role       authority.ProcessRole
	Peer       authority.ProcessRole
	Nonce      [16]byte
	MACKey     []byte
	Socket     *os.File
	RootKey    []byte // auth (M2c) or legacy net (M2a)
	AllowRoots []string
	// Extra peer (M2c net↔apply while primary is auth).
	ExtraPeer   authority.ProcessRole
	ExtraSocket *os.File
	ExtraMACKey []byte
	// KeyChannel is the SCM key/control channel (M2l/M2n). Kept open for
	// survivor roles that accept peer-FD rebind (M2o–M3b net/parser/plan/index/audit/auth).
	KeyChannel *os.File
	// AllowRootFDs are FreeBSD conferred directory descriptors (M3c).
	AllowRootFDs []*os.File
	// ConferredRights is the LimitConferredFDs finding from ClaimChild (M3o).
	ConferredRights confine.Finding
}

// ClaimChild claims conferred IPC + keys. Confinement is applied separately so
// net can publish a ready address before Landlock/Seatbelt deny FS writes.
func ClaimChild() (ChildEnv, error) {
	var zero ChildEnv
	mode := os.Getenv(launcher.EnvMode)
	if mode != launcher.ModeEngineering && mode != launcher.ModeRelease {
		return zero, fmt.Errorf("refusing unknown launch mode %q", mode)
	}
	sock := os.NewFile(uintptr(launcher.IPCFileFD), "ipc")
	if sock == nil {
		return zero, fmt.Errorf("missing ipc fd")
	}
	kt := os.Getenv(launcher.EnvKeyTransport)
	scm := kt == string(launcher.KeyTransportSCMRights)

	role := authority.ProcessRole(os.Getenv(launcher.EnvRole))
	peer := authority.ProcessRole(os.Getenv(launcher.EnvPeer))
	if role == "" || peer == "" {
		_ = sock.Close()
		return zero, fmt.Errorf("missing role/peer")
	}
	hasRoot := os.Getenv(launcher.EnvHasRootKey) == "1"
	extraPeer := authority.ProcessRole(os.Getenv(launcher.EnvExtraPeer))

	var keyF, rootF, extraSock, extraKeyF, keyCh *os.File
	if scm {
		keyCh = os.NewFile(uintptr(launcher.KeyChannelFDSCM), "key-channel")
		if keyCh == nil {
			_ = sock.Close()
			return zero, fmt.Errorf("missing key channel fd")
		}
		f, err := ipc.RecvFDFile(keyCh)
		if err != nil {
			closeAll(sock, keyCh)
			return zero, fmt.Errorf("recv key fd: %w", err)
		}
		keyF = f
		if hasRoot {
			rf, err := ipc.RecvFDFile(keyCh)
			if err != nil {
				closeAll(sock, keyCh, keyF)
				return zero, fmt.Errorf("recv root key fd: %w", err)
			}
			rootF = rf
		}
		if extraPeer != "" {
			extraSock = os.NewFile(uintptr(launcher.ExtraPeerSocketFDSCM), "ipc-extra")
			if extraSock == nil {
				closeAll(sock, keyCh, keyF, rootF)
				return zero, fmt.Errorf("missing extra peer socket fd")
			}
			ek, err := ipc.RecvFDFile(keyCh)
			if err != nil {
				closeAll(sock, keyCh, keyF, rootF, extraSock)
				return zero, fmt.Errorf("recv extra key fd: %w", err)
			}
			extraKeyF = ek
		}
		// Keep key channel open for RestartOne survivors:
		// M2o–M2p/M2t–M2z net (primary+ExtraPeer demux); M2q parser; M2r plan;
		// M2s index; M3a audit ExtraPeer→auth; M3b auth ExtraPeer→audit.
		keepKeyCh := (role == authority.RoleNet &&
			(extraPeer == "" || extraPeer == authority.RoleApply || extraPeer == authority.RoleParser)) ||
			(role == authority.RoleParser && extraPeer == authority.RoleApply) ||
			(role == authority.RolePlan && extraPeer == authority.RoleApply) ||
			(role == authority.RoleIndex && extraPeer == authority.RoleApply) ||
			(role == authority.RoleAudit && extraPeer == authority.RoleAuth) ||
			(role == authority.RoleAuth && extraPeer == authority.RoleAudit)
		if !keepKeyCh {
			_ = keyCh.Close()
			keyCh = nil
		}
	} else {
		keyF = os.NewFile(uintptr(launcher.KeyFileFD), "key")
		if keyF == nil {
			_ = sock.Close()
			return zero, fmt.Errorf("missing key fd")
		}
		if hasRoot {
			rootF = os.NewFile(uintptr(launcher.RootKeyFileFD), "rootkey")
			if rootF == nil {
				closeAll(sock, keyF)
				return zero, fmt.Errorf("missing root key fd")
			}
		}
		if extraPeer != "" {
			extraSock = os.NewFile(uintptr(launcher.ExtraPeerSocketFD(hasRoot)), "ipc-extra")
			extraKeyF = os.NewFile(uintptr(launcher.ExtraPeerKeyFD(hasRoot)), "key-extra")
			if extraSock == nil || extraKeyF == nil {
				closeAll(sock, keyF, rootF, extraSock, extraKeyF)
				return zero, fmt.Errorf("missing extra peer fds")
			}
		}
	}

	limit := []*os.File{sock, keyF}
	if rootF != nil {
		limit = append(limit, rootF)
	}
	if extraSock != nil {
		limit = append(limit, extraSock, extraKeyF)
	}
	if keyCh != nil {
		limit = append(limit, keyCh)
	}
	conferredRights := confine.LimitConferredFDs(limit...)

	var allowRoots []string
	if raw := os.Getenv(launcher.EnvAllowRoots); raw != "" {
		allowRoots = splitAllowRoots(raw)
	}
	// M3c: adopt FreeBSD allow-root directory FDs before CapEnter (stub parity).
	allowRootFDs := launcher.ClaimAllowRootFDs(os.Getenv(launcher.EnvAllowRootFDs))

	nonceRaw, err := hex.DecodeString(os.Getenv(launcher.EnvNonce))
	if err != nil || len(nonceRaw) != 16 {
		launcher.CloseAllowRootFDs(allowRootFDs)
		closeAll(sock, keyF, rootF, extraSock, extraKeyF, keyCh)
		return zero, fmt.Errorf("bad nonce")
	}
	var nonce [16]byte
	copy(nonce[:], nonceRaw)

	macKey, err := io.ReadAll(io.LimitReader(keyF, 257))
	_ = keyF.Close()
	if err != nil || len(macKey) < 16 || len(macKey) > 256 {
		launcher.CloseAllowRootFDs(allowRootFDs)
		closeAll(sock, rootF, extraSock, extraKeyF, keyCh)
		return zero, fmt.Errorf("bad mac key")
	}

	env := ChildEnv{
		Role:            role,
		Peer:            peer,
		Nonce:           nonce,
		MACKey:          macKey,
		Socket:          sock,
		AllowRoots:      allowRoots,
		AllowRootFDs:    allowRootFDs,
		KeyChannel:      keyCh,
		ConferredRights: conferredRights,
	}
	if rootF != nil {
		root, err := io.ReadAll(io.LimitReader(rootF, 8<<10))
		_ = rootF.Close()
		if err != nil || (len(root) != 32 && len(root) < 8) {
			launcher.CloseAllowRootFDs(allowRootFDs)
			closeAll(sock, extraSock, extraKeyF, keyCh)
			return zero, fmt.Errorf("bad root key material")
		}
		env.RootKey = root
	}
	if extraPeer != "" {
		extraMAC, err := io.ReadAll(io.LimitReader(extraKeyF, 257))
		_ = extraKeyF.Close()
		if err != nil || len(extraMAC) < 16 {
			launcher.CloseAllowRootFDs(allowRootFDs)
			closeAll(sock, extraSock, keyCh)
			return zero, fmt.Errorf("bad extra mac key")
		}
		env.ExtraPeer = extraPeer
		env.ExtraSocket = extraSock
		env.ExtraMACKey = extraMAC
	}
	return env, nil
}

func closeAll(files ...*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}

// Confine applies OS confinement for this child. Engineering mode is
// best-effort; release mode (M2k) fails closed if APPLY-* is unavailable.
// On FreeBSD, limits conferred allow-root directory FDs before CapEnter (M3c);
// release mode also requires capability mode via cap_getmode (M3m),
// allow-root rights-limit success (M3n), conferred IPC/key rights-limit
// success from ClaimChild (M3o; Skipped on non-FreeBSD), ambient path
// open denial via NEG-FS-READ (M3q), and ambient AF_INET deny via
// NEG-ROLE-NET (M3s; FreeBSD jail ip4/ip6=disable before CapEnter).
func (e ChildEnv) Confine() error {
	r := confine.ApplyEngineeringOpts(e.Role, confine.ApplyOptions{
		AllowRoots:   e.AllowRoots,
		AllowRootFDs: e.AllowRootFDs,
	})
	allowRoots := confine.Finding{
		ID: "APPLY-CAP-ALLOW-ROOTS", Status: confine.StatusSkipped,
		Detail: "no allow-root limit finding",
	}
	for _, f := range r.Findings {
		if f.ID == "APPLY-CAP-ALLOW-ROOTS" {
			allowRoots = f
			break
		}
	}
	if os.Getenv(launcher.EnvMode) == launcher.ModeRelease {
		if err := confine.RequireConferredLimitFinding(e.ConferredRights); err != nil {
			return err
		}
		if err := confine.RequireAllowRootLimitFinding(allowRoots); err != nil {
			return err
		}
		if err := r.RequireApplyAvailable(); err != nil {
			return err
		}
		if err := confine.RequireCapModeAvailable(); err != nil {
			return err
		}
		if err := confine.RequireAmbientFSReadDenied(); err != nil {
			return err
		}
		if err := confine.RequireAmbientRoleNetDenied(e.Role); err != nil {
			return err
		}
	}
	return nil
}

// Channel builds an authenticated IPC channel for the primary peer.
func (e ChildEnv) Channel() (ipc.ChannelState, error) {
	return ipc.NewAuthenticatedChannel(e.Role, e.Peer, e.Nonce, e.MACKey)
}

// ExtraChannel builds an authenticated IPC channel for the extra peer.
func (e ChildEnv) ExtraChannel() (ipc.ChannelState, error) {
	if e.ExtraPeer == "" {
		return ipc.ChannelState{}, fmt.Errorf("no extra peer")
	}
	return ipc.NewAuthenticatedChannel(e.Role, e.ExtraPeer, e.Nonce, e.ExtraMACKey)
}

func splitAllowRoots(raw string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == ':' {
			if i > start {
				out = append(out, raw[start:i])
			}
			start = i + 1
		}
	}
	return out
}
