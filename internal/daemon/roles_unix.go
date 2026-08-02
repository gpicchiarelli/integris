//go:build unix

package daemon

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"github.com/gpicchiarelli/integris/internal/localsync"
	"github.com/gpicchiarelli/integris/internal/remotesync"
)

func onceMode() bool { return os.Getenv(launcher.EnvOnce) == "1" }

// RunRole dispatches a conferred child role worker.
func RunRole() error {
	env, err := ClaimChild()
	if err != nil {
		return err
	}
	defer env.Socket.Close()
	if env.ExtraSocket != nil {
		defer env.ExtraSocket.Close()
	}
	if env.KeyChannel != nil {
		defer env.KeyChannel.Close()
	}
	if len(env.AllowRootFDs) > 0 {
		defer launcher.CloseAllowRootFDs(env.AllowRootFDs)
	}
	switch env.Role {
	case authority.RoleNet:
		return runNet(env)
	case authority.RoleAuth:
		return runAuth(env)
	case authority.RoleParser:
		return runParser(env)
	case authority.RolePlan:
		return runPlan(env)
	case authority.RoleIndex:
		return runIndex(env)
	case authority.RoleApply:
		return runApply(env)
	case authority.RoleJournal:
		return runJournal(env)
	case authority.RoleAudit:
		return runAudit(env)
	default:
		return fmt.Errorf("unsupported role %s", env.Role)
	}
}

func runNet(env ChildEnv) error {
	addr := os.Getenv(launcher.EnvListenAddr)
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	once := onceMode()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	if ready := os.Getenv(launcher.EnvReadyPath); ready != "" {
		tmp := ready + ".tmp"
		// Ready path is conferred by the supervisor (absolute temp path), not caller input.
		if err := os.WriteFile(tmp, []byte(ln.Addr().String()+"\n"), 0o600); err != nil { // #nosec G703 -- supervisor EnvReadyPath
			return err
		}
		if err := os.Rename(tmp, ready); err != nil { // #nosec G703 -- supervisor EnvReadyPath
			return err
		}
	}
	if err := env.Confine(); err != nil {
		return err
	}

	primaryCh, err := env.Channel()
	if err != nil {
		return err
	}

	// Modes:
	// M2d: peer=auth, extra=parser
	// M2c: peer=auth, extra=apply
	// M2a: peer=apply, no extra
	useAuth := env.Peer == authority.RoleAuth
	useParser := useAuth && env.ExtraPeer == authority.RoleParser
	useApplyExtra := useAuth && env.ExtraPeer == authority.RoleApply

	var authSlot ipcPeerSlot
	var dataSlot ipcPeerSlot
	if useAuth {
		if len(env.RootKey) != 0 {
			return fmt.Errorf("net must not hold push root key when auth is enabled")
		}
		if env.ExtraPeer == "" {
			return fmt.Errorf("net with auth requires extra peer (parser or apply)")
		}
		extraCh, err := env.ExtraChannel()
		if err != nil {
			return err
		}
		authSlot.sock = env.Socket
		authSlot.ch = &primaryCh
		dataSlot.sock = env.ExtraSocket
		dataSlot.ch = &extraCh
		// M2p/M2t/M2u/M2v ExtraPeer + M2w primary(auth) demux on one KeyChannel.
		if (useApplyExtra || useParser) && env.KeyChannel != nil {
			go rebindNetDualLoop(env, &authSlot, &dataSlot)
		}
	} else {
		dataSlot.sock = env.Socket
		dataSlot.ch = &primaryCh
		if len(env.RootKey) != remotesync.RootKeySize {
			return fmt.Errorf("net role missing push root key")
		}
		// M2o: accept peer-FD rebind on the key channel while listen survives.
		if env.KeyChannel != nil {
			go rebindPeerLoop(env, &dataSlot)
		}
	}

	for {
		if once {
			_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(60 * time.Second))
		} else {
			_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
		}
		conn, err := ln.Accept()
		if err != nil {
			if !once {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
			}
			return err
		}
		dataSock, dataCh := dataSlot.snapshot()
		var sessErr error
		if useAuth {
			authSock, authCh := authSlot.snapshot()
			sess, err := remotesync.AcceptHandshakeViaAuthIPC(conn, authSock, authCh)
			if err != nil {
				_ = conn.Close()
				sessErr = err
			} else if useParser {
				sessErr = remotesync.HandleActiveConnViaParserIPC(sess, dataSock, dataCh)
			} else {
				sessErr = remotesync.HandleActiveConnViaApplyIPC(sess, dataSock, dataCh)
			}
		} else {
			sessErr = remotesync.HandleConnViaApplyIPC(conn, env.RootKey, dataSock, dataCh)
			_ = conn.Close()
		}
		if once {
			return sessErr
		}
		if sessErr != nil && remotesync.IsKind(sessErr, remotesync.KindTransport) {
			return sessErr
		}
	}
}

// ipcPeerSlot holds a mutable peer IPC end for RestartOne rebind.
// ch is a pointer so sequence numbers persist across connections.
type ipcPeerSlot struct {
	mu   sync.Mutex
	sock *os.File
	ch   *ipc.ChannelState
}

func (s *ipcPeerSlot) snapshot() (*os.File, *ipc.ChannelState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sock, s.ch
}

func (s *ipcPeerSlot) install(newSock *os.File, ch *ipc.ChannelState) {
	s.mu.Lock()
	old := s.sock
	s.sock = newSock
	s.ch = ch
	s.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}

func rebindPeerLoop(env ChildEnv, slot *ipcPeerSlot) {
	// Rebound edge is ExtraPeer (M2p) when set, else primary peer (M2o).
	peer := env.Peer
	mac := env.MACKey
	if env.ExtraPeer != "" {
		peer = env.ExtraPeer
		mac = env.ExtraMACKey
	}
	for {
		newSock, err := ipc.RecvPeerFDFile(env.KeyChannel)
		if err != nil {
			return
		}
		ch, err := ipc.NewAuthenticatedChannel(env.Role, peer, env.Nonce, mac)
		if err != nil {
			_ = newSock.Close()
			return
		}
		slot.install(newSock, &ch)
	}
}

// rebindNetDualLoop demuxes ExtraPeer (PeerFDMagic) vs primary auth
// (PrimaryPeerFDMagic) on net's KeyChannel (M2w).
func rebindNetDualLoop(env ChildEnv, authSlot, dataSlot *ipcPeerSlot) {
	for {
		newSock, kind, err := ipc.RecvRebindFDFile(env.KeyChannel)
		if err != nil {
			return
		}
		var peer authority.ProcessRole
		var mac []byte
		var slot *ipcPeerSlot
		switch kind {
		case ipc.RebindPrimary:
			peer = env.Peer
			mac = env.MACKey
			slot = authSlot
		case ipc.RebindExtra:
			peer = env.ExtraPeer
			mac = env.ExtraMACKey
			slot = dataSlot
		default:
			_ = newSock.Close()
			return
		}
		ch, err := ipc.NewAuthenticatedChannel(env.Role, peer, env.Nonce, mac)
		if err != nil {
			_ = newSock.Close()
			return
		}
		slot.install(newSock, &ch)
	}
}

func runAuth(env ChildEnv) error {
	if len(env.RootKey) == 0 {
		return fmt.Errorf("auth role missing push root key material")
	}
	if _, _, err := remotesync.DecodeRootMaterial(env.RootKey); err != nil {
		return fmt.Errorf("auth root material: %w", err)
	}
	if err := env.Confine(); err != nil {
		return err
	}
	ch, err := env.Channel()
	if err != nil {
		return err
	}
	var audit remotesync.AuthAuditPeer
	if env.ExtraPeer == authority.RoleAudit {
		if env.ExtraSocket == nil {
			return fmt.Errorf("auth audit extra peer missing socket")
		}
		ach, err := env.ExtraChannel()
		if err != nil {
			return err
		}
		// M3b: ExtraPeer→audit can be rebound while auth+net survive.
		if env.KeyChannel != nil {
			var extraSlot ipcPeerSlot
			extraSlot.sock = env.ExtraSocket
			extraSlot.ch = &ach
			go rebindPeerLoop(env, &extraSlot)
			audit = remotesync.AuthAuditPeer{Side: func() (io.ReadWriter, *ipc.ChannelState) {
				sock, c := extraSlot.snapshot()
				return sock, c
			}}
		} else {
			audit = remotesync.AuthAuditPeer{RW: env.ExtraSocket, Ch: &ach}
		}
	}
	return remotesync.ServeAuthHandshakeIPC(env.RootKey, env.Socket, &ch, onceMode(), audit)
}

func runParser(env ChildEnv) error {
	if env.ExtraPeer != authority.RoleApply && env.ExtraPeer != authority.RolePlan {
		return fmt.Errorf("parser requires extra peer apply or plan")
	}
	if env.ExtraSocket == nil {
		return fmt.Errorf("parser missing extra peer socket")
	}
	if env.Peer != authority.RoleNet {
		return fmt.Errorf("parser primary peer must be net")
	}
	if err := env.Confine(); err != nil {
		return err
	}
	netCh, err := env.Channel()
	if err != nil {
		return err
	}
	downCh, err := env.ExtraChannel()
	if err != nil {
		return err
	}
	// M2q: ExtraPeer=apply can be rebound while parser+net survive.
	if env.ExtraPeer == authority.RoleApply && env.KeyChannel != nil {
		var downSlot ipcPeerSlot
		downSlot.sock = env.ExtraSocket
		downSlot.ch = &downCh
		go rebindPeerLoop(env, &downSlot)
		return remotesync.ServeParserBridgeDyn(env.Socket, &netCh, func() (io.ReadWriter, *ipc.ChannelState) {
			sock, ch := downSlot.snapshot()
			return sock, ch
		}, onceMode())
	}
	return remotesync.ServeParserBridge(env.Socket, env.ExtraSocket, &netCh, &downCh, onceMode())
}

func runPlan(env ChildEnv) error {
	if env.Peer != authority.RoleParser {
		return fmt.Errorf("plan primary peer must be parser")
	}
	if env.ExtraPeer != authority.RoleApply && env.ExtraPeer != authority.RoleIndex {
		return fmt.Errorf("plan requires extra peer apply or index")
	}
	if env.ExtraSocket == nil {
		return fmt.Errorf("plan missing extra peer socket")
	}
	if err := env.Confine(); err != nil {
		return err
	}
	parserCh, err := env.Channel()
	if err != nil {
		return err
	}
	downCh, err := env.ExtraChannel()
	if err != nil {
		return err
	}
	// M2r: ExtraPeer=apply can be rebound while plan (+ upstream) survive.
	if env.ExtraPeer == authority.RoleApply && env.KeyChannel != nil {
		var downSlot ipcPeerSlot
		downSlot.sock = env.ExtraSocket
		downSlot.ch = &downCh
		go rebindPeerLoop(env, &downSlot)
		return remotesync.ServePlanBridgeDyn(env.Socket, &parserCh, func() (io.ReadWriter, *ipc.ChannelState) {
			sock, ch := downSlot.snapshot()
			return sock, ch
		}, onceMode())
	}
	return remotesync.ServePlanBridge(env.Socket, env.ExtraSocket, &parserCh, &downCh, onceMode())
}

func runIndex(env ChildEnv) error {
	if env.Peer != authority.RolePlan {
		return fmt.Errorf("index primary peer must be plan")
	}
	if env.ExtraPeer != authority.RoleApply || env.ExtraSocket == nil {
		return fmt.Errorf("index requires extra peer apply")
	}
	if len(env.AllowRoots) == 0 {
		return fmt.Errorf("index role missing allow root")
	}
	if err := env.Confine(); err != nil {
		return err
	}
	planCh, err := env.Channel()
	if err != nil {
		return err
	}
	applyCh, err := env.ExtraChannel()
	if err != nil {
		return err
	}
	// M3d: prefer conferred allow-root directory FD for openat destination scan.
	var destDir *os.File
	if len(env.AllowRootFDs) > 0 {
		destDir = env.AllowRootFDs[0]
	}
	// M2s: ExtraPeer=apply can be rebound while index (+ upstream) survive.
	if env.KeyChannel != nil {
		var downSlot ipcPeerSlot
		downSlot.sock = env.ExtraSocket
		downSlot.ch = &applyCh
		go rebindPeerLoop(env, &downSlot)
		return remotesync.ServeIndexBridgeDyn(env.AllowRoots[0], destDir, env.Socket, &planCh, func() (io.ReadWriter, *ipc.ChannelState) {
			sock, ch := downSlot.snapshot()
			return sock, ch
		}, onceMode())
	}
	return remotesync.ServeIndexBridge(env.AllowRoots[0], destDir, env.Socket, env.ExtraSocket, &planCh, &applyCh, onceMode())
}

func runApply(env ChildEnv) error {
	if err := env.Confine(); err != nil {
		return err
	}
	ch, err := env.Channel()
	if err != nil {
		return err
	}
	if len(env.AllowRoots) == 0 {
		return fmt.Errorf("apply role missing allow root")
	}
	once := onceMode()
	var extras remotesync.ApplyIPCExtras
	switch env.ExtraPeer {
	case authority.RoleJournal:
		if env.ExtraSocket == nil {
			return fmt.Errorf("apply journal extra peer missing socket")
		}
		jch, err := env.ExtraChannel()
		if err != nil {
			return err
		}
		// Journal owns durable appends; same socket relays audit (or acks Done).
		extras.Journal = &remotesync.IPCJournalSession{RW: env.ExtraSocket, Ch: &jch}
		extras.Audit = remotesync.AuditPeer{RW: env.ExtraSocket, Ch: &jch, Done: once}
	case authority.RoleAudit:
		if env.ExtraSocket == nil {
			return fmt.Errorf("apply audit extra peer missing socket")
		}
		ach, err := env.ExtraChannel()
		if err != nil {
			return err
		}
		extras.Audit = remotesync.AuditPeer{RW: env.ExtraSocket, Ch: &ach, Done: once}
	}
	// M3e: prefer conferred allow-root directory FD for openat staging.
	var destDir *os.File
	if len(env.AllowRootFDs) > 0 {
		destDir = env.AllowRootFDs[0]
	}
	for {
		var err error
		if extras.Journal != nil || extras.Audit.RW != nil {
			err = remotesync.ServeApplyIPCExtras(env.AllowRoots[0], destDir, env.Socket, &ch, extras)
		} else {
			err = remotesync.ServeApplyIPC(env.AllowRoots[0], destDir, env.Socket, &ch)
		}
		if once {
			return err
		}
		if err != nil {
			return err
		}
	}
}

func runJournal(env ChildEnv) error {
	if env.Peer != authority.RoleApply {
		return fmt.Errorf("journal primary peer must be apply")
	}
	if len(env.AllowRoots) == 0 {
		return fmt.Errorf("journal role missing allow root")
	}
	jpath := filepath.Join(env.AllowRoots[0], localsync.MetaDirName, localsync.JournalFileName)
	// Ensure journal file exists before confinement (CapJournalDescriptor is RW).
	// M3l: prefer openat bootstrap on conferred dest FD (M3h audit parity).
	var destDir *os.File
	if len(env.AllowRootFDs) > 0 && env.AllowRootFDs[0] != nil {
		destDir = env.AllowRootFDs[0]
		if err := remotesync.BootstrapJournalAt(destDir); err != nil {
			return err
		}
	} else {
		integrisDir := filepath.Join(env.AllowRoots[0], localsync.MetaDirName)
		if err := os.MkdirAll(integrisDir, 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(jpath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		_ = f.Close()
	}
	if err := env.Confine(); err != nil {
		return err
	}
	ch, err := env.Channel()
	if err != nil {
		return err
	}
	var audit remotesync.JournalAuditRelay
	if env.ExtraPeer == authority.RoleAudit {
		if env.ExtraSocket == nil {
			return fmt.Errorf("journal audit extra peer missing socket")
		}
		ach, err := env.ExtraChannel()
		if err != nil {
			return err
		}
		audit = remotesync.JournalAuditRelay{RW: env.ExtraSocket, Ch: &ach}
	}
	return remotesync.ServeJournalIPC(jpath, destDir, env.Socket, &ch, audit, onceMode())
}

func runAudit(env ChildEnv) error {
	if env.Peer != authority.RoleApply && env.Peer != authority.RoleJournal {
		return fmt.Errorf("audit primary peer must be apply or journal")
	}
	if len(env.AllowRoots) == 0 {
		return fmt.Errorf("audit role missing allow root")
	}
	// Open sink before confinement (Audit allow-root stays readonly; sink FD
	// is held across CapEnter). Prefer openat on conferred dest FD (M3h).
	var f *os.File
	var err error
	if len(env.AllowRootFDs) > 0 && env.AllowRootFDs[0] != nil {
		f, err = remotesync.OpenAuditSinkAt(env.AllowRootFDs[0])
	} else {
		integrisDir := filepath.Join(env.AllowRoots[0], ".integris")
		if err := os.MkdirAll(integrisDir, 0o700); err != nil {
			return err
		}
		sinkPath := filepath.Join(integrisDir, remotesync.AuditSinkFileName)
		f, err = os.OpenFile(sinkPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if err := env.Confine(); err != nil {
		return err
	}
	ch, err := env.Channel()
	if err != nil {
		return err
	}
	if env.ExtraPeer == authority.RoleAuth {
		if env.ExtraSocket == nil {
			return fmt.Errorf("audit auth extra peer missing socket")
		}
		ach, err := env.ExtraChannel()
		if err != nil {
			return err
		}
		// M3a: ExtraPeer→auth can be rebound while audit+journal survive.
		if env.KeyChannel != nil {
			var extraSlot ipcPeerSlot
			extraSlot.sock = env.ExtraSocket
			extraSlot.ch = &ach
			go rebindPeerLoop(env, &extraSlot)
			return remotesync.ServeAuditSinkExtraDyn(f, env.Socket, &ch, func() (io.ReadWriter, *ipc.ChannelState) {
				sock, c := extraSlot.snapshot()
				return sock, c
			}, onceMode())
		}
		return remotesync.ServeAuditSinkExtra(f, env.Socket, &ch, env.ExtraSocket, &ach, onceMode())
	}
	return remotesync.ServeAuditSink(f, env.Socket, &ch, onceMode())
}
