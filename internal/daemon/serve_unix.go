//go:build unix

package daemon

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"github.com/gpicchiarelli/integris/internal/remotesync"
	"github.com/gpicchiarelli/integris/internal/supervisor"
)

// ServeOptions configures the M2a–M3q engineering supervisor.
type ServeOptions struct {
	Addr        string
	Destination string
	RootKey     []byte
	Once        bool
	// MaxRestarts budgets full-role restart after unexpected child exit.
	// Ignored when Once is true. Negative selects default 3; zero disables restarts.
	MaxRestarts int
	// Executable is the absolute path of this binary (role re-exec).
	Executable string
	// Ready receives the listen address after each successful bind (including restarts).
	Ready chan<- string
	// DisableAuth uses M2a net↔apply only (PSK in net).
	DisableAuth bool
	// DisableParser uses M2c net↔apply data plane (requires auth).
	DisableParser bool
	// DisableAudit omits integrisd-audit (requires auth+parser when audit on).
	DisableAudit bool
	// DisableJournal omits integrisd-journal; apply writes local.jrn itself (M2e/M2d).
	DisableJournal bool
	// DisablePlan omits integrisd-plan (M2f and earlier).
	DisablePlan bool
	// DisableIndex omits integrisd-index (M2g). Default is M2h: plan↔index↔apply
	// with journal+audit. Engineering M2h requires plan+journal+audit.
	DisableIndex bool
	// Peers is an optional per-peer PSK keyring (M2i). When set, RootKey must be
	// empty; auth admits only listed peer IDs. When empty, RootKey is the shared PSK.
	Peers remotesync.PeerKeyring
	// StrictLaunch enables M2k release-shaped launch: full role chain required,
	// children use INTEGRIS_LAUNCH_MODE=release with fail-closed confinement
	// (APPLY-*, CapMode M3m, Capsicum rights M3n/M3o, ambient FS-read M3q).
	// Not an IC-1 production claim.
	StrictLaunch bool
}

// Status is a snapshot of supervisor health.
type Status struct {
	ListenAddr  string
	Restarts    int
	Once        bool
	WithAuth    bool
	WithParser  bool
	WithAudit   bool
	WithJournal bool
	WithPlan    bool
	WithIndex   bool
}

// Server is a running M2b supervisor session.
type Server struct {
	mu          sync.Mutex
	rt          *supervisor.Runtime
	opts        ServeOptions
	exe         string
	readyPath   string
	listenAddr  string
	restarts    int
	maxRestarts int
	runCancel   context.CancelFunc
	done        chan struct{}
	err         error
}

// Serve starts apply+net and blocks until they exit (Once) or ctx is cancelled.
func Serve(ctx context.Context, opts ServeOptions) error {
	srv, err := Start(ctx, opts)
	if err != nil {
		return err
	}
	return srv.Wait()
}

// Start launches the net/apply pair and returns once the listener is ready.
func Start(ctx context.Context, opts ServeOptions) (*Server, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Destination == "" {
		return nil, fmt.Errorf("destination required")
	}
	if opts.StrictLaunch {
		if opts.DisableAuth || opts.DisableParser || opts.DisableAudit ||
			opts.DisableJournal || opts.DisablePlan || opts.DisableIndex {
			return nil, fmt.Errorf("strict launch requires full eight-role receive chain")
		}
	}
	var rootMaterial []byte
	switch {
	case len(opts.Peers) > 0:
		if len(opts.RootKey) != 0 {
			return nil, fmt.Errorf("use Peers or RootKey, not both")
		}
		enc, err := remotesync.EncodeKeyring(opts.Peers)
		if err != nil {
			return nil, err
		}
		rootMaterial = enc
	case len(opts.RootKey) == remotesync.RootKeySize:
		rootMaterial = append([]byte{}, opts.RootKey...)
	default:
		return nil, fmt.Errorf("root key must be %d bytes (or provide Peers keyring)", remotesync.RootKeySize)
	}
	exe := opts.Executable
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			return nil, err
		}
		exe, err = filepath.Abs(exe)
		if err != nil {
			return nil, err
		}
	}
	dest, err := filepath.Abs(opts.Destination)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, err
	}
	addr := opts.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}

	if opts.DisableAuth && len(opts.Peers) > 0 {
		return nil, fmt.Errorf("peer keyring requires auth role")
	}
	if opts.DisableAuth && !opts.DisableParser {
		return nil, fmt.Errorf("parser requires auth (disable both or neither)")
	}
	if opts.DisableAuth && !opts.DisableAudit {
		return nil, fmt.Errorf("audit requires auth (disable both or neither)")
	}
	if opts.DisableParser && !opts.DisableAudit {
		return nil, fmt.Errorf("audit requires parser (disable both or neither)")
	}
	if opts.DisableAuth && !opts.DisableJournal {
		return nil, fmt.Errorf("journal requires auth (disable both or neither)")
	}
	if opts.DisableParser && !opts.DisableJournal {
		return nil, fmt.Errorf("journal requires parser (disable both or neither)")
	}
	if opts.DisableAuth && !opts.DisablePlan {
		return nil, fmt.Errorf("plan requires auth (disable both or neither)")
	}
	if opts.DisableParser && !opts.DisablePlan {
		return nil, fmt.Errorf("plan requires parser (disable both or neither)")
	}
	if !opts.DisablePlan && (opts.DisableJournal || opts.DisableAudit) {
		return nil, fmt.Errorf("plan role requires journal and audit in this engineering slice")
	}
	if opts.DisablePlan {
		opts.DisableIndex = true // index requires plan
	}
	if !opts.DisableIndex && opts.DisablePlan {
		return nil, fmt.Errorf("index requires plan (disable both or neither)")
	}
	if !opts.DisableIndex && (opts.DisableJournal || opts.DisableAudit) {
		return nil, fmt.Errorf("index role requires journal and audit in this engineering slice")
	}
	var plan supervisor.Plan
	switch {
	case opts.DisableAuth:
		plan, err = NetApplyPlan()
	case opts.DisableParser:
		plan, err = AuthNetApplyPlan()
	case !opts.DisableIndex:
		if len(opts.Peers) > 0 && !opts.DisableAudit {
			plan, err = AuthParserNetPlanIndexApplyJournalAuditPeerPlan()
		} else {
			plan, err = AuthParserNetPlanIndexApplyJournalAuditPlan()
		}
	case !opts.DisablePlan:
		plan, err = AuthParserNetPlanApplyJournalAuditPlan()
	case opts.DisableJournal && opts.DisableAudit:
		plan, err = AuthParserNetApplyPlan()
	case opts.DisableJournal:
		plan, err = AuthParserNetApplyAuditPlan()
	case opts.DisableAudit:
		plan, err = AuthParserNetApplyJournalPlan()
	default:
		plan, err = AuthParserNetApplyJournalAuditPlan()
	}
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	fabricKey := opts.RootKey
	if len(fabricKey) != remotesync.RootKeySize {
		fabricKey = make([]byte, remotesync.RootKeySize)
		if _, err := rand.Read(fabricKey); err != nil {
			return nil, err
		}
	}
	rt, err := supervisor.OpenRuntime(plan, fabricKey, nonce)
	if err != nil {
		return nil, err
	}

	var readyNonce [8]byte
	if _, err := rand.Read(readyNonce[:]); err != nil {
		_ = rt.Close()
		return nil, err
	}
	readyPath := filepath.Join(os.TempDir(), fmt.Sprintf("integrisd-ready-%d-%x", os.Getpid(), readyNonce))
	_ = os.Remove(readyPath)

	// M2l: default SCM_RIGHTS key conferral; sockets (incl. ExtraPeer) on ExtraFiles.
	rt.KeyViaExtraFiles = false
	rt.AllowRoots = map[authority.ProcessRole][]string{
		authority.RoleApply: {dest},
	}
	if !opts.DisableAuth && !opts.DisableParser && !opts.DisableJournal {
		rt.AllowRoots[authority.RoleJournal] = []string{dest}
	}
	if !opts.DisableAuth && !opts.DisableParser && !opts.DisableAudit {
		rt.AllowRoots[authority.RoleAudit] = []string{dest}
	}
	if !opts.DisableAuth && !opts.DisableParser && !opts.DisableIndex {
		rt.AllowRoots[authority.RoleIndex] = []string{dest}
	}
	rt.PushRootKey = rootMaterial
	rt.ListenAddr = addr
	rt.Once = opts.Once
	rt.ReadyPath = readyPath
	rt.ReleaseMode = opts.StrictLaunch
	if opts.DisableAuth {
		rt.PushRootRole = authority.RoleNet
	} else {
		rt.PushRootRole = authority.RoleAuth
		rt.ExtraPeerFor = map[authority.ProcessRole]authority.ProcessRole{}
		if opts.DisableParser {
			rt.ExtraPeerFor[authority.RoleNet] = authority.RoleApply
		} else if !opts.DisableIndex {
			rt.ExtraPeerFor[authority.RoleNet] = authority.RoleParser
			rt.ExtraPeerFor[authority.RoleParser] = authority.RolePlan
			rt.ExtraPeerFor[authority.RolePlan] = authority.RoleIndex
			rt.ExtraPeerFor[authority.RoleIndex] = authority.RoleApply
			rt.ExtraPeerFor[authority.RoleApply] = authority.RoleJournal
			rt.ExtraPeerFor[authority.RoleJournal] = authority.RoleAudit
		} else if !opts.DisablePlan {
			rt.ExtraPeerFor[authority.RoleNet] = authority.RoleParser
			rt.ExtraPeerFor[authority.RoleParser] = authority.RolePlan
			rt.ExtraPeerFor[authority.RolePlan] = authority.RoleApply
			rt.ExtraPeerFor[authority.RoleApply] = authority.RoleJournal
			rt.ExtraPeerFor[authority.RoleJournal] = authority.RoleAudit
		} else {
			rt.ExtraPeerFor[authority.RoleNet] = authority.RoleParser
			rt.ExtraPeerFor[authority.RoleParser] = authority.RoleApply
			switch {
			case !opts.DisableJournal:
				rt.ExtraPeerFor[authority.RoleApply] = authority.RoleJournal
				if !opts.DisableAudit {
					rt.ExtraPeerFor[authority.RoleJournal] = authority.RoleAudit
				}
			case !opts.DisableAudit:
				rt.ExtraPeerFor[authority.RoleApply] = authority.RoleAudit
			}
		}
		// M2j: peer keyring admit/deny → audit (auth ExtraPeer; M2h plan only).
		if len(opts.Peers) > 0 && !opts.DisableAudit && !opts.DisableIndex {
			rt.ExtraPeerFor[authority.RoleAuth] = authority.RoleAudit
			rt.ExtraPeerFor[authority.RoleAudit] = authority.RoleAuth
		}
	}

	maxRestarts := opts.MaxRestarts
	if opts.Once {
		maxRestarts = 0
	} else if maxRestarts < 0 {
		maxRestarts = 3
	}

	// Long deadline satisfies launcher; cancelled when parent ctx ends or Close.
	runCtx, runCancel := context.WithTimeout(context.Background(), 24*time.Hour)
	go func() {
		<-ctx.Done()
		runCancel()
	}()

	if err := startRoleChildren(rt, runCtx, exe, opts); err != nil {
		runCancel()
		_ = rt.Close()
		return nil, err
	}

	listenAddr, err := waitReadyFile(readyPath, 30*time.Second)
	if err != nil {
		runCancel()
		_ = rt.Close()
		return nil, err
	}
	if opts.Ready != nil {
		opts.Ready <- listenAddr
	}

	srv := &Server{
		rt:          rt,
		opts:        opts,
		exe:         exe,
		readyPath:   readyPath,
		listenAddr:  listenAddr,
		maxRestarts: maxRestarts,
		runCancel:   runCancel,
		done:        make(chan struct{}),
	}
	go srv.supervise(ctx, runCtx)
	return srv, nil
}

// Status returns a health snapshot.
func (s *Server) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{
		ListenAddr:  s.listenAddr,
		Restarts:    s.restarts,
		Once:        s.opts.Once,
		WithAuth:    !s.opts.DisableAuth,
		WithParser:  !s.opts.DisableAuth && !s.opts.DisableParser,
		WithAudit:   !s.opts.DisableAuth && !s.opts.DisableParser && !s.opts.DisableAudit,
		WithJournal: !s.opts.DisableAuth && !s.opts.DisableParser && !s.opts.DisableJournal,
		WithPlan:    !s.opts.DisableAuth && !s.opts.DisableParser && !s.opts.DisablePlan,
		WithIndex:   !s.opts.DisableAuth && !s.opts.DisableParser && !s.opts.DisableIndex,
	}
}

// Wait blocks until the supervisor finishes.
func (s *Server) Wait() error {
	if s == nil {
		return fmt.Errorf("nil server")
	}
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Close stops children and waits for the supervise loop to finish.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	if s.runCancel != nil {
		s.runCancel()
	}
	s.killTracked()
	return s.Wait()
}

// KillRole SIGKILLs a tracked child (engineering/test fault injection).
func (s *Server) KillRole(role authority.ProcessRole) error {
	if s == nil {
		return fmt.Errorf("nil server")
	}
	s.mu.Lock()
	rt := s.rt
	s.mu.Unlock()
	if rt == nil {
		return fmt.Errorf("runtime closed")
	}
	h, ok := rt.Children[role]
	if !ok || h == nil || h.Cmd == nil || h.Cmd.Process == nil {
		return fmt.Errorf("role %s not running", role)
	}
	return h.Cmd.Process.Kill()
}

// ChildPID returns the OS PID of a tracked role child (engineering/tests).
func (s *Server) ChildPID(role authority.ProcessRole) (int, bool) {
	if s == nil {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rt == nil {
		return 0, false
	}
	h, ok := s.rt.Children[role]
	if !ok || h == nil || h.Cmd == nil || h.Cmd.Process == nil {
		return 0, false
	}
	return h.Cmd.Process.Pid, true
}

func (s *Server) supervise(parent, runCtx context.Context) {
	defer close(s.done)
	defer func() {
		_ = os.Remove(s.readyPath)
		if s.runCancel != nil {
			s.runCancel()
		}
		s.killTracked()
		// Allow watchers to finish Wait before dropping the runtime.
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			s.mu.Lock()
			n := 0
			if s.rt != nil {
				n = len(s.rt.Children)
			}
			s.mu.Unlock()
			if n == 0 {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		s.mu.Lock()
		if s.rt != nil {
			if s.rt.Fabric != nil {
				_ = s.rt.Fabric.Close()
				s.rt.Fabric = nil
			}
			s.rt = nil
		}
		s.mu.Unlock()
	}()

	if s.opts.Once {
		var first error
		for _, role := range s.roleList() {
			if err := s.rt.WaitChild(role); err != nil && first == nil {
				first = err
			}
		}
		s.mu.Lock()
		s.err = first
		s.mu.Unlock()
		return
	}

	exitCh := make(chan authority.ProcessRole, 8)
	s.armWatchers(exitCh)

	for {
		select {
		case <-parent.Done():
			s.killTracked()
			s.mu.Lock()
			s.err = parent.Err()
			s.mu.Unlock()
			return
		case role := <-exitCh:
			if parent.Err() != nil || runCtx.Err() != nil {
				s.killTracked()
				s.mu.Lock()
				s.err = parent.Err()
				if s.err == nil {
					s.err = runCtx.Err()
				}
				s.mu.Unlock()
				return
			}
			s.mu.Lock()
			if s.restarts >= s.maxRestarts {
				s.err = fmt.Errorf("child %s exited; restart budget exhausted (%d)", role, s.maxRestarts)
				s.mu.Unlock()
				s.killTracked()
				return
			}
			s.restarts++
			restarts := s.restarts
			s.mu.Unlock()

			// M2o–M2r: selective RestartOne / apply-subtree restart.
			if armed, ok := s.tryRestartOne(runCtx, role, exitCh); ok {
				// M3j: drop cascade exits buffered while waiting for killed
				// siblings so they do not burn the restart budget as "new" deaths.
				flushExitPending(exitCh)
				for _, r := range armed {
					s.armWatcher(r, exitCh)
				}
				s.mu.Lock()
				addr := s.listenAddr
				readyCh := s.opts.Ready
				s.mu.Unlock()
				if readyCh != nil && addr != "" {
					readyCh <- addr
				}
				continue
			}

			// Full fleet restart; each Handle is Wait'd once by its watcher.
			s.killTracked()
			if err := s.drainExits(exitCh, 15*time.Second); err != nil {
				s.mu.Lock()
				s.err = fmt.Errorf("restart #%d: %w", restarts, err)
				s.mu.Unlock()
				return
			}

			_ = os.Remove(s.readyPath)
			if err := s.respawnAll(runCtx); err != nil {
				s.mu.Lock()
				s.err = fmt.Errorf("restart #%d: %w", restarts, err)
				s.mu.Unlock()
				return
			}
			addr, err := waitReadyFile(s.readyPath, 30*time.Second)
			if err != nil {
				s.mu.Lock()
				s.err = fmt.Errorf("restart #%d ready: %w", restarts, err)
				s.mu.Unlock()
				return
			}
			s.mu.Lock()
			s.listenAddr = addr
			readyCh := s.opts.Ready
			s.mu.Unlock()
			if readyCh != nil {
				readyCh <- addr
			}
			// Fresh watchers for the respawned fleet.
			exitCh = make(chan authority.ProcessRole, 8)
			s.armWatchers(exitCh)
		}
	}
}

// tryRestartOne attempts selective recovery. Returns roles to armWatcher.
// M2o M2a / M2p M2c / M2q M2d: RestartOne apply→net|parser.
// M2w–M2z / M3a: auth death → respawn auth, rebind net primary→auth
// (M3a also rebinds audit ExtraPeer→auth when peer keyring is set).
// M3b: apply/journal/audit subtree (or M2v parser-down) with Peers also rebinds
// surviving auth ExtraPeer→audit.
// M2t M2d: parser death → respawn parser+apply, rebind net ExtraPeer→parser.
// M2u M2g: parser/plan death → respawn parser→plan→apply→journal→audit, rebind net.
// M2v M2h: parser/plan/index death → respawn parser→plan→index→apply→journal→audit, rebind net.
// M2r M2g / M2s M2h: apply/journal/audit subtree restart + plan|index ExtraPeer rebind
// (journal dies on apply EOF, so the whole apply→journal→audit fan must respawn).
func (s *Server) tryRestartOne(ctx context.Context, dead authority.ProcessRole, exitCh <-chan authority.ProcessRole) ([]authority.ProcessRole, bool) {
	m2a := s.opts.DisableAuth
	m2c := !s.opts.DisableAuth && s.opts.DisableParser
	m2d := !s.opts.DisableAuth && !s.opts.DisableParser &&
		s.opts.DisablePlan && s.opts.DisableJournal && s.opts.DisableAudit
	m2g := !s.opts.DisableAuth && !s.opts.DisableParser && !s.opts.DisablePlan &&
		s.opts.DisableIndex && !s.opts.DisableJournal && !s.opts.DisableAudit
	m2h := !s.opts.DisableAuth && !s.opts.DisableParser && !s.opts.DisablePlan &&
		!s.opts.DisableIndex && !s.opts.DisableJournal && !s.opts.DisableAudit

	// M2w–M2z / M3a: auth loss — rebind net primary (+ audit ExtraPeer when M2j).
	if dead == authority.RoleAuth && (m2c || m2d || m2g || m2h) {
		if len(s.opts.Peers) > 0 && !m2h {
			// Peer keyring ExtraPeer auth↔audit is M2h-only.
			return nil, false
		}
		if s.restartAuthPrimary(ctx, exitCh) {
			return []authority.ProcessRole{authority.RoleAuth}, true
		}
		return nil, false
	}

	// M2u: parser/plan loss on M2g — larger than apply-only subtree (M2r).
	if m2g && (dead == authority.RoleParser || dead == authority.RolePlan ||
		((dead == authority.RoleApply || dead == authority.RoleJournal || dead == authority.RoleAudit) &&
			!s.childAlive(authority.RoleParser))) {
		if s.restartParserDownM2g(ctx, exitCh) {
			return []authority.ProcessRole{
				authority.RoleAudit, authority.RoleJournal, authority.RoleApply,
				authority.RolePlan, authority.RoleParser,
			}, true
		}
		return nil, false
	}

	// M2v: parser/plan/index loss on M2h — larger than apply-only subtree (M2s).
	if m2h && (dead == authority.RoleParser || dead == authority.RolePlan || dead == authority.RoleIndex ||
		((dead == authority.RoleApply || dead == authority.RoleJournal || dead == authority.RoleAudit) &&
			!s.childAlive(authority.RoleParser))) {
		if s.restartParserDownM2h(ctx, exitCh) {
			return []authority.ProcessRole{
				authority.RoleAudit, authority.RoleJournal, authority.RoleApply,
				authority.RoleIndex, authority.RolePlan, authority.RoleParser,
			}, true
		}
		return nil, false
	}

	if (m2g || m2h) && (dead == authority.RoleApply || dead == authority.RoleJournal || dead == authority.RoleAudit) {
		bridge := authority.RolePlan
		if m2h {
			bridge = authority.RoleIndex
		}
		if s.restartApplySubtree(ctx, exitCh, bridge) {
			return []authority.ProcessRole{
				authority.RoleAudit, authority.RoleJournal, authority.RoleApply,
			}, true
		}
		return nil, false
	}

	if m2d && (dead == authority.RoleParser ||
		(dead == authority.RoleApply && !s.childAlive(authority.RoleParser))) {
		if s.restartParserDownM2d(ctx, exitCh) {
			return []authority.ProcessRole{authority.RoleApply, authority.RoleParser}, true
		}
		return nil, false
	}

	if dead != authority.RoleApply {
		return nil, false
	}
	if !m2a && !m2c && !m2d {
		return nil, false
	}
	s.mu.Lock()
	rt := s.rt
	exe := s.exe
	s.mu.Unlock()
	if rt == nil {
		return nil, false
	}
	live := authority.RoleNet
	initiator := authority.RoleNet
	if m2d {
		live = authority.RoleParser
		initiator = authority.RoleParser
	}
	if _, ok := rt.Children[live]; !ok {
		return nil, false
	}
	if err := rt.RestartOne(ctx, dead, live, initiator, exe); err != nil {
		return nil, false
	}
	return []authority.ProcessRole{dead}, true
}

func (s *Server) childAlive(role authority.ProcessRole) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rt == nil {
		return false
	}
	_, ok := s.rt.Children[role]
	return ok
}

// restartAuthPrimary respawns auth and rebinds net primary→auth while the
// listen socket and data-plane roles survive (M2w–M2z). With a peer keyring
// (M3a), also ReplacePair(auth,audit) and SendPeerFD into surviving audit.
func (s *Server) restartAuthPrimary(ctx context.Context, exitCh <-chan authority.ProcessRole) bool {
	s.mu.Lock()
	rt := s.rt
	exe := s.exe
	m2j := len(s.opts.Peers) > 0
	s.mu.Unlock()
	if rt == nil {
		return false
	}
	netH, ok := rt.Children[authority.RoleNet]
	if !ok || netH == nil || netH.KeyChannel == nil {
		return false
	}
	netPID := 0
	if netH.Cmd != nil && netH.Cmd.Process != nil {
		netPID = netH.Cmd.Process.Pid
	}
	var auditH *launcher.Handle
	auditPID := 0
	if m2j {
		auditH, ok = rt.Children[authority.RoleAudit]
		if !ok || auditH == nil || auditH.KeyChannel == nil {
			return false
		}
		if auditH.Cmd != nil && auditH.Cmd.Process != nil {
			auditPID = auditH.Cmd.Process.Pid
		}
	}

	s.killRole(authority.RoleAuth)
	deadline := time.Now().Add(15 * time.Second)
	for {
		s.mu.Lock()
		_, still := rt.Children[authority.RoleAuth]
		s.mu.Unlock()
		if !still {
			flushExitPending(exitCh)
			break
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			return false
		}
		select {
		case <-exitCh:
		case <-time.After(remain):
			return false
		}
	}

	if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleAuth, rt.RootKey); err != nil {
		return false
	}
	if m2j {
		if err := rt.Fabric.ReplacePair(authority.RoleAuth, authority.RoleAudit, rt.RootKey); err != nil {
			return false
		}
	}
	if err := rt.StartChild(ctx, authority.RoleAuth, authority.RoleNet, exe); err != nil {
		return false
	}

	ep, err := rt.Fabric.Endpoint(authority.RoleNet, authority.RoleAuth)
	if err != nil {
		return false
	}
	peerSock, err := ep.Conn.File()
	if err != nil {
		return false
	}
	_ = ep.Conn.Close()
	ep.Conn = nil
	if err := ipc.SendPrimaryPeerFDFile(netH.KeyChannel, peerSock); err != nil {
		_ = peerSock.Close()
		return false
	}
	_ = peerSock.Close()
	if netPID != 0 && netH.Cmd != nil && netH.Cmd.Process != nil &&
		netH.Cmd.Process.Pid != netPID {
		return false
	}

	if m2j {
		aep, err := rt.Fabric.Endpoint(authority.RoleAudit, authority.RoleAuth)
		if err != nil {
			return false
		}
		auditSock, err := aep.Conn.File()
		if err != nil {
			return false
		}
		_ = aep.Conn.Close()
		aep.Conn = nil
		if err := ipc.SendPeerFDFile(auditH.KeyChannel, auditSock); err != nil {
			_ = auditSock.Close()
			return false
		}
		_ = auditSock.Close()
		if auditPID != 0 && auditH.Cmd != nil && auditH.Cmd.Process != nil &&
			auditH.Cmd.Process.Pid != auditPID {
			return false
		}
	}
	return true
}

// restartParserDownM2d respawns parser+apply and rebinds net ExtraPeer→parser (M2t).
func (s *Server) restartParserDownM2d(ctx context.Context, exitCh <-chan authority.ProcessRole) bool {
	s.mu.Lock()
	rt := s.rt
	exe := s.exe
	s.mu.Unlock()
	if rt == nil {
		return false
	}
	netH, ok := rt.Children[authority.RoleNet]
	if !ok || netH == nil || netH.KeyChannel == nil {
		return false
	}
	netPID := 0
	if netH.Cmd != nil && netH.Cmd.Process != nil {
		netPID = netH.Cmd.Process.Pid
	}

	down := []authority.ProcessRole{authority.RoleParser, authority.RoleApply}
	for _, role := range down {
		s.killRole(role)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		s.mu.Lock()
		left := 0
		for _, role := range down {
			if _, ok := rt.Children[role]; ok {
				left++
			}
		}
		s.mu.Unlock()
		if left == 0 {
			flushExitPending(exitCh)
			break
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			return false
		}
		select {
		case <-exitCh:
		case <-time.After(remain):
			return false
		}
	}

	if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleParser, rt.RootKey); err != nil {
		return false
	}
	if err := rt.Fabric.ReplacePair(authority.RoleParser, authority.RoleApply, rt.RootKey); err != nil {
		return false
	}
	if err := rt.StartChild(ctx, authority.RoleApply, authority.RoleParser, exe); err != nil {
		return false
	}
	if err := rt.StartChild(ctx, authority.RoleParser, authority.RoleNet, exe); err != nil {
		return false
	}

	ep, err := rt.Fabric.Endpoint(authority.RoleNet, authority.RoleParser)
	if err != nil {
		return false
	}
	peerSock, err := ep.Conn.File()
	if err != nil {
		return false
	}
	_ = ep.Conn.Close()
	ep.Conn = nil
	if err := ipc.SendPeerFDFile(netH.KeyChannel, peerSock); err != nil {
		_ = peerSock.Close()
		return false
	}
	_ = peerSock.Close()
	if netPID != 0 && netH.Cmd != nil && netH.Cmd.Process != nil &&
		netH.Cmd.Process.Pid != netPID {
		return false
	}
	return true
}

// restartParserDownM2g respawns parser→plan→apply→journal→audit and rebinds
// net ExtraPeer→parser while auth+net survive (M2u).
func (s *Server) restartParserDownM2g(ctx context.Context, exitCh <-chan authority.ProcessRole) bool {
	s.mu.Lock()
	rt := s.rt
	exe := s.exe
	s.mu.Unlock()
	if rt == nil {
		return false
	}
	netH, ok := rt.Children[authority.RoleNet]
	if !ok || netH == nil || netH.KeyChannel == nil {
		return false
	}
	netPID := 0
	if netH.Cmd != nil && netH.Cmd.Process != nil {
		netPID = netH.Cmd.Process.Pid
	}

	down := []authority.ProcessRole{
		authority.RoleParser, authority.RolePlan, authority.RoleApply,
		authority.RoleJournal, authority.RoleAudit,
	}
	for _, role := range down {
		s.killRole(role)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		s.mu.Lock()
		left := 0
		for _, role := range down {
			if _, ok := rt.Children[role]; ok {
				left++
			}
		}
		s.mu.Unlock()
		if left == 0 {
			flushExitPending(exitCh)
			break
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			return false
		}
		select {
		case <-exitCh:
		case <-time.After(remain):
			return false
		}
	}

	if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleParser, rt.RootKey); err != nil {
		return false
	}
	if err := rt.Fabric.ReplacePair(authority.RoleParser, authority.RolePlan, rt.RootKey); err != nil {
		return false
	}
	if err := rt.Fabric.ReplacePair(authority.RolePlan, authority.RoleApply, rt.RootKey); err != nil {
		return false
	}
	if err := rt.Fabric.ReplacePair(authority.RoleApply, authority.RoleJournal, rt.RootKey); err != nil {
		return false
	}
	if err := rt.Fabric.ReplacePair(authority.RoleJournal, authority.RoleAudit, rt.RootKey); err != nil {
		return false
	}
	// Same bottom-up order as startRoleChildren for M2g (auth/net already live).
	if err := rt.StartChild(ctx, authority.RoleAudit, authority.RoleJournal, exe); err != nil {
		return false
	}
	if err := rt.StartChild(ctx, authority.RoleJournal, authority.RoleApply, exe); err != nil {
		return false
	}
	if err := rt.StartChild(ctx, authority.RoleApply, authority.RolePlan, exe); err != nil {
		return false
	}
	if err := rt.StartChild(ctx, authority.RolePlan, authority.RoleParser, exe); err != nil {
		return false
	}
	if err := rt.StartChild(ctx, authority.RoleParser, authority.RoleNet, exe); err != nil {
		return false
	}

	ep, err := rt.Fabric.Endpoint(authority.RoleNet, authority.RoleParser)
	if err != nil {
		return false
	}
	peerSock, err := ep.Conn.File()
	if err != nil {
		return false
	}
	_ = ep.Conn.Close()
	ep.Conn = nil
	if err := ipc.SendPeerFDFile(netH.KeyChannel, peerSock); err != nil {
		_ = peerSock.Close()
		return false
	}
	_ = peerSock.Close()
	if netPID != 0 && netH.Cmd != nil && netH.Cmd.Process != nil &&
		netH.Cmd.Process.Pid != netPID {
		return false
	}
	return true
}

// restartParserDownM2h respawns parser→plan→index→apply→journal→audit and
// rebinds net ExtraPeer→parser while auth+net survive (M2v).
func (s *Server) restartParserDownM2h(ctx context.Context, exitCh <-chan authority.ProcessRole) bool {
	s.mu.Lock()
	rt := s.rt
	exe := s.exe
	s.mu.Unlock()
	if rt == nil {
		return false
	}
	netH, ok := rt.Children[authority.RoleNet]
	if !ok || netH == nil || netH.KeyChannel == nil {
		return false
	}
	netPID := 0
	if netH.Cmd != nil && netH.Cmd.Process != nil {
		netPID = netH.Cmd.Process.Pid
	}

	down := []authority.ProcessRole{
		authority.RoleParser, authority.RolePlan, authority.RoleIndex,
		authority.RoleApply, authority.RoleJournal, authority.RoleAudit,
	}
	for _, role := range down {
		s.killRole(role)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		s.mu.Lock()
		left := 0
		for _, role := range down {
			if _, ok := rt.Children[role]; ok {
				left++
			}
		}
		s.mu.Unlock()
		if left == 0 {
			flushExitPending(exitCh)
			break
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			return false
		}
		select {
		case <-exitCh:
		case <-time.After(remain):
			return false
		}
	}

	if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleParser, rt.RootKey); err != nil {
		return false
	}
	if err := rt.Fabric.ReplacePair(authority.RoleParser, authority.RolePlan, rt.RootKey); err != nil {
		return false
	}
	if err := rt.Fabric.ReplacePair(authority.RolePlan, authority.RoleIndex, rt.RootKey); err != nil {
		return false
	}
	if err := rt.Fabric.ReplacePair(authority.RoleIndex, authority.RoleApply, rt.RootKey); err != nil {
		return false
	}
	if err := rt.Fabric.ReplacePair(authority.RoleApply, authority.RoleJournal, rt.RootKey); err != nil {
		return false
	}
	if err := rt.Fabric.ReplacePair(authority.RoleJournal, authority.RoleAudit, rt.RootKey); err != nil {
		return false
	}
	if !s.replaceAuthAuditPair(rt) {
		return false
	}
	// Same bottom-up order as startRoleChildren for M2h (auth/net already live).
	if err := rt.StartChild(ctx, authority.RoleAudit, authority.RoleJournal, exe); err != nil {
		return false
	}
	if !s.sendAuthAuditPeerFD(rt) {
		return false
	}
	if err := rt.StartChild(ctx, authority.RoleJournal, authority.RoleApply, exe); err != nil {
		return false
	}
	if err := rt.StartChild(ctx, authority.RoleApply, authority.RoleIndex, exe); err != nil {
		return false
	}
	if err := rt.StartChild(ctx, authority.RoleIndex, authority.RolePlan, exe); err != nil {
		return false
	}
	if err := rt.StartChild(ctx, authority.RolePlan, authority.RoleParser, exe); err != nil {
		return false
	}
	if err := rt.StartChild(ctx, authority.RoleParser, authority.RoleNet, exe); err != nil {
		return false
	}

	ep, err := rt.Fabric.Endpoint(authority.RoleNet, authority.RoleParser)
	if err != nil {
		return false
	}
	peerSock, err := ep.Conn.File()
	if err != nil {
		return false
	}
	_ = ep.Conn.Close()
	ep.Conn = nil
	if err := ipc.SendPeerFDFile(netH.KeyChannel, peerSock); err != nil {
		_ = peerSock.Close()
		return false
	}
	_ = peerSock.Close()
	if netPID != 0 && netH.Cmd != nil && netH.Cmd.Process != nil &&
		netH.Cmd.Process.Pid != netPID {
		return false
	}
	return true
}

// restartApplySubtree respawns apply+journal+audit and rebinds bridge→apply
// (M2r bridge=plan; M2s bridge=index). With peer keyring (M3b), also rebinds
// surviving auth ExtraPeer→audit.
func (s *Server) restartApplySubtree(ctx context.Context, exitCh <-chan authority.ProcessRole, bridge authority.ProcessRole) bool {
	s.mu.Lock()
	rt := s.rt
	exe := s.exe
	s.mu.Unlock()
	if rt == nil {
		return false
	}
	bridgeH, ok := rt.Children[bridge]
	if !ok || bridgeH == nil || bridgeH.KeyChannel == nil {
		return false
	}
	bridgePID := 0
	if bridgeH.Cmd != nil && bridgeH.Cmd.Process != nil {
		bridgePID = bridgeH.Cmd.Process.Pid
	}
	authPID := 0
	if len(s.opts.Peers) > 0 {
		if authH, ok := rt.Children[authority.RoleAuth]; ok && authH != nil &&
			authH.Cmd != nil && authH.Cmd.Process != nil {
			authPID = authH.Cmd.Process.Pid
		}
	}

	subtree := []authority.ProcessRole{
		authority.RoleApply, authority.RoleJournal, authority.RoleAudit,
	}
	for _, role := range subtree {
		s.killRole(role)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		s.mu.Lock()
		left := 0
		for _, role := range subtree {
			if _, ok := rt.Children[role]; ok {
				left++
			}
		}
		s.mu.Unlock()
		if left == 0 {
			flushExitPending(exitCh)
			break
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			return false
		}
		select {
		case <-exitCh:
		case <-time.After(remain):
			return false
		}
	}

	if err := rt.Fabric.ReplacePair(bridge, authority.RoleApply, rt.RootKey); err != nil {
		return false
	}
	if err := rt.Fabric.ReplacePair(authority.RoleApply, authority.RoleJournal, rt.RootKey); err != nil {
		return false
	}
	if err := rt.Fabric.ReplacePair(authority.RoleJournal, authority.RoleAudit, rt.RootKey); err != nil {
		return false
	}
	if !s.replaceAuthAuditPair(rt) {
		return false
	}
	if err := rt.StartChild(ctx, authority.RoleAudit, authority.RoleJournal, exe); err != nil {
		return false
	}
	if !s.sendAuthAuditPeerFD(rt) {
		return false
	}
	if err := rt.StartChild(ctx, authority.RoleJournal, authority.RoleApply, exe); err != nil {
		return false
	}
	if err := rt.StartChild(ctx, authority.RoleApply, bridge, exe); err != nil {
		return false
	}

	ep, err := rt.Fabric.Endpoint(bridge, authority.RoleApply)
	if err != nil {
		return false
	}
	peerSock, err := ep.Conn.File()
	if err != nil {
		return false
	}
	_ = ep.Conn.Close()
	ep.Conn = nil
	if err := ipc.SendPeerFDFile(bridgeH.KeyChannel, peerSock); err != nil {
		_ = peerSock.Close()
		return false
	}
	_ = peerSock.Close()
	if bridgePID != 0 && bridgeH.Cmd != nil && bridgeH.Cmd.Process != nil &&
		bridgeH.Cmd.Process.Pid != bridgePID {
		return false
	}
	if authPID != 0 {
		authH, ok := rt.Children[authority.RoleAuth]
		if !ok || authH == nil || authH.Cmd == nil || authH.Cmd.Process == nil ||
			authH.Cmd.Process.Pid != authPID {
			return false
		}
	}
	return true
}

// replaceAuthAuditPair recreates the M2j auth↔audit edge before StartChild(audit).
func (s *Server) replaceAuthAuditPair(rt *supervisor.Runtime) bool {
	if len(s.opts.Peers) == 0 || rt == nil {
		return true
	}
	return rt.Fabric.ReplacePair(authority.RoleAuth, authority.RoleAudit, rt.RootKey) == nil
}

// sendAuthAuditPeerFD confers the auth-side ExtraPeer socket into surviving auth (M3b).
func (s *Server) sendAuthAuditPeerFD(rt *supervisor.Runtime) bool {
	if len(s.opts.Peers) == 0 || rt == nil {
		return true
	}
	authH, ok := rt.Children[authority.RoleAuth]
	if !ok || authH == nil || authH.KeyChannel == nil {
		return false
	}
	ep, err := rt.Fabric.Endpoint(authority.RoleAuth, authority.RoleAudit)
	if err != nil {
		return false
	}
	peerSock, err := ep.Conn.File()
	if err != nil {
		return false
	}
	_ = ep.Conn.Close()
	ep.Conn = nil
	if err := ipc.SendPeerFDFile(authH.KeyChannel, peerSock); err != nil {
		_ = peerSock.Close()
		return false
	}
	_ = peerSock.Close()
	return true
}

func (s *Server) roleList() []authority.ProcessRole {
	switch {
	case s.opts.DisableAuth:
		return []authority.ProcessRole{authority.RoleNet, authority.RoleApply}
	case s.opts.DisableParser:
		return []authority.ProcessRole{authority.RoleAuth, authority.RoleApply, authority.RoleNet}
	case !s.opts.DisableIndex:
		return []authority.ProcessRole{
			authority.RoleAuth, authority.RoleAudit, authority.RoleJournal,
			authority.RoleApply, authority.RoleIndex, authority.RolePlan,
			authority.RoleParser, authority.RoleNet,
		}
	case !s.opts.DisablePlan:
		return []authority.ProcessRole{
			authority.RoleAuth, authority.RoleAudit, authority.RoleJournal,
			authority.RoleApply, authority.RolePlan, authority.RoleParser, authority.RoleNet,
		}
	case s.opts.DisableJournal && s.opts.DisableAudit:
		return []authority.ProcessRole{
			authority.RoleAuth, authority.RoleParser, authority.RoleApply, authority.RoleNet,
		}
	case s.opts.DisableJournal:
		return []authority.ProcessRole{
			authority.RoleAuth, authority.RoleAudit, authority.RoleApply,
			authority.RoleParser, authority.RoleNet,
		}
	case s.opts.DisableAudit:
		return []authority.ProcessRole{
			authority.RoleAuth, authority.RoleJournal, authority.RoleApply,
			authority.RoleParser, authority.RoleNet,
		}
	default:
		return []authority.ProcessRole{
			authority.RoleAuth, authority.RoleAudit, authority.RoleJournal,
			authority.RoleApply, authority.RoleParser, authority.RoleNet,
		}
	}
}

// armWatchers starts one Wait owner per tracked child. Do not Wait those
// handles elsewhere.
func (s *Server) armWatchers(exitCh chan<- authority.ProcessRole) {
	s.mu.Lock()
	roles := make([]authority.ProcessRole, 0, len(s.rt.Children))
	for role := range s.rt.Children {
		roles = append(roles, role)
	}
	s.mu.Unlock()
	for _, role := range roles {
		s.armWatcher(role, exitCh)
	}
}

// armWatcher starts a Wait owner for one role.
func (s *Server) armWatcher(role authority.ProcessRole, exitCh chan<- authority.ProcessRole) {
	s.mu.Lock()
	var h *launcher.Handle
	if s.rt != nil {
		h = s.rt.Children[role]
	}
	s.mu.Unlock()
	if h == nil {
		return
	}
	go func() {
		_ = h.Wait()
		if h.KeyChannel != nil {
			_ = h.KeyChannel.Close()
			h.KeyChannel = nil
		}
		s.mu.Lock()
		current := s.rt != nil && s.rt.Children[role] == h
		if current {
			delete(s.rt.Children, role)
		}
		s.mu.Unlock()
		// M3j: superseded handles (RestartOne replaced the child) must not
		// signal exitCh — that stale role would burn the restart budget.
		if !current {
			return
		}
		select {
		case exitCh <- role:
		case <-s.done:
		}
	}()
}

// flushExitPending non-blocking drains buffered child-exit notifications (M3j).
func flushExitPending(exitCh <-chan authority.ProcessRole) {
	for {
		select {
		case <-exitCh:
		default:
			return
		}
	}
}

func (s *Server) drainExits(exitCh <-chan authority.ProcessRole, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		s.mu.Lock()
		n := len(s.rt.Children)
		s.mu.Unlock()
		if n == 0 {
			return nil
		}
		remain := time.Until(deadline)
		if remain <= 0 {
			return fmt.Errorf("children still tracked: %v", s.rt.ChildRoles())
		}
		select {
		case <-exitCh:
		case <-time.After(remain):
			return fmt.Errorf("children still tracked: %v", s.rt.ChildRoles())
		}
	}
}

func (s *Server) killRole(role authority.ProcessRole) {
	s.mu.Lock()
	h := s.rt.Children[role]
	s.mu.Unlock()
	if h != nil && h.Cmd != nil && h.Cmd.Process != nil && h.Cmd.ProcessState == nil {
		_ = h.Cmd.Process.Kill()
	}
}

func (s *Server) killTracked() {
	s.mu.Lock()
	roles := make([]authority.ProcessRole, 0, len(s.rt.Children))
	for role := range s.rt.Children {
		roles = append(roles, role)
	}
	s.mu.Unlock()
	for _, role := range roles {
		s.killRole(role)
	}
}

func (s *Server) respawnAll(ctx context.Context) error {
	s.mu.Lock()
	n := len(s.rt.Children)
	s.mu.Unlock()
	if n != 0 {
		return fmt.Errorf("cannot respawn while children tracked: %v", s.rt.ChildRoles())
	}
	if err := replaceRolePairs(s.rt, s.opts); err != nil {
		return err
	}
	return startRoleChildren(s.rt, ctx, s.exe, s.opts)
}

func replaceRolePairs(rt *supervisor.Runtime, opts ServeOptions) error {
	switch {
	case opts.DisableAuth:
		return rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleApply, rt.RootKey)
	case opts.DisableParser:
		if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleAuth, rt.RootKey); err != nil {
			return err
		}
		return rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleApply, rt.RootKey)
	case !opts.DisableIndex:
		if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleAuth, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleParser, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleParser, authority.RolePlan, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RolePlan, authority.RoleIndex, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleIndex, authority.RoleApply, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleApply, authority.RoleJournal, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleJournal, authority.RoleAudit, rt.RootKey); err != nil {
			return err
		}
		if len(opts.Peers) > 0 && !opts.DisableAudit && !opts.DisableIndex {
			return rt.Fabric.ReplacePair(authority.RoleAuth, authority.RoleAudit, rt.RootKey)
		}
		return nil
	case !opts.DisablePlan:
		if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleAuth, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleParser, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleParser, authority.RolePlan, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RolePlan, authority.RoleApply, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleApply, authority.RoleJournal, rt.RootKey); err != nil {
			return err
		}
		return rt.Fabric.ReplacePair(authority.RoleJournal, authority.RoleAudit, rt.RootKey)
	case opts.DisableJournal && opts.DisableAudit:
		if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleAuth, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleParser, rt.RootKey); err != nil {
			return err
		}
		return rt.Fabric.ReplacePair(authority.RoleParser, authority.RoleApply, rt.RootKey)
	case opts.DisableJournal:
		if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleAuth, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleParser, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleParser, authority.RoleApply, rt.RootKey); err != nil {
			return err
		}
		return rt.Fabric.ReplacePair(authority.RoleApply, authority.RoleAudit, rt.RootKey)
	case opts.DisableAudit:
		if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleAuth, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleParser, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleParser, authority.RoleApply, rt.RootKey); err != nil {
			return err
		}
		return rt.Fabric.ReplacePair(authority.RoleApply, authority.RoleJournal, rt.RootKey)
	default:
		if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleAuth, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleNet, authority.RoleParser, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleParser, authority.RoleApply, rt.RootKey); err != nil {
			return err
		}
		if err := rt.Fabric.ReplacePair(authority.RoleApply, authority.RoleJournal, rt.RootKey); err != nil {
			return err
		}
		return rt.Fabric.ReplacePair(authority.RoleJournal, authority.RoleAudit, rt.RootKey)
	}
}

func startRoleChildren(rt *supervisor.Runtime, ctx context.Context, exe string, opts ServeOptions) error {
	switch {
	case opts.DisableAuth:
		if err := rt.StartChild(ctx, authority.RoleApply, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start apply: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleNet, authority.RoleApply, exe); err != nil {
			return fmt.Errorf("start net: %w", err)
		}
	case opts.DisableParser:
		if err := rt.StartChild(ctx, authority.RoleAuth, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start auth: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleApply, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start apply: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleNet, authority.RoleAuth, exe); err != nil {
			return fmt.Errorf("start net: %w", err)
		}
	case !opts.DisableIndex:
		// audit before auth (M2j auth ExtraPeer→audit); then journal→apply→index→plan→parser→net
		if err := rt.StartChild(ctx, authority.RoleAudit, authority.RoleJournal, exe); err != nil {
			return fmt.Errorf("start audit: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleAuth, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start auth: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleJournal, authority.RoleApply, exe); err != nil {
			return fmt.Errorf("start journal: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleApply, authority.RoleIndex, exe); err != nil {
			return fmt.Errorf("start apply: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleIndex, authority.RolePlan, exe); err != nil {
			return fmt.Errorf("start index: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RolePlan, authority.RoleParser, exe); err != nil {
			return fmt.Errorf("start plan: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleParser, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start parser: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleNet, authority.RoleAuth, exe); err != nil {
			return fmt.Errorf("start net: %w", err)
		}
	case !opts.DisablePlan:
		// audit→auth→journal→apply→plan→parser→net (extra peers conferred bottom-up)
		if err := rt.StartChild(ctx, authority.RoleAudit, authority.RoleJournal, exe); err != nil {
			return fmt.Errorf("start audit: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleAuth, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start auth: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleJournal, authority.RoleApply, exe); err != nil {
			return fmt.Errorf("start journal: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleApply, authority.RolePlan, exe); err != nil {
			return fmt.Errorf("start apply: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RolePlan, authority.RoleParser, exe); err != nil {
			return fmt.Errorf("start plan: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleParser, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start parser: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleNet, authority.RoleAuth, exe); err != nil {
			return fmt.Errorf("start net: %w", err)
		}
	case opts.DisableJournal && opts.DisableAudit:
		if err := rt.StartChild(ctx, authority.RoleAuth, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start auth: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleApply, authority.RoleParser, exe); err != nil {
			return fmt.Errorf("start apply: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleParser, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start parser: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleNet, authority.RoleAuth, exe); err != nil {
			return fmt.Errorf("start net: %w", err)
		}
	case opts.DisableJournal:
		if err := rt.StartChild(ctx, authority.RoleAuth, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start auth: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleAudit, authority.RoleApply, exe); err != nil {
			return fmt.Errorf("start audit: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleApply, authority.RoleParser, exe); err != nil {
			return fmt.Errorf("start apply: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleParser, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start parser: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleNet, authority.RoleAuth, exe); err != nil {
			return fmt.Errorf("start net: %w", err)
		}
	case opts.DisableAudit:
		if err := rt.StartChild(ctx, authority.RoleAuth, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start auth: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleJournal, authority.RoleApply, exe); err != nil {
			return fmt.Errorf("start journal: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleApply, authority.RoleParser, exe); err != nil {
			return fmt.Errorf("start apply: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleParser, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start parser: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleNet, authority.RoleAuth, exe); err != nil {
			return fmt.Errorf("start net: %w", err)
		}
	default:
		// audit before auth/journal; journal before apply; apply before parser.
		if err := rt.StartChild(ctx, authority.RoleAudit, authority.RoleJournal, exe); err != nil {
			return fmt.Errorf("start audit: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleAuth, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start auth: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleJournal, authority.RoleApply, exe); err != nil {
			return fmt.Errorf("start journal: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleApply, authority.RoleParser, exe); err != nil {
			return fmt.Errorf("start apply: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleParser, authority.RoleNet, exe); err != nil {
			return fmt.Errorf("start parser: %w", err)
		}
		if err := rt.StartChild(ctx, authority.RoleNet, authority.RoleAuth, exe); err != nil {
			return fmt.Errorf("start net: %w", err)
		}
	}
	return nil
}

func waitReadyFile(path string, d time.Duration) (string, error) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil {
			addr := strings.TrimSpace(string(b))
			if addr != "" {
				return addr, nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return "", fmt.Errorf("timeout waiting for net ready at %s", path)
}
