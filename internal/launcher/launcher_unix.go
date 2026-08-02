//go:build unix

package launcher

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gpicchiarelli/integris/internal/authority"
)

// Handle is a started child.
type Handle struct {
	Cmd  *exec.Cmd
	Role authority.ProcessRole
	// KeyFD is non-nil when using the default SCM_RIGHTS path. Caller must
	// confer it with ipc.SendFD (or SendFDFile) then Close it.
	KeyFD *os.File
	// KeyChannel is the parent end of a dedicated socketpair for SCM key
	// conferral (M2l). Caller SendFDFile(KeyChannel, KeyFD/…) then Close.
	KeyChannel *os.File
	// RootKeyFD / ExtraKeyFD are conferred via KeyChannel after start (M2l).
	RootKeyFD  *os.File
	ExtraKeyFD *os.File
}

// Start validates req and starts the child. The caller owns waiting via Wait.
func Start(ctx context.Context, req Request) (*Handle, error) {
	if ctx == nil {
		return nil, fail("context", "nil context")
	}
	mode, err := launchMode(req.EngineeringMode, req.ReleaseMode)
	if err != nil {
		return nil, err
	}
	if req.Executable == "" || !filepath.IsAbs(req.Executable) {
		return nil, fail("path", "executable must be an absolute path")
	}
	if req.Role == "" || req.Peer == "" || req.Role == req.Peer {
		return nil, fail("role", "invalid role/peer")
	}
	if len(req.MACKey) < 16 {
		return nil, fail("key", "MAC key must be at least 16 bytes")
	}
	if req.Socket == nil {
		return nil, fail("socket", "missing conferred socket file")
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		return nil, fail("context", "context deadline required")
	}
	work := req.WorkDir
	if work == "" {
		dir, err := os.MkdirTemp("", "integris-launch-*")
		if err != nil {
			return nil, fail("workdir", err.Error())
		}
		work = dir
	}
	env := []string{
		EnvMode + "=" + mode,
		EnvRole + "=" + string(req.Role),
		EnvPeer + "=" + string(req.Peer),
		EnvNonce + "=" + hex.EncodeToString(req.Nonce[:]),
	}
	if len(req.Confer) > 0 {
		parts := make([]string, len(req.Confer))
		for i, c := range req.Confer {
			parts[i] = string(c)
		}
		env = append(env, EnvConfer+"="+strings.Join(parts, ","))
	}
	if len(req.SlotKinds) > 0 {
		env = append(env, EnvSlots+"="+strings.Join(req.SlotKinds, ","))
	}
	if len(req.AllowRoots) > 0 {
		env = append(env, EnvAllowRoots+"="+strings.Join(req.AllowRoots, ":"))
	}
	stubMode := req.StubMode
	if stubMode == "" {
		stubMode = StubModeRespond
	}
	env = append(env, EnvStubMode+"="+stubMode)
	if req.ListenAddr != "" {
		env = append(env, EnvListenAddr+"="+req.ListenAddr)
	}
	if req.Once {
		env = append(env, EnvOnce+"=1")
	}
	if req.ReadyPath != "" {
		env = append(env, EnvReadyPath+"="+req.ReadyPath)
	}
	keyFD, transport, err := CreateKeyFD(req.MACKey)
	if err != nil {
		return nil, err
	}
	var pushRootFD *os.File
	if len(req.RootKey) > 0 {
		pushRootFD, _, err = CreateKeyFD(req.RootKey)
		if err != nil {
			_ = keyFD.Close()
			return nil, err
		}
		env = append(env, EnvHasRootKey+"=1")
	}
	var extraKeyFD *os.File
	if req.ExtraPeer != "" {
		if req.ExtraSocket == nil || len(req.ExtraMACKey) < 16 {
			_ = keyFD.Close()
			if pushRootFD != nil {
				_ = pushRootFD.Close()
			}
			return nil, fail("peer", "ExtraPeer requires socket and MAC key")
		}
		extraKeyFD, _, err = CreateKeyFD(req.ExtraMACKey)
		if err != nil {
			_ = keyFD.Close()
			if pushRootFD != nil {
				_ = pushRootFD.Close()
			}
			return nil, err
		}
		env = append(env, EnvExtraPeer+"="+string(req.ExtraPeer))
	}
	rootFiles, _, err := openAllowRootDirs(req.AllowRoots)
	if err != nil {
		_ = keyFD.Close()
		if pushRootFD != nil {
			_ = pushRootFD.Close()
		}
		if extraKeyFD != nil {
			_ = extraKeyFD.Close()
		}
		return nil, err
	}
	defer closeFiles(rootFiles)

	cmd := exec.CommandContext(ctx, req.Executable)
	cmd.Dir = work
	h := &Handle{Cmd: cmd, Role: req.Role}
	if req.KeyViaExtraFiles {
		env = append(env, EnvKeyTransport+"="+string(transport))
		extras := make([]*os.File, 0, 5+len(rootFiles))
		extras = append(extras, req.Socket, keyFD)
		extraIdx := 2
		if pushRootFD != nil {
			extras = append(extras, pushRootFD)
			extraIdx++
		}
		if extraKeyFD != nil {
			extras = append(extras, req.ExtraSocket, extraKeyFD)
			extraIdx += 2
		}
		extras = append(extras, rootFiles...)
		if fdEnv := allowRootFDEnv(extraIdx, len(rootFiles)); fdEnv != "" {
			env = append(env, EnvAllowRootFDs+"="+fdEnv)
		}
		cmd.Env = env // intentional: do not inherit parent env; no MAC key in env
		cmd.ExtraFiles = extras
		if err := cmd.Start(); err != nil {
			_ = keyFD.Close()
			if pushRootFD != nil {
				_ = pushRootFD.Close()
			}
			if extraKeyFD != nil {
				_ = extraKeyFD.Close()
			}
			return nil, fail("start", err.Error())
		}
		_ = keyFD.Close() // child holds the dup'd FD
		if pushRootFD != nil {
			_ = pushRootFD.Close()
		}
		if extraKeyFD != nil {
			_ = extraKeyFD.Close()
		}
		return h, nil
	}
	// M2l SCM path: ExtraFiles = IPC sock(s) + key-channel child end; keys via SCM.
	env = append(env, EnvKeyTransport+"="+string(KeyTransportSCMRights))
	keyChParent, keyChChild, err := unixSocketpair()
	if err != nil {
		_ = keyFD.Close()
		if pushRootFD != nil {
			_ = pushRootFD.Close()
		}
		if extraKeyFD != nil {
			_ = extraKeyFD.Close()
		}
		return nil, fail("socket", err.Error())
	}
	extras := make([]*os.File, 0, 3+len(rootFiles))
	extras = append(extras, req.Socket, keyChChild)
	sockCount := 2
	if req.ExtraPeer != "" {
		extras = append(extras, req.ExtraSocket)
		sockCount++
	}
	extras = append(extras, rootFiles...)
	if fdEnv := allowRootFDEnv(sockCount, len(rootFiles)); fdEnv != "" {
		env = append(env, EnvAllowRootFDs+"="+fdEnv)
	}
	cmd.Env = env
	cmd.ExtraFiles = extras
	if err := cmd.Start(); err != nil {
		_ = keyFD.Close()
		_ = keyChParent.Close()
		_ = keyChChild.Close()
		if pushRootFD != nil {
			_ = pushRootFD.Close()
		}
		if extraKeyFD != nil {
			_ = extraKeyFD.Close()
		}
		return nil, fail("start", err.Error())
	}
	_ = keyChChild.Close() // child holds the dup
	h.KeyFD = keyFD
	h.KeyChannel = keyChParent
	h.RootKeyFD = pushRootFD
	h.ExtraKeyFD = extraKeyFD
	return h, nil
}

// Wait waits for the child.
func (h *Handle) Wait() error {
	if h == nil || h.Cmd == nil {
		return fail("handle", "nil handle")
	}
	if err := h.Cmd.Wait(); err != nil {
		return fail("wait", err.Error())
	}
	return nil
}

// RunEngineering starts an absolute executable with no shell and waits for exit.
// The process environment is only ModeEngineering plus req.Env (no parent inherit).
func RunEngineering(ctx context.Context, req ExecRequest) error {
	if ctx == nil {
		return fail("context", "nil context")
	}
	if !req.EngineeringMode {
		return fail("mode", "release launch refused; EngineeringMode required (IP-A-0003)")
	}
	if req.Executable == "" || !filepath.IsAbs(req.Executable) {
		return fail("path", "executable must be an absolute path")
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		return fail("context", "context deadline required")
	}
	env := make([]string, 0, 1+len(req.Env))
	env = append(env, EnvMode+"="+ModeEngineering)
	env = append(env, req.Env...)
	cmd := exec.CommandContext(ctx, req.Executable, req.Args...)
	cmd.Dir = req.Dir
	cmd.Env = env
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// ExitSignaled reports whether err is an exec.ExitError caused by a signal
// (e.g. SIGKILL from an OS crash harness).
func ExitSignaled(err error) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return false
	}
	status, ok := ee.Sys().(syscall.WaitStatus)
	if !ok {
		return false
	}
	return status.Signaled()
}

// BuildGoPackage runs `go build -o out pkg` for engineering test helpers.
func BuildGoPackage(ctx context.Context, moduleRoot, pkg, out string) error {
	if ctx == nil {
		return fail("context", "nil context")
	}
	if !filepath.IsAbs(out) {
		return fail("path", "output must be absolute")
	}
	if moduleRoot == "" || pkg == "" {
		return fail("path", "module root and package required")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		return fail("toolchain", err.Error())
	}
	cmd := exec.CommandContext(ctx, goBin, "build", "-o", out, pkg)
	cmd.Dir = moduleRoot
	cmd.Env = os.Environ()
	if outb, err := cmd.CombinedOutput(); err != nil {
		return fail("build", fmt.Sprintf("%v: %s", err, outb))
	}
	return nil
}

func launchMode(engineering, release bool) (string, error) {
	switch {
	case engineering && release:
		return "", fail("mode", "EngineeringMode and ReleaseMode are mutually exclusive")
	case engineering:
		return ModeEngineering, nil
	case release:
		return ModeRelease, nil
	default:
		return "", fail("mode", "EngineeringMode or ReleaseMode required (IP-A-0003)")
	}
}

func unixSocketpair() (parent, child *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	parent = os.NewFile(uintptr(fds[0]), "integris-keych-parent")
	child = os.NewFile(uintptr(fds[1]), "integris-keych-child")
	if parent == nil || child == nil {
		if parent != nil {
			_ = parent.Close()
		}
		if child != nil {
			_ = child.Close()
		}
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
		return nil, nil, fail("socket", "NewFile failed")
	}
	return parent, child, nil
}
