//go:build unix

package launcher

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/gpicchiarelli/integris/internal/authority"
)

// Handle is a started child.
type Handle struct {
	Cmd  *exec.Cmd
	Role authority.ProcessRole
}

// Start validates req and starts the child. The caller owns waiting via Wait.
func Start(ctx context.Context, req Request) (*Handle, error) {
	if ctx == nil {
		return nil, fail("context", "nil context")
	}
	if !req.EngineeringMode {
		return nil, fail("mode", "release launch refused; EngineeringMode required (IP-A-0003)")
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
		EnvMode + "=" + ModeEngineering,
		EnvRole + "=" + string(req.Role),
		EnvPeer + "=" + string(req.Peer),
		EnvNonce + "=" + hex.EncodeToString(req.Nonce[:]),
	}
	keyFD, transport, err := CreateKeyFD(req.MACKey)
	if err != nil {
		return nil, err
	}
	env = append(env, EnvKeyTransport+"="+string(transport))
	cmd := exec.CommandContext(ctx, req.Executable)
	cmd.Dir = work
	cmd.Env = env // intentional: do not inherit parent env; no MAC key in env
	cmd.ExtraFiles = []*os.File{req.Socket, keyFD}
	if err := cmd.Start(); err != nil {
		_ = keyFD.Close()
		return nil, fail("start", err.Error())
	}
	_ = keyFD.Close() // child holds the dup'd FD
	return &Handle{Cmd: cmd, Role: req.Role}, nil
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
