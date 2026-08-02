//go:build !unix

package daemon

import (
	"context"
	"fmt"

	"github.com/gpicchiarelli/integris/internal/authority"
)

// ServeOptions mirrors the Unix API for build tags.
type ServeOptions struct {
	Addr           string
	Destination    string
	RootKey        []byte
	Once           bool
	MaxRestarts    int
	Executable     string
	Ready          chan<- string
	DisableAuth    bool
	DisableParser  bool
	DisableAudit   bool
	DisableJournal bool
	DisablePlan    bool
	DisableIndex   bool
	Peers          map[string][]byte
	StrictLaunch   bool
}

// Status mirrors the Unix API.
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

// Server mirrors the Unix API.
type Server struct{}

// Serve is unavailable off Unix.
func Serve(ctx context.Context, opts ServeOptions) error {
	_ = ctx
	_ = opts
	return fmt.Errorf("integrisd M2a–M2k requires Unix")
}

// Start is unavailable off Unix.
func Start(ctx context.Context, opts ServeOptions) (*Server, error) {
	_ = ctx
	_ = opts
	return nil, fmt.Errorf("integrisd M2a–M2k requires Unix")
}

// RunRole is unavailable off Unix.
func RunRole() error {
	return fmt.Errorf("integrisd M2a–M2k requires Unix")
}

func (s *Server) Status() Status { return Status{} }
func (s *Server) Wait() error    { return fmt.Errorf("integrisd M2a–M2k requires Unix") }
func (s *Server) Close() error   { return nil }
func (s *Server) KillRole(role authority.ProcessRole) error {
	_ = role
	return fmt.Errorf("integrisd M2a–M2k requires Unix")
}
func (s *Server) ChildPID(role authority.ProcessRole) (int, bool) {
	_ = role
	return 0, false
}
