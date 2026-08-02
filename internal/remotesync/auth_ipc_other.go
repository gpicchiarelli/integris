//go:build !unix

package remotesync

import (
	"fmt"

	"github.com/gpicchiarelli/integris/internal/ipc"
)

// AuthAuditPeer is an optional auth→audit link for peer admit/deny (M2i).
type AuthAuditPeer struct {
	RW   interface{}
	Ch   *ipc.ChannelState
	Side func() (interface{}, *ipc.ChannelState)
}

// AcceptHandshakeViaAuthIPC is Unix-only.
func AcceptHandshakeViaAuthIPC(conn interface{}, authSock interface{}, ch *ipc.ChannelState) (*Session, error) {
	return nil, fmt.Errorf("auth handshake ipc: unix only")
}

// ServeAuthHandshakeIPC is Unix-only.
func ServeAuthHandshakeIPC(rootKey []byte, authSock interface{}, ch *ipc.ChannelState, once bool, audit AuthAuditPeer) error {
	return fmt.Errorf("auth handshake ipc: unix only")
}
