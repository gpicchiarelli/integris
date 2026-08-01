//go:build unix

package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/launcher"
)

// Engineering role stub: one authenticated IPC request/response on fd 3, then exit.
// MAC key is read from fd 4 (pipe). Not a product daemon (IP-A-0003).
func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "integris-role-stub: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	applyBestEffortConfinement()

	if os.Getenv(launcher.EnvMode) != launcher.ModeEngineering {
		return fmt.Errorf("refusing non-engineering launch mode")
	}
	role := authority.ProcessRole(os.Getenv(launcher.EnvRole))
	peer := authority.ProcessRole(os.Getenv(launcher.EnvPeer))
	if role == "" || peer == "" {
		return fmt.Errorf("missing role/peer")
	}
	nonceRaw, err := hex.DecodeString(os.Getenv(launcher.EnvNonce))
	if err != nil || len(nonceRaw) != 16 {
		return fmt.Errorf("bad nonce")
	}
	var nonce [16]byte
	copy(nonce[:], nonceRaw)

	macKey, err := readKeyFD(launcher.KeyFileFD)
	if err != nil {
		return err
	}
	sock, err := os.OpenFile(fmt.Sprintf("/dev/fd/%d", launcher.IPCFileFD), os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open ipc fd: %w", err)
	}
	defer sock.Close()

	ch, err := ipc.NewAuthenticatedChannel(role, peer, nonce, macKey)
	if err != nil {
		return err
	}
	raw, err := ipc.ReadFrame(sock, 0)
	if err != nil {
		return err
	}
	frame, err := ch.Decode(raw)
	if err != nil {
		return err
	}
	reply, err := ch.Encode(ipc.TypeResponse, append([]byte("ack:"), frame.Payload...))
	if err != nil {
		return err
	}
	return ipc.WriteFrame(sock, reply)
}

func readKeyFD(fd int) ([]byte, error) {
	f, err := os.OpenFile(fmt.Sprintf("/dev/fd/%d", fd), os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open key fd: %w", err)
	}
	defer f.Close()
	// Bound: MAC keys are small; refuse > 256 bytes.
	buf, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	if len(buf) < 16 || len(buf) > 256 {
		return nil, fmt.Errorf("bad mac key length %d", len(buf))
	}
	return buf, nil
}
