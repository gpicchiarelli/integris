//go:build unix

package main

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

// Engineering role stub: claim conferred fds, apply confinement, one IPC exchange.
func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "integris-role-stub: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Wrap inherited fds before Landlock/pledge (no new path opens).
	sock := os.NewFile(uintptr(launcher.IPCFileFD), "ipc")
	if sock == nil {
		return fmt.Errorf("missing ipc fd")
	}
	defer sock.Close()
	keyF := os.NewFile(uintptr(launcher.KeyFileFD), "key")
	if keyF == nil {
		return fmt.Errorf("missing key fd")
	}
	defer keyF.Close()

	_ = confine.ApplyEngineering()

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

	macKey, err := io.ReadAll(io.LimitReader(keyF, 257))
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	if len(macKey) < 16 || len(macKey) > 256 {
		return fmt.Errorf("bad mac key length %d", len(macKey))
	}

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
