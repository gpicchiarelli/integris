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

// Engineering role stub: claim conferred fds, apply confinement, negative
// probes, one IPC exchange. Not a product daemon (IP-A-0003).
func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "integris-role-stub: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	sock := os.NewFile(uintptr(launcher.IPCFileFD), "ipc")
	if sock == nil {
		return fmt.Errorf("missing ipc fd")
	}
	defer sock.Close()

	kt := os.Getenv(launcher.EnvKeyTransport)
	var keyF *os.File
	if kt == string(launcher.KeyTransportSCMRights) {
		f, err := ipc.RecvFDFile(sock)
		if err != nil {
			return fmt.Errorf("recv key fd: %w", err)
		}
		keyF = f
	} else {
		keyF = os.NewFile(uintptr(launcher.KeyFileFD), "key")
		if keyF == nil {
			return fmt.Errorf("missing key fd")
		}
	}
	defer keyF.Close()

	_ = confine.LimitConferredFDs(sock, keyF)
	_ = confine.ApplyEngineering()
	negFindings := confine.NegativeEngineering()

	if os.Getenv(launcher.EnvMode) != launcher.ModeEngineering {
		return fmt.Errorf("refusing non-engineering launch mode")
	}
	role := authority.ProcessRole(os.Getenv(launcher.EnvRole))
	peer := authority.ProcessRole(os.Getenv(launcher.EnvPeer))
	if role == "" || peer == "" {
		return fmt.Errorf("missing role/peer")
	}
	negFindings = append(negFindings, confine.NegativeRoleSemantic(confine.RoleProbeInput{
		Role:      role,
		Confer:    confine.ParseCapList(os.Getenv(launcher.EnvConfer)),
		SlotKinds: confine.ParseSlotKindList(os.Getenv(launcher.EnvSlots)),
	})...)
	negAck := confine.FormatNegativeAck(negFindings)
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
	payload := append([]byte("ack:"), frame.Payload...)
	payload = append(payload, []byte(negAck)...)
	if kt != "" {
		payload = append(payload, []byte("|KEY:"+kt)...)
	}
	reply, err := ch.Encode(ipc.TypeResponse, payload)
	if err != nil {
		return err
	}
	return ipc.WriteFrame(sock, reply)
}
