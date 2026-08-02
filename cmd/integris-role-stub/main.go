//go:build unix

package main

import (
	"bytes"
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
	defer func() { _ = sock.Close() }()

	kt := os.Getenv(launcher.EnvKeyTransport)
	var keyF, keyCh *os.File
	hold := false
	if kt == string(launcher.KeyTransportSCMRights) {
		// M2l: keys arrive on the dedicated key-channel socket (fd4), not IPC.
		keyCh = os.NewFile(uintptr(launcher.KeyChannelFDSCM), "key-channel")
		if keyCh == nil {
			return fmt.Errorf("missing key channel fd")
		}
		f, err := ipc.RecvFDFile(keyCh)
		if err != nil {
			_ = keyCh.Close()
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

	switch os.Getenv(launcher.EnvMode) {
	case launcher.ModeEngineering, launcher.ModeRelease:
	default:
		return fmt.Errorf("refusing unknown launch mode")
	}
	role := authority.ProcessRole(os.Getenv(launcher.EnvRole))
	peer := authority.ProcessRole(os.Getenv(launcher.EnvPeer))
	if role == "" || peer == "" {
		return fmt.Errorf("missing role/peer")
	}

	_ = confine.LimitConferredFDs(sock, keyF)
	opts := confine.ApplyOptions{}
	if rawRoots := os.Getenv(launcher.EnvAllowRoots); rawRoots != "" {
		opts.AllowRoots = splitAllowRoots(rawRoots)
	}
	rootFDs := launcher.ClaimAllowRootFDs(os.Getenv(launcher.EnvAllowRootFDs))
	defer launcher.CloseAllowRootFDs(rootFDs)
	opts.AllowRootFDs = rootFDs
	// FreeBSD ApplyEngineeringOpts: jail → LimitAllowRootFDs → CapEnter (M3s).
	_ = confine.ApplyEngineeringOpts(role, opts)
	negFindings := confine.NegativeEngineeringOpts(role, opts)
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

	stubMode := os.Getenv(launcher.EnvStubMode)
	if stubMode == "" {
		stubMode = launcher.StubModeRespond
	}
	switch stubMode {
	case launcher.StubModeHoldInitiate, launcher.StubModeHoldRespond:
		hold = true
	}
	if !hold && keyCh != nil {
		_ = keyCh.Close()
		keyCh = nil
	}
	if keyCh != nil {
		defer keyCh.Close()
	}

	switch stubMode {
	case launcher.StubModeInitiate:
		return initiate(sock, &ch, kt, negAck)
	case launcher.StubModeRespond:
		return respond(sock, &ch, kt, negAck)
	case launcher.StubModeHoldInitiate:
		return holdExchange(true, &sock, role, peer, nonce, macKey, keyCh, kt, negAck)
	case launcher.StubModeHoldRespond:
		return holdExchange(false, &sock, role, peer, nonce, macKey, keyCh, kt, negAck)
	default:
		return fmt.Errorf("unknown stub mode %q", stubMode)
	}
}

// holdExchange: first IPC exchange, RecvPeerFDFile, second exchange (M2n).
func holdExchange(asInitiator bool, sock **os.File, role, peer authority.ProcessRole, nonce [16]byte, macKey []byte, keyCh *os.File, kt, negAck string) error {
	if keyCh == nil {
		return fmt.Errorf("hold mode requires key channel")
	}
	ch, err := ipc.NewAuthenticatedChannel(role, peer, nonce, macKey)
	if err != nil {
		return err
	}
	if asInitiator {
		if err := initiate(*sock, &ch, kt, negAck); err != nil {
			return err
		}
	} else {
		if err := respond(*sock, &ch, kt, negAck); err != nil {
			return err
		}
	}
	// Signal parent over the key channel (no filesystem; Seatbelt-safe).
	if _, err := keyCh.Write(ipc.StubReadyMagic); err != nil {
		return fmt.Errorf("stub ready: %w", err)
	}
	newSock, err := ipc.RecvPeerFDFile(keyCh)
	if err != nil {
		return fmt.Errorf("recv peer fd: %w", err)
	}
	_ = (*sock).Close()
	*sock = newSock
	ch2, err := ipc.NewAuthenticatedChannel(role, peer, nonce, macKey)
	if err != nil {
		return err
	}
	if asInitiator {
		return initiate(*sock, &ch2, kt, negAck+"|REBIND")
	}
	return respond(*sock, &ch2, kt, negAck+"|REBIND")
}

func respond(sock *os.File, ch *ipc.ChannelState, kt, negAck string) error {
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

func initiate(sock *os.File, ch *ipc.ChannelState, kt, negAck string) error {
	payload := []byte("pair")
	payload = append(payload, []byte(negAck)...)
	if kt != "" {
		payload = append(payload, []byte("|KEY:"+kt)...)
	}
	raw, err := ch.Encode(ipc.TypeRequest, payload)
	if err != nil {
		return err
	}
	if err := ipc.WriteFrame(sock, raw); err != nil {
		return err
	}
	respRaw, err := ipc.ReadFrame(sock, 0)
	if err != nil {
		return err
	}
	resp, err := ch.Decode(respRaw)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(resp.Payload, []byte("ack:pair")) {
		return fmt.Errorf("unexpected response %q", resp.Payload)
	}
	return nil
}

func splitAllowRoots(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ':' {
			part := s[start:i]
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}
