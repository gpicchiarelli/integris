// Command integrisd is the M2a–M2i engineering privilege-separated receive daemon.
// Without INTEGRIS_ROLE it supervises the eight-role receive chain (same binary
// re-exec). With INTEGRIS_ROLE it runs the conferred child worker.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gpicchiarelli/integris/internal/daemon"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"github.com/gpicchiarelli/integris/internal/remotesync"
)

func main() {
	if os.Getenv(launcher.EnvRole) != "" {
		if err := daemon.RunRole(); err != nil {
			fmt.Fprintf(os.Stderr, "integrisd: %v\n", err)
			os.Exit(1)
		}
		return
	}
	os.Exit(runSupervisor(os.Args[1:]))
}

func runSupervisor(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage()
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	if args[0] != "serve" {
		fmt.Fprintf(os.Stderr, "integrisd: unknown command %q\n", args[0])
		usage()
		return 2
	}
	return runServe(args[1:])
}

type peerKeyFlags map[string]string

func (p *peerKeyFlags) String() string {
	if p == nil || len(*p) == 0 {
		return ""
	}
	var b strings.Builder
	for id, path := range *p {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(id)
		b.WriteByte('=')
		b.WriteString(path)
	}
	return b.String()
}

func (p *peerKeyFlags) Set(v string) error {
	if *p == nil {
		*p = make(map[string]string)
	}
	id, path, err := remotesync.ParsePeerKeyFlag(v)
	if err != nil {
		return err
	}
	if _, exists := (*p)[id]; exists {
		return fmt.Errorf("duplicate peer id %q", id)
	}
	(*p)[id] = path
	return nil
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", "127.0.0.1:9100", "listen address")
	dest := fs.String("destination", "", "destination directory")
	key := fs.String("key", "", "32-byte root key (hex or raw); mutually exclusive with -peer-key")
	keyFile := fs.String("keyfile", "", "path to root key file; mutually exclusive with -peer-key")
	once := fs.Bool("once", false, "serve a single connection then exit")
	maxRestarts := fs.Int("max-restarts", -1, "pair restart budget after child crash (-1=default 3; 0=disable; ignored with -once)")
	strict := fs.Bool("strict-launch", false, "M2k release-shaped launch (full role chain; fail-closed confinement)")
	var peers peerKeyFlags
	fs.Var(&peers, "peer-key", "admit peer ID=PATH (repeatable; M2i keyring; exclusive with -key/-keyfile)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*dest) == "" {
		fmt.Fprintln(os.Stderr, "integrisd serve: -destination is required")
		return 2
	}

	opts := daemon.ServeOptions{
		Addr:         *addr,
		Destination:  *dest,
		Once:         *once,
		MaxRestarts:  *maxRestarts,
		StrictLaunch: *strict,
	}
	if len(peers) > 0 {
		if strings.TrimSpace(*key) != "" || strings.TrimSpace(*keyFile) != "" {
			fmt.Fprintln(os.Stderr, "integrisd serve: -peer-key cannot be combined with -key/-keyfile")
			return 2
		}
		kr := make(remotesync.PeerKeyring, len(peers))
		for id, path := range peers {
			k, err := remotesync.LoadRootKeyFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "integrisd serve: peer %s: %v\n", id, err)
				return 2
			}
			kr[id] = k
		}
		opts.Peers = kr
	} else {
		root, err := loadKey(*key, *keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "integrisd serve: %v\n", err)
			return 2
		}
		opts.RootKey = root
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "integrisd serve: %v\n", err)
		return 1
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integrisd serve: %v\n", err)
		return 1
	}
	opts.Executable = exe
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = daemon.Serve(ctx, opts)
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "integrisd serve: %v\n", err)
		return 1
	}
	return 0
}

func loadKey(key, keyFile string) ([]byte, error) {
	if strings.TrimSpace(keyFile) != "" {
		return remotesync.LoadRootKeyFile(keyFile)
	}
	return remotesync.ParseRootKey(key)
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: integrisd serve -destination DIR (-key HEX|-keyfile PATH|-peer-key ID=PATH...) [options]

options:
  -addr HOST:PORT     listen address (default 127.0.0.1:9100)
  -once               serve one connection then exit
  -max-restarts N     restart role set after crash (-1=default 3; 0=off)
  -peer-key ID=PATH   per-peer PSK allow-list entry (repeatable; M2i)
  -strict-launch      release-shaped launch (full chain; fail-closed confine; M2k)

M2a–M4m engineering privilege-separated receive daemon
(eight supervised roles + optional per-peer PSK admission in integrisd-auth;
admit/deny audit events when using -peer-key; -strict-launch for fail-closed
confinement; SCM-only key conferral on a dedicated key channel by default,
including dual-live StartPair, selective RestartOne with exit-channel drain,
FreeBSD allow-root directory FD claim, CapEnter-oriented openat for
index/apply/journal/audit (including journal bootstrap), CapEnter receive-chain
proof, role-stub NEG-CAP-MODE CapEnter probes, StrictLaunch CapEnter
RestartOne (apply, parser-down, auth-primary, M2j dual ExtraPeer auth↔audit,
M2j apply, and M2j parser-down), StrictLaunch CapEnter peer-key Once push and
peer deny/admit, FreeBSD ambient AF_INET residual documentation, FreeBSD
sealed MAC key FD, and Darwin/OpenBSD anon key FD residual documentation).
PSK auth only; not release PKI; not an IC-1 production claim.

See docs/daemon-m2a.md.
`)
}
