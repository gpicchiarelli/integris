// Command integris is the operator CLI for Integris engineering increments.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/gpicchiarelli/integris/internal/localsync"
	"github.com/gpicchiarelli/integris/internal/remotesync"
)

const (
	exitOK          = 0
	exitFailure     = 1
	exitUsage       = 2
	exitPathUnsafe  = 3
	exitUnsupported = 4
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	switch args[0] {
	case "sync":
		return runSync(args[1:])
	case "serve":
		return runServe(args[1:])
	case "push":
		return runPush(args[1:])
	case "help", "-h", "--help":
		usage()
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "integris: unknown command %q\n", args[0])
		usage()
		return exitUsage
	}
}

func runSync(args []string) int {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	source := fs.String("source", "", "source directory")
	dest := fs.String("destination", "", "destination directory")
	jsonOut := fs.Bool("json", false, "emit structured JSON result")
	planOnly := fs.Bool("plan-only", false, "build plan without applying")
	noJournal := fs.Bool("no-journal", false, "disable durable journal (not crash-safe)")
	journalPath := fs.String("journal", "", "override journal segment path")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if strings.TrimSpace(*source) == "" || strings.TrimSpace(*dest) == "" {
		fmt.Fprintln(os.Stderr, "integris sync: -source and -destination are required")
		return exitUsage
	}

	res, err := localsync.Sync(localsync.Options{
		Source:         *source,
		Destination:    *dest,
		PlanOnly:       *planOnly,
		DisableJournal: *noJournal,
		JournalPath:    *journalPath,
	})

	if *jsonOut {
		b, jerr := res.JSON()
		if jerr != nil {
			fmt.Fprintf(os.Stderr, "integris sync: encode result: %v\n", jerr)
			return exitFailure
		}
		fmt.Println(string(b))
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "integris sync: %v\n", err)
	} else {
		fmt.Printf("outcome=%s planned=%d completed=%d skipped=%d bytes=%d duration_ms=%d durability=%s resumed=%v journal=%s\n",
			res.Outcome, res.PlannedOps, res.CompletedOps, res.SkippedOps, res.BytesTransferred,
			res.Duration.Milliseconds(), res.DurabilityNote, res.Resumed, res.JournalPath)
	}

	if err == nil {
		return exitOK
	}
	switch {
	case localsync.IsKind(err, localsync.KindInvalidArgument):
		return exitUsage
	case localsync.IsKind(err, localsync.KindPathUnsafe):
		return exitPathUnsafe
	case localsync.IsKind(err, localsync.KindUnsupported):
		return exitUnsupported
	default:
		return exitFailure
	}
}

func loadKey(key, keyFile string) ([]byte, error) {
	if strings.TrimSpace(keyFile) != "" {
		return remotesync.LoadRootKeyFile(keyFile)
	}
	return remotesync.ParseRootKey(key)
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", "127.0.0.1:9100", "listen address")
	dest := fs.String("destination", "", "destination directory")
	key := fs.String("key", "", "32-byte root key (hex or raw)")
	keyFile := fs.String("keyfile", "", "path to root key file")
	once := fs.Bool("once", false, "serve a single connection then exit")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if strings.TrimSpace(*dest) == "" {
		fmt.Fprintln(os.Stderr, "integris serve: -destination is required")
		return exitUsage
	}
	root, err := loadKey(*key, *keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integris serve: %v\n", err)
		return exitUsage
	}
	err = remotesync.Serve(remotesync.ServeOptions{
		Addr:        *addr,
		Destination: *dest,
		RootKey:     root,
		Once:        *once,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "integris serve: %v\n", err)
		return exitFailure
	}
	return exitOK
}

func runPush(args []string) int {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", "", "remote serve address host:port")
	source := fs.String("source", "", "source directory")
	key := fs.String("key", "", "32-byte root key (hex or raw)")
	keyFile := fs.String("keyfile", "", "path to root key file")
	peer := fs.String("peer", "", "peer id for keyring admission (M2i; optional)")
	chunkSize := fs.Int("chunk-size", 0, "file chunk size in bytes (0 = default 256KiB)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if strings.TrimSpace(*addr) == "" || strings.TrimSpace(*source) == "" {
		fmt.Fprintln(os.Stderr, "integris push: -addr and -source are required")
		return exitUsage
	}
	root, err := loadKey(*key, *keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integris push: %v\n", err)
		return exitUsage
	}
	if pid := strings.TrimSpace(*peer); pid != "" {
		if err := remotesync.ValidatePeerID(pid); err != nil {
			fmt.Fprintf(os.Stderr, "integris push: %v\n", err)
			return exitUsage
		}
	}
	res, err := remotesync.Push(remotesync.PushOptions{
		Addr:      *addr,
		Source:    *source,
		RootKey:   root,
		PeerID:    strings.TrimSpace(*peer),
		ChunkSize: *chunkSize,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "integris push: %v\n", err)
		return exitFailure
	}
	fmt.Printf("outcome=%s files=%d dirs=%d bytes=%d duration_ms=%d\n",
		res.Outcome, res.FilesSent, res.DirsSent, res.BytesSent, res.Duration.Milliseconds())
	return exitOK
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: integris <command> [flags]

commands:
  sync     unidirectional local directory sync (source → destination)
  serve    accept authenticated remote push into a destination
  push     push a local directory to a remote serve

integris sync -source DIR -destination DIR [-json] [-plan-only] [-no-journal] [-journal PATH]
integris serve -destination DIR -key HEX|-keyfile PATH [-addr HOST:PORT] [-once]
integris push -source DIR -addr HOST:PORT -key HEX|-keyfile PATH [-peer ID] [-chunk-size N]

Local journal (sync/serve apply): destination/.integris/local.jrn
Remote recv partials: destination/.integris/recv-partial/
Remote auth: shared 32-byte PSK, or per-peer PSK with -peer against a keyring serve (M2i).

Exit codes:
  0  success
  1  sync/runtime failure
  2  invalid usage or arguments
  3  unsafe path
  4  unsupported filesystem object
`)
}
