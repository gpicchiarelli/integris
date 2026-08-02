package remotesync

import (
	"io"
	"os"

	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/localsync"
)

// msgDestManifest carries a readonly destination index snapshot to apply (M2h).
const msgDestManifest byte = 0xe0

func encodeDestManifest(entries []localsync.Entry) ([]byte, error) {
	b, err := encodeManifest(entries)
	if err != nil {
		return nil, err
	}
	b[0] = msgDestManifest
	return b, nil
}

func decodeDestManifest(p []byte) ([]localsync.Entry, error) {
	if len(p) < 1 || p[0] != msgDestManifest {
		return nil, fail(KindProtocol, "bad dest manifest")
	}
	tmp := append([]byte{msgManifest}, p[1:]...)
	return decodeManifest(tmp)
}

// ServeIndexBridge relays plan↔apply and, on commit, scans the destination
// readonly then confers the dest manifest to apply before forwarding commit.
// Index holds CapReadonlyArchiveRoot only (no staging, no journal, no PSK).
// destDir, when non-nil, is a conferred allow-root directory FD used for
// openat scan (M3d); destination remains the Manifest.Root label.
func ServeIndexBridge(destination string, destDir *os.File, planRW, applyRW io.ReadWriter, planCh, applyCh *ipc.ChannelState, once bool) error {
	if planCh == nil || applyCh == nil {
		return fail(KindInvalidArgument, "nil index channel")
	}
	return ServeIndexBridgeDyn(destination, destDir, planRW, planCh, func() (io.ReadWriter, *ipc.ChannelState) {
		return applyRW, applyCh
	}, once)
}

// ServeIndexBridgeDyn refreshes the apply endpoint per forward (M2s peer-FD rebind).
func ServeIndexBridgeDyn(destination string, destDir *os.File, planRW io.ReadWriter, planCh *ipc.ChannelState, applySide func() (io.ReadWriter, *ipc.ChannelState), once bool) error {
	if planCh == nil || applySide == nil {
		return fail(KindInvalidArgument, "nil index channel")
	}
	if destination == "" {
		return fail(KindInvalidArgument, "index destination required")
	}
	fromPlan := &ipcWire{rw: planRW, ch: planCh}
	for {
		req, err := fromPlan.readRequest()
		if err != nil {
			return err
		}
		if len(req) == 0 {
			_ = fromPlan.respond(mustResult(false, "empty index request"))
			continue
		}
		applyRW, applyCh := applySide()
		if applyRW == nil || applyCh == nil {
			return fail(KindInvalidArgument, "nil apply endpoint")
		}
		toApply := &ipcWire{rw: applyRW, ch: applyCh}
		if req[0] == msgCommit {
			man, err := scanDestination(destination, destDir)
			if err != nil {
				_ = fromPlan.respond(mustResult(false, err.Error()))
				if once {
					return err
				}
				continue
			}
			destMsg, err := encodeDestManifest(man.Entries)
			if err != nil {
				_ = fromPlan.respond(mustResult(false, err.Error()))
				return err
			}
			if _, err := toApply.request(destMsg); err != nil {
				_ = fromPlan.respond(mustResult(false, err.Error()))
				return err
			}
		}
		resp, err := toApply.request(req)
		if err != nil {
			_ = fromPlan.respond(mustResult(false, err.Error()))
			return err
		}
		if err := fromPlan.respond(resp); err != nil {
			return err
		}
		if req[0] == msgCommit {
			if once {
				return nil
			}
		}
	}
}

func scanDestination(destination string, destDir *os.File) (localsync.Manifest, error) {
	if destDir != nil {
		man, err := localsync.ScanAt(destDir, destination)
		if err != nil {
			return localsync.Manifest{}, wrap(KindApply, "index scanat", err)
		}
		return man, nil
	}
	fi, err := os.Lstat(destination)
	if err != nil {
		if os.IsNotExist(err) {
			return localsync.Manifest{Root: destination}, nil
		}
		return localsync.Manifest{}, wrap(KindApply, "index lstat", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return localsync.Manifest{}, fail(KindApply, "index: destination must not be a symbolic link")
	}
	if !fi.IsDir() {
		return localsync.Manifest{}, fail(KindApply, "index: destination must be a directory")
	}
	man, err := localsync.Scan(destination)
	if err != nil {
		return localsync.Manifest{}, wrap(KindApply, "index scan", err)
	}
	return man, nil
}
