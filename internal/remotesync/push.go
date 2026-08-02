package remotesync

import (
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/gpicchiarelli/integris/internal/localsync"
)

// PushHooks are optional test/fault points.
type PushHooks struct {
	// AfterChunk is called after each successful chunk send with the next offset.
	AfterChunk func(rel string, nextOffset uint64) error
}

// PushOptions configures an authenticated unidirectional push.
type PushOptions struct {
	Addr      string
	Source    string
	RootKey   []byte
	PeerID    string // optional; required when server uses a peer keyring (M2i)
	ChunkSize int    // 0 = DefaultChunkSize
	Hooks     *PushHooks
	Dial      func(network, address string) (net.Conn, error) // optional; default net.Dial
}

// PushResult is the structured outcome of a push.
type PushResult struct {
	Outcome     string
	FilesSent   int
	DirsSent    int
	BytesSent   int64
	Duration    time.Duration
	RemoteError string
}

// Push dials addr, handshakes, and pushes source tree to the remote serve.
func Push(opts PushOptions) (PushResult, error) {
	start := time.Now()
	var res PushResult
	res.Outcome = "failed"

	srcAbs, err := filepath.Abs(opts.Source)
	if err != nil {
		return res, wrap(KindInvalidArgument, "source", err)
	}
	fi, err := os.Lstat(srcAbs)
	if err != nil {
		return res, wrap(KindInvalidArgument, "source", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return res, fail(KindInvalidArgument, "source must be a real directory")
	}

	man, err := localsync.Scan(srcAbs)
	if err != nil {
		return res, wrap(KindApply, "scan", err)
	}
	for _, e := range man.Entries {
		if e.Type == localsync.EntryDir {
			res.DirsSent++
		}
	}

	dial := opts.Dial
	if dial == nil {
		dial = net.Dial
	}
	conn, err := dial("tcp", opts.Addr)
	if err != nil {
		return res, wrap(KindTransport, "dial", err)
	}
	sess, err := DialHandshake(conn, opts.RootKey, opts.PeerID)
	if err != nil {
		_ = conn.Close()
		return res, err
	}
	defer sess.Close()

	payload, err := encodeManifest(man.Entries)
	if err != nil {
		return res, err
	}
	if err := sess.sendData(payload); err != nil {
		return res, err
	}
	ack, err := sess.recvData()
	if err != nil {
		return res, err
	}
	if len(ack) != 1 || ack[0] != msgManifestOK {
		return res, fail(KindProtocol, "manifest not acknowledged")
	}

	for _, e := range man.Entries {
		if e.Type != localsync.EntryFile {
			continue
		}
		n, err := sendFileChunked(sess, srcAbs, e, opts.ChunkSize, opts.Hooks)
		if err != nil {
			res.BytesSent += n
			return res, err
		}
		res.FilesSent++
		res.BytesSent += n
	}

	if err := sess.sendData(encodeCommit()); err != nil {
		return res, err
	}
	raw, err := sess.recvData()
	if err != nil {
		return res, err
	}
	ok, msg, err := decodeResult(raw)
	if err != nil {
		return res, err
	}
	res.Duration = time.Since(start)
	if !ok {
		res.RemoteError = msg
		return res, failf(KindApply, "remote apply failed: %s", msg)
	}
	res.Outcome = "success"
	return res, nil
}
