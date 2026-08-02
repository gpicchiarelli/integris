package remotesync

import (
	"net"
	"time"

	"github.com/gpicchiarelli/integris/internal/localsync"
)

// ServeOptions configures an authenticated receive+apply listener.
type ServeOptions struct {
	Addr        string
	Destination string
	RootKey     []byte
	// Once, when true, serves a single connection then returns.
	Once bool
}

// Serve listens for push clients, stages content, and applies via localsync.
func Serve(opts ServeOptions) error {
	if opts.Destination == "" {
		return fail(KindInvalidArgument, "destination required")
	}
	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return wrap(KindTransport, "listen", err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return wrap(KindTransport, "accept", err)
		}
		err = HandleConn(conn, opts.RootKey, opts.Destination)
		_ = conn.Close()
		if err != nil {
			return err
		}
		if opts.Once {
			return nil
		}
	}
}

// HandleConn serves one authenticated push into destination (monolithic process).
func HandleConn(conn net.Conn, rootKey []byte, destination string) error {
	store, err := openLocalStore(destination)
	if err != nil {
		return err
	}
	defer store.close()
	return handleConnWithStore(conn, rootKey, store)
}

func handleConnWithStore(conn net.Conn, rootKey []byte, store *localStore) error {
	sess, err := AcceptHandshake(conn, rootKey)
	if err != nil {
		return err
	}
	defer sess.Close()
	return serveSession(sess, store)
}

func serveSession(sess *Session, store *localStore) error {
	raw, err := sess.recvData()
	if err != nil {
		return err
	}
	entries, err := decodeManifest(raw)
	if err != nil {
		return err
	}
	if err := store.prepareDirs(entries); err != nil {
		return respondErr(sess, err)
	}
	if err := sess.sendData(encodeManifestOK()); err != nil {
		return err
	}

	filesExpected := 0
	for _, e := range entries {
		if e.Type == localsync.EntryFile {
			filesExpected++
		}
	}
	for i := 0; i < filesExpected; i++ {
		raw, err := sess.recvData()
		if err != nil {
			store.persistActive()
			return err
		}
		if len(raw) > 0 && raw[0] == msgFile {
			fw, err := decodeFile(raw)
			if err != nil {
				return respondErr(sess, err)
			}
			if err := store.stageLegacy(fw); err != nil {
				return respondErr(sess, err)
			}
			continue
		}
		begin, err := decodeFileBegin(raw)
		if err != nil {
			return respondErr(sess, err)
		}
		if err := recvFileChunked(sess, store, begin); err != nil {
			return respondErr(sess, err)
		}
	}

	raw, err = sess.recvData()
	if err != nil {
		return err
	}
	if len(raw) != 1 || raw[0] != msgCommit {
		return fail(KindProtocol, "expected commit")
	}
	if err := store.commit(nil); err != nil {
		return respondErr(sess, err)
	}
	ok, err := encodeResult(true, "ok")
	if err != nil {
		return err
	}
	return sess.sendData(ok)
}

func respondErr(sess *Session, err error) error {
	msg := err.Error()
	if len(msg) > 1024 {
		msg = msg[:1024]
	}
	raw, encErr := encodeResult(false, msg)
	if encErr == nil {
		_ = sess.sendData(raw)
	}
	return err
}

// ListenAndServeOnce is a test helper with a short accept deadline.
func ListenAndServeOnce(addr string, rootKey []byte, destination string, ready chan<- string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return wrap(KindTransport, "listen", err)
	}
	defer ln.Close()
	if ready != nil {
		ready <- ln.Addr().String()
	}
	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(60 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		return wrap(KindTransport, "accept", err)
	}
	defer conn.Close()
	return HandleConn(conn, rootKey, destination)
}
