//go:build unix

package remotesync

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/localsync"
	"golang.org/x/sys/unix"
)

func TestOpenLocalStoreAtStaging(t *testing.T) {
	dest := t.TempDir()
	fd, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(fd), dest)
	defer dir.Close()

	store, err := openLocalStoreAt(dest, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if !store.useAt() {
		t.Fatal("expected openat staging")
	}
	if _, err := os.Stat(filepath.Join(dest, ".integris", "recv-stage")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, ".integris", "recv-partial")); err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello-m3e-stageat")
	dig := digestOf(payload)
	begin := fileBegin{Rel: "d/a.txt", Mode: 0o644, Digest: dig, Size: uint64(len(payload))}

	off, err := store.beginFile(begin)
	if err != nil {
		t.Fatal(err)
	}
	if off != 0 {
		t.Fatalf("offset %d", off)
	}
	if err := store.writeChunk(0, payload); err != nil {
		t.Fatal(err)
	}
	if err := store.endFile(begin.Rel, dig); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(dest, ".integris", "recv-stage", "d", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q", got)
	}
}

func TestPrepareDirsAt(t *testing.T) {
	dest := t.TempDir()
	fd, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(fd), dest)
	defer dir.Close()
	store, err := openLocalStoreAt(dest, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if err := store.prepareDirs([]localsync.Entry{
		{Rel: "x/y", Type: localsync.EntryDir, Mode: 0o755},
	}); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(dest, ".integris", "recv-stage", "x", "y")); err != nil || !st.IsDir() {
		t.Fatalf("dir: %v %v", st, err)
	}
}

func TestStageLegacyAt(t *testing.T) {
	dest := t.TempDir()
	fd, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(fd), dest)
	defer dir.Close()
	store, err := openLocalStoreAt(dest, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	payload := []byte("legacy-m3e")
	dig := digestOf(payload)
	if err := store.stageLegacy(fileWire{
		Rel: "n/b.txt", Mode: 0o644, Digest: dig, Data: payload,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, ".integris", "recv-stage", "n", "b.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q", got)
	}
}

func digestOf(b []byte) codec.Digest {
	sum := sha256.Sum256(b)
	var d codec.Digest
	copy(d[:], sum[:])
	return d
}
