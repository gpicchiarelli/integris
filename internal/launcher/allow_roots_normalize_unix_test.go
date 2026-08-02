//go:build unix

package launcher_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
)

func TestStartAllowRootsRefuseRelative(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := launcher.Start(ctx, launcher.Request{
		Executable: "/bin/true", Role: authority.RoleApply, Peer: authority.RoleNet,
		MACKey: bytes.Repeat([]byte{1}, 16), Socket: os.Stdin,
		EngineeringMode: true,
		AllowRoots:      []string{"relative/root"},
	})
	var e *launcher.Error
	if !errors.As(err, &e) || e.Code != "allow_roots" {
		t.Fatalf("got %v", err)
	}
}

func TestAllowRootsSymlinkCanonical(t *testing.T) {
	realDir := t.TempDir()
	parent := t.TempDir()
	link := filepath.Join(parent, "dest-link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatal(err)
	}
	got, err := confine.NormalizeAllowRoots([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %v want [%q]", got, want)
	}
}
