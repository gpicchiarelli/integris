//go:build unix

package path_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/path"
)

func TestOSResolveFile(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "a")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(sub, "b.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	root, ident, err := path.OpenOSRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	chain, err := path.Resolve(context.Background(), root, [][]byte{[]byte("a"), []byte("b.txt")}, path.ResolveOpts{
		Root:        ident,
		ExpectFinal: path.TypeFile,
	}, path.DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	info, err := chain.Files[1].Info()
	if err != nil || info.Type != path.TypeFile {
		t.Fatalf("info=%v err=%v", info, err)
	}
	if info.Volume != ident.Volume {
		t.Fatalf("volume mismatch %v vs %v", info.Volume, ident.Volume)
	}
}

func TestOSResolveRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real")
	if err := os.WriteFile(realFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink("real", link); err != nil {
		t.Fatal(err)
	}

	root, ident, err := path.OpenOSRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	_, err = path.Resolve(context.Background(), root, [][]byte{[]byte("link")}, path.ResolveOpts{
		Root: ident,
	}, path.DefaultProfile)
	var pe *path.Error
	if !errors.As(err, &pe) {
		t.Fatalf("got %v", err)
	}
	if pe.Rule != path.RuleLink && pe.Rule != path.RuleOpen {
		t.Fatalf("got rule %s", pe.Rule)
	}
}

func TestOSResolveRejectsDotDotGrammar(t *testing.T) {
	dir := t.TempDir()
	root, ident, err := path.OpenOSRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, err = path.Resolve(context.Background(), root, [][]byte{[]byte("..")}, path.ResolveOpts{
		Root: ident,
	}, path.DefaultProfile)
	var pe *path.Error
	if !errors.As(err, &pe) || pe.Rule != path.RuleDotDot {
		t.Fatalf("got %v", err)
	}
}
