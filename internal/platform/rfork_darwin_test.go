//go:build darwin

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyResourceForkRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := []byte("rfork-v1")
	if err := os.WriteFile(namedForkPath(src), want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CopyResourceFork(dst, src); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(namedForkPath(dst))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCopyResourceForkNoOpWithoutFork(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CopyResourceFork(dst, src); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(namedForkPath(dst)); !os.IsNotExist(err) {
		t.Fatalf("expected no dst fork, err=%v", err)
	}
}

func TestCopyFileExclusivePreservesResourceFork(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("clone-rfork"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := []byte("keep-rfork")
	if err := os.WriteFile(namedForkPath(src), want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFileExclusive(dst, src); err != nil {
		t.Fatal(err)
	}
	gotPayload, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotPayload) != "clone-rfork" {
		t.Fatalf("payload=%q", gotPayload)
	}
	got, err := os.ReadFile(namedForkPath(dst))
	if err != nil {
		t.Fatalf("dst rfork missing: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}
}
