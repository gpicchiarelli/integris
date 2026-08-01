//go:build darwin && cgo

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyFileExclusivePreservesACL(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("clone-acl"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ACLRoundTrip(src); err != nil {
		t.Fatal(err)
	}
	ok, err := hasExtendedACL(src)
	if err != nil || !ok {
		t.Fatalf("src ACL present=%v err=%v", ok, err)
	}
	if err := copyFileExclusive(dst, src); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "clone-acl" {
		t.Fatalf("payload=%q", got)
	}
	ok, err = hasExtendedACL(dst)
	if err != nil || !ok {
		t.Fatalf("dst ACL present=%v err=%v (degraded copy must preserve ACL)", ok, err)
	}
}

func TestCopyACLNoOpWithoutSourceACL(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CopyACL(dst, src); err != nil {
		t.Fatal(err)
	}
	ok, err := hasExtendedACL(dst)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("CopyACL must not invent an ACL when src has none")
	}
}
