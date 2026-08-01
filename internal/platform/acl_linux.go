//go:build linux

package platform

import (
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const (
	aclSupported         = true
	posixACLAccessXattr  = "system.posix_acl_access"
	posixACLXattrVersion = 2
	posixACLUndefinedID  = uint32(0xffffffff)
	posixACLTagUserObj   = uint16(0x01)
	posixACLTagUser      = uint16(0x02)
	posixACLTagGroupObj  = uint16(0x04)
	posixACLTagMask      = uint16(0x10)
	posixACLTagOther     = uint16(0x20)
	posixACLPermRead     = uint16(0x04)
	posixACLPermWrite    = uint16(0x02)
)

func aclRoundTrip(path string) error {
	if path == "" {
		return fmt.Errorf("platform: empty ACL path")
	}
	uid := uint32(os.Getuid())
	blob := encodePOSIXACL([]posixACLEntry{
		{tag: posixACLTagUserObj, perm: posixACLPermRead | posixACLPermWrite, id: posixACLUndefinedID},
		{tag: posixACLTagUser, perm: posixACLPermRead | posixACLPermWrite, id: uid},
		{tag: posixACLTagGroupObj, perm: 0, id: posixACLUndefinedID},
		{tag: posixACLTagMask, perm: posixACLPermRead | posixACLPermWrite, id: posixACLUndefinedID},
		{tag: posixACLTagOther, perm: 0, id: posixACLUndefinedID},
	})
	if err := unix.Setxattr(path, posixACLAccessXattr, blob, 0); err != nil {
		return fmt.Errorf("platform: set posix ACL: %w", err)
	}
	got := make([]byte, len(blob)+16)
	n, err := unix.Getxattr(path, posixACLAccessXattr, got)
	if err != nil {
		return fmt.Errorf("platform: get posix ACL: %w", err)
	}
	if n < 4+8*3 {
		return fmt.Errorf("platform: posix ACL too short: %d", n)
	}
	if binary.LittleEndian.Uint32(got[:4]) != posixACLXattrVersion {
		return fmt.Errorf("platform: unexpected posix ACL version")
	}
	if !aclBlobHasUser(got[:n], uid) {
		return fmt.Errorf("platform: posix ACL missing named user entry")
	}
	return nil
}

func copyACL(dst, src string) error {
	if dst == "" || src == "" {
		return fmt.Errorf("platform: empty ACL copy path")
	}
	size, err := unix.Getxattr(src, posixACLAccessXattr, nil)
	if err != nil {
		if err == unix.ENODATA {
			return nil
		}
		return fmt.Errorf("platform: get posix ACL size: %w", err)
	}
	if size <= 0 {
		return nil
	}
	buf := make([]byte, size)
	n, err := unix.Getxattr(src, posixACLAccessXattr, buf)
	if err != nil {
		if err == unix.ENODATA {
			return nil
		}
		return fmt.Errorf("platform: get posix ACL: %w", err)
	}
	if err := unix.Setxattr(dst, posixACLAccessXattr, buf[:n], 0); err != nil {
		return fmt.Errorf("platform: set posix ACL: %w", err)
	}
	return nil
}

type posixACLEntry struct {
	tag  uint16
	perm uint16
	id   uint32
}

func encodePOSIXACL(entries []posixACLEntry) []byte {
	buf := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(buf[0:4], posixACLXattrVersion)
	off := 4
	for _, e := range entries {
		binary.LittleEndian.PutUint16(buf[off:off+2], e.tag)
		binary.LittleEndian.PutUint16(buf[off+2:off+4], e.perm)
		binary.LittleEndian.PutUint32(buf[off+4:off+8], e.id)
		off += 8
	}
	return buf
}

func aclBlobHasUser(blob []byte, uid uint32) bool {
	if len(blob) < 4 {
		return false
	}
	for off := 4; off+8 <= len(blob); off += 8 {
		tag := binary.LittleEndian.Uint16(blob[off : off+2])
		id := binary.LittleEndian.Uint32(blob[off+4 : off+8])
		if tag == posixACLTagUser && id == uid {
			return true
		}
	}
	return false
}
