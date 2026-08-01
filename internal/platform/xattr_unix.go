//go:build unix

package platform

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func copyXattr(dst, src string) error {
	if dst == "" || src == "" {
		return fmt.Errorf("platform: empty xattr path")
	}
	names, err := listXattrNames(src)
	if err != nil {
		return fmt.Errorf("platform: listxattr: %w", err)
	}
	for _, name := range names {
		if skipXattrName(name) {
			continue
		}
		val, err := getXattr(src, name)
		if err != nil {
			return fmt.Errorf("platform: getxattr %q: %w", name, err)
		}
		if err := unix.Setxattr(dst, name, val, 0); err != nil {
			return fmt.Errorf("platform: setxattr %q: %w", name, err)
		}
	}
	return nil
}

func skipXattrName(name string) bool {
	// Extended ACLs are transferred by CopyACL; do not race via xattr APIs.
	return name == "com.apple.system.Security"
}

func listXattrNames(path string) ([]string, error) {
	sz, err := unix.Listxattr(path, nil)
	if err != nil {
		return nil, err
	}
	if sz == 0 {
		return nil, nil
	}
	buf := make([]byte, sz)
	n, err := unix.Listxattr(path, buf)
	if err != nil {
		return nil, err
	}
	var names []string
	start := 0
	for i := 0; i < n; i++ {
		if buf[i] != 0 {
			continue
		}
		if i > start {
			names = append(names, string(buf[start:i]))
		}
		start = i + 1
	}
	return names, nil
}

func getXattr(path, name string) ([]byte, error) {
	sz, err := unix.Getxattr(path, name, nil)
	if err != nil {
		return nil, err
	}
	if sz == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, sz)
	n, err := unix.Getxattr(path, name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
