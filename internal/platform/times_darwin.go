//go:build darwin

package platform

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

func captureBirth(st *unix.Stat_t, saved *sourceTimes) {
	saved.birth = st.Btim
	saved.hasBirth = true
}

func applyBirth(path string, saved sourceTimes) error {
	if !saved.hasBirth {
		return nil
	}
	attrlist := unix.Attrlist{
		Bitmapcount: unix.ATTR_BIT_MAP_COUNT,
		Commonattr:  unix.ATTR_CMN_CRTIME,
	}
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], uint64(saved.birth.Sec))
	binary.LittleEndian.PutUint64(buf[8:16], uint64(saved.birth.Nsec))
	if err := unix.Setattrlist(path, &attrlist, buf, 0); err != nil {
		return fmt.Errorf("platform: setattrlist crtime: %w", err)
	}
	return nil
}
