package path

import (
	"sort"
	"unicode/utf8"
)

// Hangul composition constants (Unicode Standard, §3.12).
const (
	hangulSBase  = 0xAC00
	hangulLBase  = 0x1100
	hangulVBase  = 0x1161
	hangulTBase  = 0x11A7
	hangulLCount = 19
	hangulVCount = 21
	hangulTCount = 28
	hangulSCount = hangulLCount * hangulVCount * hangulTCount // 11172
)

type nfcMark struct {
	r  rune
	cc uint8
}

// isNFC reports whether b is well-formed UTF-8 already in Unicode NFC.
// Caller must ensure utf8.Valid(b); invalid UTF-8 returns false.
//
// Implements UAX #15 NFC quick check with pairwise composition detection for
// MAYBE sequences (stdlib-only; tables generated from Unicode via x/text).
func isNFC(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	var intervening []nfcMark
	lastStarter := rune(-1)
	haveStarter := false
	lastCC := uint8(0)

	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		i += size
		if r == utf8.RuneError && size == 1 {
			return false
		}
		if runeInSorted(nfcQCNo, r) {
			return false
		}
		cc := nfcCCC[r] // 0 if absent
		if lastCC > cc && cc != 0 {
			return false
		}

		if haveStarter {
			if _, ok := composePair(lastStarter, r); ok {
				if !isBlocked(intervening, cc) {
					// A composition would apply → not NFC.
					return false
				}
			}
		}

		if cc == 0 {
			lastStarter = r
			haveStarter = true
			intervening = intervening[:0]
		} else if haveStarter {
			intervening = append(intervening, nfcMark{r: r, cc: cc})
		}
		lastCC = cc
	}
	return true
}

func isBlocked(intervening []nfcMark, cc uint8) bool {
	for _, m := range intervening {
		if m.cc == 0 || m.cc >= cc {
			return true
		}
	}
	return false
}

func composePair(a, b rune) (rune, bool) {
	// Hangul L+V and LV+T.
	if comp, ok := composeHangul(a, b); ok {
		return comp, true
	}
	key := uint64(a)<<32 | uint64(uint32(b))
	comp, ok := nfcCompose[key]
	return comp, ok
}

func composeHangul(a, b rune) (rune, bool) {
	// L + V → LV
	if a >= hangulLBase && a < hangulLBase+hangulLCount {
		if b >= hangulVBase && b < hangulVBase+hangulVCount {
			l := int(a - hangulLBase)
			v := int(b - hangulVBase)
			return rune(hangulSBase + (l*hangulVCount+v)*hangulTCount), true
		}
	}
	// LV + T → LVT
	if a >= hangulSBase && a < hangulSBase+hangulSCount {
		if (a-hangulSBase)%hangulTCount == 0 { // LV syllable (no T)
			if b > hangulTBase && b < hangulTBase+hangulTCount {
				return a + (b - hangulTBase), true
			}
		}
	}
	return 0, false
}

func runeInSorted(list []rune, r rune) bool {
	i := sort.Search(len(list), func(i int) bool { return list[i] >= r })
	return i < len(list) && list[i] == r
}
