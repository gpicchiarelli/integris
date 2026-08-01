package path

import (
	"unicode/utf8"
)

// ValidateComponents checks a protocol path component sequence against the
// name grammar for profile. On success it returns nil. On failure it returns
// *Error with a stable RuleID. No filesystem access is performed.
func ValidateComponents(components [][]byte, profile Profile) error {
	if len(components) == 0 {
		return reject(RuleEmpty, -1, "path requires at least one component")
	}
	if len(components) > MaxComponents {
		return reject(RuleCount, -1, "component count exceeds MaxComponents")
	}
	budget := 0
	for i, c := range components {
		if err := validateComponent(c, i, profile); err != nil {
			return err
		}
		budget += len(c)
		if budget > MaxPathBytes {
			return reject(RuleBudget, i, "sum of component bytes exceeds MaxPathBytes")
		}
	}
	return nil
}

// ValidateComponentsDefault calls ValidateComponents with DefaultProfile.
func ValidateComponentsDefault(components [][]byte) error {
	return ValidateComponents(components, DefaultProfile)
}

func validateComponent(c []byte, index int, profile Profile) error {
	if len(c) == 0 {
		return reject(RuleEmpty, index, "empty component")
	}
	if len(c) > MaxComponentBytes {
		return reject(RuleLen, index, "component exceeds MaxComponentBytes")
	}

	// Exact . / .. before other scans (still byte-identical checks).
	if len(c) == 1 && c[0] == '.' {
		return reject(RuleDot, index, "component is .")
	}
	if len(c) == 2 && c[0] == '.' && c[1] == '.' {
		return reject(RuleDotDot, index, "component is ..")
	}

	for _, b := range c {
		if b == 0 {
			return reject(RuleNUL, index, "component contains NUL")
		}
		if b == '/' || b == '\\' {
			return reject(RuleSep, index, "component contains separator")
		}
	}

	if isAbsoluteComponent(c) {
		return reject(RuleAbs, index, "component is an absolute path form")
	}

	if !utf8.Valid(c) {
		return reject(RuleUTF8, index, "component is not well-formed UTF-8")
	}

	// C0 controls (including TAB) and DEL. NUL already rejected as G-NUL.
	for _, b := range c {
		if b < 0x20 || b == 0x7F {
			return reject(RuleCtrl, index, "component contains control character")
		}
	}

	if !isNFC(c) {
		return reject(RuleNorm, index, "component is not Unicode NFC")
	}

	if profile.WindowsReserved && isWindowsReserved(c) {
		return reject(RuleWinRes, index, "component matches Windows reserved name")
	}

	return nil
}

// isAbsoluteComponent reports platform absolute indicators offered as a single
// component (drive forms without separators). Leading '/' and '\\' are already
// G-SEP. Joined absolute strings are rejected by ValidateJoined.
func isAbsoluteComponent(c []byte) bool {
	// Drive form: "C:" or "C:something" without separators (separators already rejected).
	if len(c) >= 2 && isASCIILetter(c[0]) && c[1] == ':' {
		return true
	}
	return false
}

// ValidateJoined rejects a slash-joined path string before splitting. Absolute
// forms and empty input fail closed. Successful parse returns validated components.
func ValidateJoined(joined string, profile Profile) ([][]byte, error) {
	if joined == "" {
		return nil, reject(RuleEmpty, -1, "empty path string")
	}
	if isAbsoluteJoined(joined) {
		return nil, reject(RuleAbs, -1, "absolute path string")
	}
	// Split on '/' only; '\' inside a segment is rejected by G-SEP.
	parts := splitSlash(joined)
	comps := make([][]byte, len(parts))
	for i, p := range parts {
		comps[i] = []byte(p)
	}
	if err := ValidateComponents(comps, profile); err != nil {
		return nil, err
	}
	return comps, nil
}

func isAbsoluteJoined(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '/' || s[0] == '\\' {
		return true
	}
	// UNC or drive-absolute: "C:\" or "C:/" or "C:foo" as joined offering.
	if len(s) >= 2 && isASCIILetter(s[0]) && s[1] == ':' {
		return true
	}
	return false
}

func splitSlash(s string) []string {
	if s == "" {
		return nil
	}
	n := 1
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			n++
		}
	}
	out := make([]string, 0, n)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isWindowsReserved(c []byte) bool {
	// Trailing dot or space.
	if last := c[len(c)-1]; last == '.' || last == ' ' {
		return true
	}
	// Strip one trailing extension for device-name match: NAME or NAME.ext
	base := c
	for i := 0; i < len(c); i++ {
		if c[i] == '.' {
			base = c[:i]
			break
		}
	}
	if len(base) == 0 || len(base) > 4 {
		return false
	}
	var buf [4]byte
	for i := 0; i < len(base); i++ {
		b := base[i]
		if b >= 'a' && b <= 'z' {
			b -= 'a' - 'A'
		}
		buf[i] = b
	}
	s := string(buf[:len(base)])
	switch s {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(s) == 4 {
		switch s[:3] {
		case "COM", "LPT":
			d := s[3]
			if d >= '1' && d <= '9' {
				return true
			}
		}
	}
	return false
}
