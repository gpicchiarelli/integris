// Package path implements Integris protocol path grammar validation and
// descriptor-relative resolution (IP-S-0001 / docs/specifications/path-resolution.md).
//
// String validation does not authorize access. Resolution requires an already
// open root descriptor and never follows symbolic links.
package path

// Format/profile version 1 limits (IP-S-0001).
const (
	MaxComponentBytes = 255
	MaxComponents     = 1024
	MaxPathBytes      = 4096
)

// RuleID is a stable grammar / resolution reject identifier.
type RuleID string

// Grammar and resolution rule IDs from IP-S-0001.
const (
	RuleEmpty  RuleID = "G-EMPTY"
	RuleDot    RuleID = "G-DOT"
	RuleDotDot RuleID = "G-DOTDOT"
	RuleNUL    RuleID = "G-NUL"
	RuleSep    RuleID = "G-SEP"
	RuleAbs    RuleID = "G-ABS"
	RuleUTF8   RuleID = "G-UTF8"
	RuleNorm   RuleID = "G-NORM"
	RuleCtrl   RuleID = "G-CTRL"
	RuleLen    RuleID = "G-LEN"
	RuleCount  RuleID = "G-COUNT"
	RuleBudget RuleID = "G-BUDGET"
	RuleWinRes RuleID = "G-WINRES"
	RuleUnk    RuleID = "G-UNK"
	RuleLink   RuleID = "G-LINK"
	RuleType   RuleID = "G-TYPE"
	RuleIdent  RuleID = "G-IDENT"
	RuleVolume RuleID = "G-VOLUME"
	RuleOpen   RuleID = "G-OPEN"
	RulePolicy RuleID = "G-POLICY"
)

// Profile selects optional grammar extensions. Protocol limits are always applied.
type Profile struct {
	// WindowsReserved enables G-WINRES (DOS device names, trailing dot/space).
	WindowsReserved bool
}

// DefaultProfile is the M1 default: portable grammar without Windows-hostile rules.
var DefaultProfile = Profile{}

// Error is a typed path grammar or resolution failure. It never wraps panics;
// expected input and filesystem faults surface as Error values.
type Error struct {
	Rule    RuleID
	Index   int // component index, or -1 when not component-specific
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return string(e.Rule) + ": " + e.Message
	}
	return string(e.Rule)
}

func reject(rule RuleID, index int, msg string) error {
	return &Error{Rule: rule, Index: index, Message: msg}
}
