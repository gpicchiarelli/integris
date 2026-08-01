package path

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func ruleOf(err error) RuleID {
	var e *Error
	if errors.As(err, &e) {
		return e.Rule
	}
	return ""
}

func TestValidateAcceptASCII(t *testing.T) {
	cases := [][][]byte{
		{b("a")},
		{b("file.txt")},
		{b("dir"), b("file")},
		{bytes.Repeat([]byte{'x'}, 1)},
		{bytes.Repeat([]byte{'x'}, MaxComponentBytes)},
	}
	for _, c := range cases {
		if err := ValidateComponentsDefault(c); err != nil {
			t.Fatalf("accept %q: %v", c, err)
		}
	}
}

func TestValidateRejectTable(t *testing.T) {
	win := Profile{WindowsReserved: true}
	long := bytes.Repeat([]byte{'a'}, MaxComponentBytes+1)
	overlongUTF8 := []byte{0xC0, 0x80}   // overlong NUL
	nfdEAcute := []byte{'e', 0xCC, 0x81} // e + combining acute (NFD)
	nfcEAcute := []byte{0xC3, 0xA9}      // U+00E9 NFC

	tests := []struct {
		name    string
		comps   [][]byte
		profile Profile
		rule    RuleID
	}{
		{"empty path", nil, DefaultProfile, RuleEmpty},
		{"empty path slice", [][]byte{}, DefaultProfile, RuleEmpty},
		{"empty component", comps(""), DefaultProfile, RuleEmpty},
		{"dot", comps("."), DefaultProfile, RuleDot},
		{"dotdot", comps(".."), DefaultProfile, RuleDotDot},
		{"nul", [][]byte{{'a', 0, 'b'}}, DefaultProfile, RuleNUL},
		{"slash", comps("a/b"), DefaultProfile, RuleSep},
		{"backslash", comps(`a\b`), DefaultProfile, RuleSep},
		{"abs drive", comps("C:"), DefaultProfile, RuleAbs},
		{"abs drive path", comps("C:foo"), DefaultProfile, RuleAbs},
		{"overlong utf8", [][]byte{overlongUTF8}, DefaultProfile, RuleUTF8},
		{"truncated utf8", [][]byte{{0xE2, 0x82}}, DefaultProfile, RuleUTF8},
		{"surrogate utf8", [][]byte{{0xED, 0xA0, 0x80}}, DefaultProfile, RuleUTF8},
		{"nfd twin", [][]byte{nfdEAcute}, DefaultProfile, RuleNorm},
		{"tab", [][]byte{{'a', '\t', 'b'}}, DefaultProfile, RuleCtrl},
		{"del", [][]byte{{'a', 0x7F}}, DefaultProfile, RuleCtrl},
		{"c0", [][]byte{{'a', 0x01}}, DefaultProfile, RuleCtrl},
		{"len 256", [][]byte{long}, DefaultProfile, RuleLen},
		{"win CON", comps("CON"), win, RuleWinRes},
		{"win con.ex", comps("con.txt"), win, RuleWinRes},
		{"win COM1", comps("COM1"), win, RuleWinRes},
		{"win LPT9", comps("LPT9"), win, RuleWinRes},
		{"win trail dot", comps("foo."), win, RuleWinRes},
		{"win trail space", comps("foo "), win, RuleWinRes},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateComponents(tc.comps, tc.profile)
			if err == nil {
				t.Fatalf("expected %s, got nil", tc.rule)
			}
			if ruleOf(err) != tc.rule {
				t.Fatalf("rule=%s want %s (err=%v)", ruleOf(err), tc.rule, err)
			}
		})
	}

	// NFC twin must be accepted.
	if err := ValidateComponentsDefault([][]byte{nfcEAcute}); err != nil {
		t.Fatalf("NFC é rejected: %v", err)
	}
}

func TestValidateCountAndBudget(t *testing.T) {
	tooMany := make([][]byte, MaxComponents+1)
	for i := range tooMany {
		tooMany[i] = []byte{'a'}
	}
	if ruleOf(ValidateComponentsDefault(tooMany)) != RuleCount {
		t.Fatalf("want G-COUNT")
	}

	// Budget: sum of component bytes > 4096 (separators not counted).
	n := (MaxPathBytes / MaxComponentBytes) + 2
	comps := make([][]byte, n)
	for i := range comps {
		comps[i] = bytes.Repeat([]byte{'b'}, MaxComponentBytes)
	}
	if ruleOf(ValidateComponentsDefault(comps)) != RuleBudget {
		t.Fatalf("want G-BUDGET, got %s", ruleOf(ValidateComponentsDefault(comps)))
	}
}

func TestValidateBoundaryLengths(t *testing.T) {
	if err := ValidateComponentsDefault([][]byte{bytes.Repeat([]byte{'x'}, 0)}); ruleOf(err) != RuleEmpty {
		t.Fatalf("len 0: %v", err)
	}
	if err := ValidateComponentsDefault([][]byte{bytes.Repeat([]byte{'x'}, 1)}); err != nil {
		t.Fatalf("len 1: %v", err)
	}
	if err := ValidateComponentsDefault([][]byte{bytes.Repeat([]byte{'x'}, 255)}); err != nil {
		t.Fatalf("len 255: %v", err)
	}
	if ruleOf(ValidateComponentsDefault([][]byte{bytes.Repeat([]byte{'x'}, 256)})) != RuleLen {
		t.Fatalf("len 256")
	}
}

func TestValidateJoinedAbsolute(t *testing.T) {
	for _, s := range []string{"/a", `\a`, "C:/a", "C:a", ""} {
		if _, err := ValidateJoined(s, DefaultProfile); err == nil {
			t.Fatalf("expected reject for %q", s)
		}
	}
	got, err := ValidateJoined("a/b", DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(got, comps("a", "b")) {
		t.Fatalf("got %q", got)
	}
}

func TestWindowsReservedOffByDefault(t *testing.T) {
	if err := ValidateComponentsDefault(comps("CON")); err != nil {
		t.Fatalf("CON should be allowed without Windows profile: %v", err)
	}
}

func TestIsNFCHangulAndAngstrom(t *testing.T) {
	// U+212B (Ångström) is QC=No; NFC is U+00C5.
	angstrom := []byte{0xE2, 0x84, 0xAB}
	if isNFC(angstrom) {
		t.Fatal("U+212B should not be NFC")
	}
	aRing := []byte{0xC3, 0x85} // U+00C5
	if !utf8.Valid(aRing) || !isNFC(aRing) {
		t.Fatal("U+00C5 should be NFC")
	}
	// Precomposed Hangul syllable 가 U+AC00 is NFC.
	ga := []byte{0xEA, 0xB0, 0x80}
	if !isNFC(ga) {
		t.Fatal("Hangul syllable should be NFC")
	}
	// Decomposed Hangul L+V for 가: U+1100 U+1161
	decomposed := []byte{0xE1, 0x84, 0x80, 0xE1, 0x85, 0xA1}
	if isNFC(decomposed) {
		t.Fatal("decomposed Hangul should not be NFC")
	}
}

func TestRejectDoesNotPanic(t *testing.T) {
	nasty := [][]byte{
		nil,
		{},
		{0xff},
		bytes.Repeat([]byte{0xff}, 300),
		[]byte(strings.Repeat("\x00", 10)),
	}
	for _, c := range nasty {
		_ = ValidateComponents([][]byte{c}, DefaultProfile)
		_ = ValidateComponents(nil, DefaultProfile)
	}
}
