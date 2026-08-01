package protocol

import (
	"fmt"

	"github.com/gpicchiarelli/integris/internal/session"
)

const (
	maxNegotiateVersions = 8
	maxNegotiateSuites   = 8
	maxSuiteIDLen        = 96
)

// EncodeNegotiateOfferBody packs versions and crypto-suite IDs for
// TypeNegotiateOffer (IP-P-0001 / IP-C-0002):
//
//	u8 n_vers || vers… || u8 n_suites || repeated (u8 len || suite_id)
func EncodeNegotiateOfferBody(vers []session.Version, suites []string) ([]byte, error) {
	if len(vers) == 0 || len(vers) > maxNegotiateVersions {
		return nil, fail("negotiate", fmt.Sprintf("version count %d out of range", len(vers)))
	}
	if len(suites) > maxNegotiateSuites {
		return nil, fail("negotiate", fmt.Sprintf("suite count %d exceeds max", len(suites)))
	}
	size := 1 + len(vers) + 1
	for _, s := range suites {
		if s == "" {
			return nil, fail("negotiate", "empty suite id")
		}
		if len(s) > maxSuiteIDLen {
			return nil, fail("negotiate", "suite id too long")
		}
		size += 1 + len(s)
	}
	out := make([]byte, 0, size)
	out = append(out, byte(len(vers)))
	for _, v := range vers {
		out = append(out, byte(v))
	}
	out = append(out, byte(len(suites)))
	for _, s := range suites {
		out = append(out, byte(len(s)))
		out = append(out, s...)
	}
	return out, nil
}

// ParseNegotiateOfferBody decodes EncodeNegotiateOfferBody output.
func ParseNegotiateOfferBody(body []byte) (vers []session.Version, suites []string, err error) {
	if len(body) < 2 {
		return nil, nil, fail("negotiate", "offer body too short")
	}
	nV := int(body[0])
	if nV == 0 || nV > maxNegotiateVersions {
		return nil, nil, fail("negotiate", "bad version count")
	}
	if len(body) < 1+nV+1 {
		return nil, nil, fail("negotiate", "truncated versions")
	}
	vers = make([]session.Version, nV)
	for i := 0; i < nV; i++ {
		vers[i] = session.Version(body[1+i])
	}
	off := 1 + nV
	nS := int(body[off])
	off++
	if nS > maxNegotiateSuites {
		return nil, nil, fail("negotiate", "bad suite count")
	}
	suites = make([]string, 0, nS)
	for i := 0; i < nS; i++ {
		if off >= len(body) {
			return nil, nil, fail("negotiate", "truncated suite length")
		}
		n := int(body[off])
		off++
		if n == 0 || n > maxSuiteIDLen {
			return nil, nil, fail("negotiate", "bad suite id length")
		}
		if off+n > len(body) {
			return nil, nil, fail("negotiate", "truncated suite id")
		}
		suites = append(suites, string(body[off:off+n]))
		off += n
	}
	if off != len(body) {
		return nil, nil, fail("negotiate", "trailing offer bytes")
	}
	return vers, suites, nil
}

// EncodeNegotiateAcceptBody packs the selected version and suite for
// TypeNegotiateAccept (IP-P-0001 / IP-C-0002):
//
//	u8 vers || u8 suite_len || suite_id[suite_len]
//
// suite_len may be 0 for version-only engineering accepts.
func EncodeNegotiateAcceptBody(vers session.Version, suite string) ([]byte, error) {
	if vers == 0 {
		return nil, fail("negotiate", "selected version required")
	}
	if len(suite) > maxSuiteIDLen {
		return nil, fail("negotiate", "suite id too long")
	}
	out := make([]byte, 0, 2+len(suite))
	out = append(out, byte(vers), byte(len(suite)))
	out = append(out, suite...)
	return out, nil
}

// ParseNegotiateAcceptBody decodes EncodeNegotiateAcceptBody output.
func ParseNegotiateAcceptBody(body []byte) (vers session.Version, suite string, err error) {
	if len(body) < 2 {
		return 0, "", fail("negotiate", "accept body too short")
	}
	vers = session.Version(body[0])
	if vers == 0 {
		return 0, "", fail("negotiate", "bad selected version")
	}
	n := int(body[1])
	if n > maxSuiteIDLen {
		return 0, "", fail("negotiate", "bad suite id length")
	}
	if len(body) != 2+n {
		return 0, "", fail("negotiate", "bad accept body length")
	}
	if n > 0 {
		suite = string(body[2:])
	}
	return vers, suite, nil
}
