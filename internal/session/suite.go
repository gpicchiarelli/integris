package session

import "github.com/gpicchiarelli/integris/internal/crypto"

// LocalSuites is the local crypto-suite allow-list (preference order).
// Unknown peer-only suites are refused (IP-C-0001 negotiation policy).
var LocalSuites = []string{crypto.SuiteIDAEAD}

// SelectSuite picks the first local suite also offered by the peer.
func SelectSuite(local, offered []string) (string, bool) {
	if len(local) == 0 || len(offered) == 0 {
		return "", false
	}
	peer := map[string]struct{}{}
	for _, s := range offered {
		if s != "" {
			peer[s] = struct{}{}
		}
	}
	for _, s := range local {
		if s == "" {
			continue
		}
		if _, ok := peer[s]; ok {
			return s, true
		}
	}
	return "", false
}
