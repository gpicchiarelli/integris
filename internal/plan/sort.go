package plan

import "bytes"

// comparePathComponents orders paths component-wise by raw validated UTF-8
// bytes (IP-S-0001 / IP-S-0002), then by component count.
func comparePathComponents(a, b [][]byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if c := bytes.Compare(a[i], b[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

// compareEntries orders by path, then capability_id, then action_code.
func compareEntries(a, b Entry) int {
	if c := comparePathComponents(a.Path, b.Path); c != 0 {
		return c
	}
	switch {
	case a.CapabilityID < b.CapabilityID:
		return -1
	case a.CapabilityID > b.CapabilityID:
		return 1
	case a.Action < b.Action:
		return -1
	case a.Action > b.Action:
		return 1
	default:
		return 0
	}
}

// compareClassifications orders input rows like plan entries.
func compareClassifications(a, b Classification) int {
	if c := comparePathComponents(a.Path, b.Path); c != 0 {
		return c
	}
	switch {
	case a.CapabilityID < b.CapabilityID:
		return -1
	case a.CapabilityID > b.CapabilityID:
		return 1
	case a.Action < b.Action:
		return -1
	case a.Action > b.Action:
		return 1
	default:
		return 0
	}
}

func sortClassifications(in []Classification) []Classification {
	out := make([]Classification, len(in))
	copy(out, in)
	// Insertion sort: bounded, deterministic, no map iteration.
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && compareClassifications(out[j-1], out[j]) > 0 {
			out[j-1], out[j] = out[j], out[j-1]
			j--
		}
	}
	return out
}

func sortEntries(in []Entry) []Entry {
	out := make([]Entry, len(in))
	copy(out, in)
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && compareEntries(out[j-1], out[j]) > 0 {
			out[j-1], out[j] = out[j], out[j-1]
			j--
		}
	}
	return out
}

func sortUint16(in []uint16) []uint16 {
	out := make([]uint16, len(in))
	copy(out, in)
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && out[j-1] > out[j] {
			out[j-1], out[j] = out[j], out[j-1]
			j--
		}
	}
	return out
}

func clonePath(p [][]byte) [][]byte {
	out := make([][]byte, len(p))
	for i := range p {
		out[i] = append([]byte{}, p[i]...)
	}
	return out
}

func allowContains(list []uint16, id uint16) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}
