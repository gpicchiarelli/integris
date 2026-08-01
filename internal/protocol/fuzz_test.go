package protocol

import "testing"

func FuzzDecode(f *testing.F) {
	f.Add([]byte{})
	raw, err := Encode(Frame{Type: TypeClose, Sequence: 1}, nil)
	if err == nil {
		f.Add(raw)
	}
	key := []byte("0123456789abcdef")
	raw2, err := Encode(Frame{Type: TypeActivate, Flags: FlagRequiresMAC, Sequence: 1, Body: []byte("x")}, key)
	if err == nil {
		f.Add(raw2)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Decode(b, nil, false)
		_, _ = Decode(b, key, false)
		_, _ = Decode(b, key, true)
	})
}
