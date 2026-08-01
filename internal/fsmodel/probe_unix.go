//go:build unix

package fsmodel

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/plan"
	"golang.org/x/sys/unix"
)

// ProbeResult captures empirical facts and the scratch digest binding.
type ProbeResult struct {
	Vector Vector
	GOOS   string
	GOARCH string
}

// ProbeScratch runs non-destructive capability probes inside an isolated
// scratch directory on the target filesystem (same volume as scratchDir).
// The directory must exist and be writable; a subdirectory is created and removed.
func ProbeScratch(scratchDir string) (ProbeResult, error) {
	var zero ProbeResult
	info, err := os.Stat(scratchDir)
	if err != nil {
		return zero, reject("probe", err.Error())
	}
	if !info.IsDir() {
		return zero, reject("probe", "scratchDir must be a directory")
	}
	dir, err := os.MkdirTemp(scratchDir, "integris-cap-*")
	if err != nil {
		return zero, reject("probe", err.Error())
	}
	defer os.RemoveAll(dir)

	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		return zero, reject("probe", err.Error())
	}
	vol := codec.SHA256([]byte(fmt.Sprintf("dev:%d", st.Dev)))

	facts := []Fact{
		{ID: plan.CapIdentity, Result: plan.ResultLossless, DetailDigest: vol},
		probeCase(dir),
		probeSymlink(dir),
		probeHardlink(dir),
		probeSpecial(dir),
		{ID: plan.CapNameEncoding, Result: plan.ResultLossless}, // UTF-8 path ops succeeded to create dir
		{ID: plan.CapUnicode, Result: plan.ResultUnknown, DetailDigest: codec.SHA256([]byte("nfc-probe-deferred"))},
		{ID: plan.CapACL, Result: plan.ResultUnknown},
		{ID: plan.CapXattr, Result: plan.ResultUnknown},
		{ID: plan.CapBSDFlags, Result: plan.ResultUnknown},
		{ID: plan.CapSparse, Result: plan.ResultUnknown},
		{ID: plan.CapResourceFork, Result: plan.ResultUnknown},
		{ID: plan.CapTimes, Result: plan.ResultUnknown},
		{ID: plan.CapIdentityMap, Result: plan.ResultUnknown},
		{ID: plan.CapMount, Result: plan.ResultUnknown},
		{ID: plan.CapRenameAtomicity, Result: probeRename(dir)},
		{ID: plan.CapSync, Result: plan.ResultLossless}, // fsync on dir succeeded below or unknown
		{ID: plan.CapCOW, Result: plan.ResultUnknown},
		{ID: plan.CapSnapshot, Result: plan.ResultUnknown},
		{ID: plan.CapDurability, Result: plan.ResultUnknown},
	}

	// Attempt directory sync as a sync capability probe.
	if d, err := os.Open(dir); err == nil {
		if err := d.Sync(); err != nil {
			facts = replaceFact(facts, plan.CapSync, plan.ResultUnknown)
		} else {
			facts = replaceFact(facts, plan.CapSync, plan.ResultLossless)
		}
		_ = d.Close()
	}

	v, err := NewVector(vol, facts)
	if err != nil {
		return zero, err
	}
	return ProbeResult{Vector: v, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}, nil
}

func replaceFact(facts []Fact, id plan.CapabilityID, r plan.ResultCode) []Fact {
	out := append([]Fact{}, facts...)
	for i := range out {
		if out[i].ID == id {
			out[i].Result = r
			return out
		}
	}
	return append(out, Fact{ID: id, Result: r})
}

func probeCase(dir string) Fact {
	lower := filepath.Join(dir, "caseprobe")
	upper := filepath.Join(dir, "CASEPROBE")
	if err := os.WriteFile(lower, []byte("a"), 0o644); err != nil {
		return Fact{ID: plan.CapCase, Result: plan.ResultUnknown}
	}
	_, err := os.Stat(upper)
	_ = os.Remove(lower)
	if err == nil {
		// Case-insensitive: upper name resolves to same object.
		return Fact{ID: plan.CapCase, Result: plan.ResultWrapped, DetailDigest: codec.SHA256([]byte("case-insensitive"))}
	}
	return Fact{ID: plan.CapCase, Result: plan.ResultLossless, DetailDigest: codec.SHA256([]byte("case-sensitive"))}
}

func probeSymlink(dir string) Fact {
	target := filepath.Join(dir, "sym-target")
	link := filepath.Join(dir, "sym-link")
	if err := os.WriteFile(target, []byte("t"), 0o644); err != nil {
		return Fact{ID: plan.CapSymlink, Result: plan.ResultUnknown}
	}
	if err := os.Symlink("sym-target", link); err != nil {
		_ = os.Remove(target)
		return Fact{ID: plan.CapSymlink, Result: plan.ResultUnrepresentable}
	}
	_ = os.Remove(link)
	_ = os.Remove(target)
	return Fact{ID: plan.CapSymlink, Result: plan.ResultLossless}
}

func probeHardlink(dir string) Fact {
	a := filepath.Join(dir, "hl-a")
	b := filepath.Join(dir, "hl-b")
	if err := os.WriteFile(a, []byte("h"), 0o644); err != nil {
		return Fact{ID: plan.CapHardlink, Result: plan.ResultUnknown}
	}
	if err := os.Link(a, b); err != nil {
		_ = os.Remove(a)
		return Fact{ID: plan.CapHardlink, Result: plan.ResultUnrepresentable}
	}
	_ = os.Remove(b)
	_ = os.Remove(a)
	return Fact{ID: plan.CapHardlink, Result: plan.ResultLossless}
}

func probeSpecial(dir string) Fact {
	// FIFO as a representative special object.
	p := filepath.Join(dir, "fifo-probe")
	if err := unix.Mkfifo(p, 0o600); err != nil {
		return Fact{ID: plan.CapSpecialObject, Result: plan.ResultUnknown}
	}
	_ = os.Remove(p)
	return Fact{ID: plan.CapSpecialObject, Result: plan.ResultLossless}
}

func probeRename(dir string) plan.ResultCode {
	a := filepath.Join(dir, "rn-a")
	b := filepath.Join(dir, "rn-b")
	if err := os.WriteFile(a, []byte("r"), 0o644); err != nil {
		return plan.ResultUnknown
	}
	if err := os.Rename(a, b); err != nil {
		_ = os.Remove(a)
		return plan.ResultUnknown
	}
	_ = os.Remove(b)
	return plan.ResultLossless
}
