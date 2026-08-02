package localsync

import (
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/gpicchiarelli/integris/internal/codec"
)

// Action is a typed plan operation.
type Action string

const (
	ActionMkdir   Action = "mkdir"
	ActionCopy    Action = "copy"
	ActionReplace Action = "replace"
	ActionSkip    Action = "skip"
)

// Reason explains why an action was chosen.
type Reason string

const (
	ReasonMissing       Reason = "missing"
	ReasonDigestDiffers Reason = "digest_differs"
	ReasonIdentical     Reason = "identical"
	ReasonDirExists     Reason = "dir_exists"
)

// Op is one immutable plan operation. Paths are logical (slash-separated).
type Op struct {
	Action       Action `json:"action"`
	Rel          string `json:"rel"`
	Reason       Reason `json:"reason"`
	ExpectedSize int64  `json:"expected_size,omitempty"`
	ExpectedMode uint32 `json:"expected_mode,omitempty"`
	// ExpectedDigestHex is the source content digest for file ops.
	ExpectedDigestHex string `json:"expected_digest_sha256,omitempty"`
	// Initial describes the destination observation used for planning.
	Initial string `json:"initial"`
	// Final describes the intended destination state after apply.
	Final string `json:"final"`
}

// Plan is an immutable, deterministic synchronization plan. Construction never
// mutates the filesystem.
type Plan struct {
	SourceRoot string `json:"source_root"`
	DestRoot   string `json:"destination_root"`
	Ops        []Op   `json:"ops"`
}

// BuildPlan compares source and destination manifests. It never deletes
// destination-only entries (v1). Planning is pure over the provided manifests.
func BuildPlan(src, dst Manifest) (Plan, error) {
	p := Plan{
		SourceRoot: src.Root,
		DestRoot:   dst.Root,
		Ops:        make([]Op, 0, len(src.Entries)),
	}

	for _, s := range src.Entries {
		d, ok := dst.lookup(s.Rel)
		switch s.Type {
		case EntryDir:
			if !ok {
				p.Ops = append(p.Ops, Op{
					Action:       ActionMkdir,
					Rel:          s.Rel,
					Reason:       ReasonMissing,
					ExpectedMode: s.Mode,
					Initial:      "absent",
					Final:        "directory",
				})
				continue
			}
			if d.Type != EntryDir {
				return Plan{}, classify(KindConflict, "plan", s.Rel, "destination is not a directory", nil)
			}
			p.Ops = append(p.Ops, Op{
				Action:       ActionSkip,
				Rel:          s.Rel,
				Reason:       ReasonDirExists,
				ExpectedMode: s.Mode,
				Initial:      "directory",
				Final:        "directory",
			})
		case EntryFile:
			if !ok {
				p.Ops = append(p.Ops, Op{
					Action:            ActionCopy,
					Rel:               s.Rel,
					Reason:            ReasonMissing,
					ExpectedSize:      s.Size,
					ExpectedMode:      s.Mode,
					ExpectedDigestHex: s.DigestHex(),
					Initial:           "absent",
					Final:             "file",
				})
				continue
			}
			if d.Type != EntryFile {
				return Plan{}, classify(KindConflict, "plan", s.Rel, "destination is not a regular file", nil)
			}
			if d.HasDigest && s.HasDigest && d.Digest == s.Digest {
				p.Ops = append(p.Ops, Op{
					Action:            ActionSkip,
					Rel:               s.Rel,
					Reason:            ReasonIdentical,
					ExpectedSize:      s.Size,
					ExpectedMode:      s.Mode,
					ExpectedDigestHex: s.DigestHex(),
					Initial:           "file_identical",
					Final:             "file",
				})
				continue
			}
			// Size may match with different content — digest decides.
			p.Ops = append(p.Ops, Op{
				Action:            ActionReplace,
				Rel:               s.Rel,
				Reason:            ReasonDigestDiffers,
				ExpectedSize:      s.Size,
				ExpectedMode:      s.Mode,
				ExpectedDigestHex: s.DigestHex(),
				Initial:           "file_different",
				Final:             "file",
			})
		default:
			return Plan{}, unsupported("plan", s.Rel, "unknown entry type")
		}
	}

	sort.SliceStable(p.Ops, func(i, j int) bool {
		if p.Ops[i].Rel != p.Ops[j].Rel {
			return p.Ops[i].Rel < p.Ops[j].Rel
		}
		return p.Ops[i].Action < p.Ops[j].Action
	})
	return p, nil
}

// FormatJSON returns indented JSON for diagnostics.
func (p Plan) FormatJSON() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// ParsePlanJSON decodes a plan previously marshaled as JSON.
func ParsePlanJSON(data []byte) (Plan, error) {
	var p Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return Plan{}, wrap(KindInvalidArgument, "plan_json", "", err)
	}
	return p, nil
}

func digestFromHex(s string) (codec.Digest, error) {
	var d codec.Digest
	b, err := hex.DecodeString(s)
	if err != nil {
		return d, err
	}
	if len(b) != len(d) {
		return d, invalidArg("digest", "expected 32-byte SHA-256 hex")
	}
	copy(d[:], b)
	return d, nil
}
