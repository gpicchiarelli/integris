package path

import "context"

// ObjectType is the post-open filesystem object class.
type ObjectType int

const (
	TypeUnknown ObjectType = iota
	TypeDir
	TypeFile
	TypeSymlink
	TypeOther
)

// Identity is a platform file identity (inode / file-id analogue).
type Identity uint64

// VolumeID is a mount/volume identity captured with the root.
type VolumeID uint64

// FileInfo holds post-open facts. Authorization decisions use these facts, not
// path strings.
type FileInfo struct {
	Type      ObjectType
	ID        Identity
	Volume    VolumeID
	LinkCount uint32
	Mode      uint32 // opaque permission bits from the adapter
}

// File is an opened filesystem object held by descriptor.
type File interface {
	Info() (FileInfo, error)
	Close() error
}

// Dir is an opened directory descriptor used for descriptor-relative opens.
type Dir interface {
	File
	// OpenNoFollow opens name relative to this directory without following
	// symbolic links. name is a single validated component.
	OpenNoFollow(ctx context.Context, name []byte) (File, error)
}

// RootIdentity is the conferred root's captured volume/filesystem identity.
type RootIdentity struct {
	Volume VolumeID
	// AllowedVolumes, when non-empty, permits those volumes in addition to Volume.
	AllowedVolumes []VolumeID
}

// ResolveOpts controls post-open policy checks.
type ResolveOpts struct {
	Root RootIdentity
	// AllowHardLinks permits LinkCount > 1 when true; default forbids.
	AllowHardLinks bool
	// RequireDir, when true, requires every intermediate and final object to be a directory.
	// When false, only intermediate components must be directories; the final may be a file.
	RequireDir bool
	// ExpectFinal, when non-zero, requires the final object type to match.
	ExpectFinal ObjectType
}

// Chain is a successfully resolved descriptor chain. The caller owns Close.
type Chain struct {
	Files []File // root is not included; Files[i] corresponds to components[i]
}

// Close closes all descriptors in reverse order. The first close error is returned.
func (c *Chain) Close() error {
	var first error
	for i := len(c.Files) - 1; i >= 0; i-- {
		if c.Files[i] == nil {
			continue
		}
		if err := c.Files[i].Close(); err != nil && first == nil {
			first = err
		}
		c.Files[i] = nil
	}
	return first
}

// Resolve validates components, then opens each relative to the prior descriptor
// with no-follow semantics and post-open identity/type/volume checks.
// On any failure the partial chain is closed and a typed *Error is returned.
func Resolve(ctx context.Context, root Dir, components [][]byte, opts ResolveOpts, profile Profile) (Chain, error) {
	var zero Chain
	if root == nil {
		return zero, reject(RuleOpen, -1, "nil root descriptor")
	}
	if err := ValidateComponents(components, profile); err != nil {
		return zero, err
	}

	rootInfo, err := root.Info()
	if err != nil {
		return zero, reject(RuleOpen, -1, "root info: "+err.Error())
	}
	if rootInfo.Type != TypeDir {
		return zero, reject(RuleType, -1, "root is not a directory")
	}
	if opts.Root.Volume != 0 && rootInfo.Volume != opts.Root.Volume {
		return zero, reject(RuleVolume, -1, "root volume does not match conferred identity")
	}

	parent := root
	out := make([]File, 0, len(components))
	fail := func(err error) (Chain, error) {
		for i := len(out) - 1; i >= 0; i-- {
			_ = out[i].Close()
		}
		return zero, err
	}

	for i, name := range components {
		if err := ctx.Err(); err != nil {
			return fail(reject(RuleOpen, i, err.Error()))
		}
		f, err := parent.OpenNoFollow(ctx, name)
		if err != nil {
			return fail(reject(RuleOpen, i, err.Error()))
		}
		info, err := f.Info()
		if err != nil {
			_ = f.Close()
			return fail(reject(RuleOpen, i, "post-open info: "+err.Error()))
		}
		if err := checkOpened(info, i, lastComponent(i, len(components)), opts); err != nil {
			_ = f.Close()
			return fail(err)
		}
		// Re-query identity facts before retaining the descriptor. A change
		// between the first and second observation is treated as a substitution
		// race (IP-S-0001 / path-resolution safety properties).
		info2, err := f.Info()
		if err != nil {
			_ = f.Close()
			return fail(reject(RuleOpen, i, "post-open recheck: "+err.Error()))
		}
		if !sameIdentity(info, info2) {
			_ = f.Close()
			return fail(reject(RuleIdent, i, "object identity changed after open"))
		}
		out = append(out, f)
		last := lastComponent(i, len(components))
		if info.Type == TypeDir {
			d, ok := f.(Dir)
			if !ok {
				return fail(reject(RuleType, i, "directory lacks Dir interface"))
			}
			parent = d
		} else if !last {
			return fail(reject(RuleType, i, "intermediate component is not a directory"))
		}
	}
	return Chain{Files: out}, nil
}

func volumeAllowed(v VolumeID, root RootIdentity) bool {
	if root.Volume == 0 && len(root.AllowedVolumes) == 0 {
		// Untyped test roots: accept any volume.
		return true
	}
	if v == root.Volume {
		return true
	}
	for _, a := range root.AllowedVolumes {
		if v == a {
			return true
		}
	}
	return false
}

func lastComponent(i, n int) bool { return i == n-1 }

func checkOpened(info FileInfo, i int, last bool, opts ResolveOpts) error {
	if info.Type == TypeSymlink {
		return reject(RuleLink, i, "symlink encountered")
	}
	if info.Type == TypeOther || info.Type == TypeUnknown {
		return reject(RuleType, i, "unsupported object type")
	}
	needDir := !last || opts.RequireDir
	if needDir && info.Type != TypeDir {
		return reject(RuleType, i, "expected directory")
	}
	if last && opts.ExpectFinal != TypeUnknown && info.Type != opts.ExpectFinal {
		return reject(RuleType, i, "final object type mismatch")
	}
	if !opts.AllowHardLinks && info.Type != TypeDir && info.LinkCount > 1 {
		return reject(RulePolicy, i, "hard link not permitted")
	}
	if !volumeAllowed(info.Volume, opts.Root) {
		return reject(RuleVolume, i, "unauthorized mount/volume")
	}
	return nil
}

func sameIdentity(a, b FileInfo) bool {
	return a.Type == b.Type && a.ID == b.ID && a.Volume == b.Volume && a.LinkCount == b.LinkCount
}
