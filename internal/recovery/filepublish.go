package recovery

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/gpicchiarelli/integris/internal/codec"
)

// FilePublisher is the apply-side publication profile for M1 crash harnesses.
// It is intentionally not a PersistIO: recovery cleanup/quarantine/confirm stay
// on FilePersist so apply and recovery paths do not share one common-cause IO
// adapter (IP-S-0003).
//
// Layout under Root:
//
//	staging/    exclusive staged object before rename
//	published/  linearized publication destination
type FilePublisher struct {
	Root   string
	FailAt CrashLabel

	// ExpectedContent, when non-nil, is compared to published bytes for
	// Observation().PublishedContentMatches.
	ExpectedContent []byte

	Checkpoints []CrashLabel
}

// NewFilePublisher prepares staging and published directories under root.
func NewFilePublisher(root string) (*FilePublisher, error) {
	for _, sub := range []string{"staging", "published"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
			return nil, err
		}
	}
	return &FilePublisher{Root: root}, nil
}

// Publish exclusive-creates staging/name, syncs, renames into published/, and
// directory-syncs. Crash labels are hit in catalog order:
// P-STAGE-CREATE → P-STAGE-SYNC → P-PUBLISH-RENAME → P-PUBLISH-DIRSYNC.
func (p *FilePublisher) Publish(name string, data []byte) error {
	if p == nil {
		return stateErr("nil FilePublisher")
	}
	if err := validatePublishName(name); err != nil {
		return err
	}
	stagePath := filepath.Join(p.Root, "staging", name)
	pubPath := filepath.Join(p.Root, "published", name)

	if err := p.checkpoint(LabelPStageCreate); err != nil {
		return err
	}
	f, err := os.OpenFile(stagePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ioErr(LabelPStageCreate, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(stagePath)
		return ioErr(LabelPStageCreate, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(stagePath)
		return ioErr(LabelPStageCreate, err)
	}

	if err := p.checkpoint(LabelPStageSync); err != nil {
		return err
	}
	sf, err := os.OpenFile(stagePath, os.O_RDWR, 0)
	if err != nil {
		return ioErr(LabelPStageSync, err)
	}
	if err := sf.Sync(); err != nil {
		_ = sf.Close()
		return ioErr(LabelPStageSync, err)
	}
	_ = sf.Close()
	if err := syncDir(filepath.Join(p.Root, "staging")); err != nil {
		return ioErr(LabelPStageSync, err)
	}

	if err := p.checkpoint(LabelPPublishRename); err != nil {
		return err
	}
	if _, err := os.Stat(pubPath); err == nil {
		return stateErr("published destination already exists")
	} else if err != nil && !os.IsNotExist(err) {
		return ioErr(LabelPPublishRename, err)
	}
	if err := os.Rename(stagePath, pubPath); err != nil {
		return ioErr(LabelPPublishRename, err)
	}

	if err := p.checkpoint(LabelPPublishDirSync); err != nil {
		return err
	}
	if err := syncDir(filepath.Join(p.Root, "published")); err != nil {
		return ioErr(LabelPPublishDirSync, err)
	}
	if err := syncDir(p.Root); err != nil {
		return ioErr(LabelPPublishDirSync, err)
	}
	return nil
}

// Observation derives FSObservation from the on-disk publish layout.
func (p *FilePublisher) Observation(rootID, volID codec.Digest) (FSObservation, error) {
	obs := FSObservation{
		RootIdentity:   rootID,
		VolumeIdentity: volID,
	}
	if p == nil {
		return obs, stateErr("nil FilePublisher")
	}
	staged, err := dirHasEntries(filepath.Join(p.Root, "staging"))
	if err != nil {
		return obs, err
	}
	obs.StagingPresent = staged

	published, err := dirHasEntries(filepath.Join(p.Root, "published"))
	if err != nil {
		return obs, err
	}
	if published {
		obs.PublicationStarted = true
		obs.PublicationLinearized = true
		if p.ExpectedContent != nil {
			match, err := publishedMatches(filepath.Join(p.Root, "published"), p.ExpectedContent)
			if err != nil {
				return obs, err
			}
			obs.PublishedContentMatches = match
		} else {
			obs.PublishedContentMatches = true
		}
	} else if staged {
		// Stage-only: publication started in the sense of prepared staging, but
		// not linearized into published/.
		obs.PublicationStarted = false
		obs.PublicationLinearized = false
		obs.PublishedContentMatches = false
	}
	return obs, nil
}

// StagingHas reports whether staging contains name.
func (p *FilePublisher) StagingHas(name string) (bool, error) {
	return pathExists(filepath.Join(p.Root, "staging", name))
}

// PublishedHas reports whether published contains name.
func (p *FilePublisher) PublishedHas(name string) (bool, error) {
	return pathExists(filepath.Join(p.Root, "published", name))
}

func (p *FilePublisher) checkpoint(label CrashLabel) error {
	p.Checkpoints = append(p.Checkpoints, label)
	if p.FailAt != "" && label == p.FailAt {
		return ioErr(label, errInjectedFault)
	}
	return nil
}

func validatePublishName(name string) error {
	if name == "" || name == "." || name == ".." {
		return stateErr("invalid publish name")
	}
	if strings.Contains(name, string(filepath.Separator)) || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return stateErr("publish name must be a single path element")
	}
	return nil
}

func dirHasEntries(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return len(entries) > 0, nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func publishedMatches(dir string, want []byte) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	if len(entries) == 0 {
		return false, nil
	}
	// Single-object M1 profile: compare the first entry's bytes.
	got, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		return false, err
	}
	if len(got) != len(want) {
		return false, nil
	}
	for i := range got {
		if got[i] != want[i] {
			return false, nil
		}
	}
	return true, nil
}
