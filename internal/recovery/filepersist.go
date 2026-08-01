package recovery

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

// FilePersist is a directory-backed PersistIO for real-filesystem fault tests.
// Layout under Root:
//
//	staging/     temporary publication staging
//	quarantine/  existence-tolerant quarantine destination
//	confirm.log  append-only confirmation markers (not the product journal)
//
// FailAt stops at Checkpoint(label) before the labeled side effect completes.
type FilePersist struct {
	Root   string
	FailAt CrashLabel

	Checkpoints []CrashLabel
	Confirms    int
}

// NewFilePersist prepares staging and quarantine directories under root.
func NewFilePersist(root string) (*FilePersist, error) {
	for _, sub := range []string{"staging", "quarantine"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
			return nil, err
		}
	}
	return &FilePersist{Root: root}, nil
}

// Checkpoint implements PersistIO.
func (f *FilePersist) Checkpoint(label CrashLabel) error {
	f.Checkpoints = append(f.Checkpoints, label)
	if f.FailAt != "" && label == f.FailAt {
		return ioErr(label, errInjectedFault)
	}
	// Best-effort directory sync at persistence labels.
	switch label {
	case LabelPStageSync, LabelPPublishDirSync, LabelPConfirmPost, LabelJMetaPost:
		if err := syncDir(f.Root); err != nil {
			return ioErr(label, err)
		}
	}
	return nil
}

// CleanupStaging removes staging contents (existence-tolerant).
func (f *FilePersist) CleanupStaging() error {
	dir := filepath.Join(f.Root, "staging")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(dir, e.Name()))
	}
	return syncDir(dir)
}

// QuarantineStaging moves staging entries into quarantine/ (existence-tolerant).
func (f *FilePersist) QuarantineStaging() error {
	src := filepath.Join(f.Root, "staging")
	dst := filepath.Join(f.Root, "quarantine")
	entries, err := os.ReadDir(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		from := filepath.Join(src, e.Name())
		to := filepath.Join(dst, e.Name())
		if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
			// Cross-device fallback: copy then remove is out of scope for M1;
			// same-volume tempdir is required for these tests.
			return fmt.Errorf("quarantine rename: %w", err)
		}
	}
	_ = syncDir(src)
	return syncDir(dst)
}

// AppendConfirmation appends a 16-byte txid record to confirm.log and syncs.
func (f *FilePersist) AppendConfirmation(txid [16]byte, payload []byte) error {
	_ = payload
	path := filepath.Join(f.Root, "confirm.log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], 16)
	if _, err := file.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := file.Write(txid[:]); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	f.Confirms++
	return nil
}

// SeedStaging writes a named staging object for quarantine/cleanup tests.
func (f *FilePersist) SeedStaging(name string, data []byte) error {
	path := filepath.Join(f.Root, "staging", name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	return syncDir(filepath.Join(f.Root, "staging"))
}

// StagingEmpty reports whether staging has no entries.
func (f *FilePersist) StagingEmpty() (bool, error) {
	entries, err := os.ReadDir(filepath.Join(f.Root, "staging"))
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}
	return len(entries) == 0, nil
}

// QuarantineHas reports whether quarantine contains name.
func (f *FilePersist) QuarantineHas(name string) (bool, error) {
	_, err := os.Stat(filepath.Join(f.Root, "quarantine", name))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
