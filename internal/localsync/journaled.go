package localsync

import (
	"crypto/rand"
	"os"
	"path/filepath"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/platform"
)

// openJournal opens or creates the destination journal, truncating a torn tail
// so appends can continue after crash.
func openJournal(path string) (*journal.FileSegment, *journal.Writer, journal.Prefix, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, journal.Prefix{}, wrap(KindWrite, "journal", "", err)
	}
	seg, err := journal.OpenFileSegment(path)
	if err != nil {
		return nil, nil, journal.Prefix{}, wrap(KindWrite, "journal", "", err)
	}
	return finishOpenJournal(seg)
}

// finishOpenJournal wraps an opened segment with a Writer, truncating a torn tail.
func finishOpenJournal(seg *journal.FileSegment) (*journal.FileSegment, *journal.Writer, journal.Prefix, error) {
	w, prefix, err := journal.OpenWriter(seg)
	if err != nil {
		_ = seg.Close()
		return nil, nil, journal.Prefix{}, wrap(KindInternal, "journal", "", err)
	}
	if prefix.Torn {
		if err := seg.Truncate(prefix.Bytes); err != nil {
			_ = w.Close()
			_ = seg.Close()
			return nil, nil, journal.Prefix{}, wrap(KindWrite, "journal", "", err)
		}
		w, prefix, err = journal.OpenWriter(seg)
		if err != nil {
			_ = seg.Close()
			return nil, nil, journal.Prefix{}, wrap(KindInternal, "journal", "", err)
		}
	}
	return seg, w, prefix, nil
}

func newTxnID() (codec.TransactionID, error) {
	var id codec.TransactionID
	if _, err := rand.Read(id[:]); err != nil {
		return id, wrap(KindInternal, "journal", "", err)
	}
	return id, nil
}

func planDigestOf(p Plan) (codec.Digest, []byte, error) {
	raw, err := p.FormatJSON()
	if err != nil {
		return codec.Digest{}, nil, wrap(KindInternal, "journal", "", err)
	}
	return codec.SHA256(raw), raw, nil
}

func writePlanSnapshot(destRoot string, raw []byte) error {
	if err := ensureMetaDir(destRoot); err != nil {
		return wrap(KindWrite, "journal", "", err)
	}
	path := planSnapshotPath(destRoot)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return wrap(KindWrite, "journal", "", err)
	}
	f, err := os.OpenFile(tmp, os.O_RDWR, 0)
	if err != nil {
		_ = os.Remove(tmp)
		return wrap(KindWrite, "journal", "", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return wrap(KindWrite, "journal", "", err)
	}
	_ = f.Close()
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return wrap(KindWrite, "journal", "", err)
	}
	_ = platformSyncDir(metaDir(destRoot))
	return nil
}

func loadPlanSnapshot(destRoot string) (Plan, codec.Digest, error) {
	raw, err := os.ReadFile(planSnapshotPath(destRoot))
	if err != nil {
		return Plan{}, codec.Digest{}, wrap(KindRead, "journal", "", err)
	}
	p, err := ParsePlanJSON(raw)
	if err != nil {
		return Plan{}, codec.Digest{}, err
	}
	return p, codec.SHA256(raw), nil
}

func appendRec(w *journal.Writer, id codec.TransactionID, t codec.RecordType, payload []byte) error {
	if _, err := w.Append(id, t, payload); err != nil {
		return wrap(KindWrite, "journal", "", err)
	}
	return nil
}

// beginNewTxn cancels any incomplete same-roots txn and starts a new one.
// destFD, when non-nil, writes the plan snapshot via openat (M3g).
func beginNewTxn(
	sess JournalSession,
	prefix journal.Prefix,
	roots Roots,
	plan Plan,
	planDig codec.Digest,
	planRaw []byte,
	destFD *os.File,
) (codec.TransactionID, error) {
	var zero codec.TransactionID
	st, ok := inspectPrefix(prefix)
	sameRoots := ok && st.Source == roots.Source && st.Destination == roots.Destination
	if ok && !st.Confirmed && sameRoots {
		pay, err := encodeCancellation("superseded_by_new_plan")
		if err != nil {
			return zero, wrap(KindInternal, "journal", "", err)
		}
		if err := sess.Append(st.ID, codec.TypeCancellation, pay); err != nil {
			return zero, err
		}
	}

	id, err := newTxnID()
	if err != nil {
		return zero, err
	}
	if destFD != nil {
		if err := writePlanSnapshotAt(destFD, planRaw); err != nil {
			return zero, err
		}
	} else if err := writePlanSnapshot(roots.Destination, planRaw); err != nil {
		return zero, err
	}
	obs, err := encodeObservation(roots.Source, roots.Destination)
	if err != nil {
		return zero, wrap(KindInternal, "journal", "", err)
	}
	if err := sess.Append(id, codec.TypeObservation, obs); err != nil {
		return zero, err
	}
	if err := sess.Append(id, codec.TypePlanDigest, encodePlanDigest(planDig, uint32(len(plan.Ops)))); err != nil {
		return zero, err
	}
	if err := sess.Append(id, codec.TypeAuthorization, encodeAuthz(planDig)); err != nil {
		return zero, err
	}
	return id, nil
}

func platformSyncDir(path string) error {
	return platform.SyncDir(path)
}
