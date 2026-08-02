package localsync

import (
	"encoding/hex"
	"errors"
	"os"
	"time"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/platform"
)

// Options controls a Sync run.
type Options struct {
	Source      string
	Destination string
	// PlanOnly builds and returns the plan without applying.
	PlanOnly bool
	Hooks    *ApplyHooks
	// DisableJournal skips append-only crash-safe progress (not recommended).
	DisableJournal bool
	// JournalPath overrides the default destination/.integris/local.jrn path.
	JournalPath string
	// Journal, when set, owns durable appends (e.g. IPC to integrisd-journal).
	// When nil, Sync opens JournalPath (or the default) locally.
	Journal JournalSession
	// DestManifest, when set, skips Scan(destination) and plans against this
	// readonly index snapshot (integrisd-index / M2h).
	DestManifest *Manifest
	// SourceFD / DestFD, when both set, use openat ScanAt/ApplyAt and plan
	// snapshot openat (M3g CapEnter-safe publish). Labels remain Source/Destination.
	// FDs are borrowed (not closed).
	SourceFD *os.File
	DestFD   *os.File
}

func (o Options) useAt() bool {
	return o.SourceFD != nil && o.DestFD != nil
}

// Sync runs scan → plan → apply → verify for a unidirectional local sync.
// When journaling is enabled (default), progress is durable and interrupted
// runs resume the persisted plan from the last completed operation.
func Sync(opts Options) (Result, error) {
	start := time.Now()
	res := Result{
		Outcome:        OutcomeFailed,
		DurabilityNote: platform.DurabilityMechanism(),
	}

	var roots Roots
	var err error
	if opts.useAt() {
		roots, err = resolveRootsAt(opts.Source, opts.Destination, opts.SourceFD, opts.DestFD)
	} else {
		roots, err = ResolveRoots(opts.Source, opts.Destination, true)
	}
	if err != nil {
		return failResult(res, start, err)
	}
	res.Source = roots.Source
	res.Destination = roots.Destination

	if opts.PlanOnly {
		plan, err := buildFreshPlan(roots, opts)
		if err != nil {
			return failResult(res, start, err)
		}
		res.Plan = plan
		res.PlannedOps = len(plan.Ops)
		res.Outcome = OutcomeSuccess
		res.Duration = time.Since(start)
		return res, nil
	}

	if opts.DisableJournal {
		plan, err := buildFreshPlan(roots, opts)
		if err != nil {
			return failResult(res, start, err)
		}
		res.Plan = plan
		res.PlannedOps = len(plan.Ops)
		var applied ApplyResult
		if opts.useAt() {
			applied, err = ApplyAt(opts.SourceFD, opts.DestFD, roots, plan, opts.Hooks)
		} else {
			applied, err = Apply(roots, plan, opts.Hooks)
		}
		res.CompletedOps = applied.Completed
		res.SkippedOps = applied.Skipped
		res.BytesTransferred = applied.Bytes
		res.Duration = time.Since(start)
		if err != nil {
			return failResult(res, start, err)
		}
		res.Outcome = OutcomeSuccess
		return res, nil
	}

	return syncJournaled(opts, roots, res, start)
}

func buildFreshPlan(roots Roots, opts Options) (Plan, error) {
	var srcMan Manifest
	var err error
	if opts.SourceFD != nil {
		srcMan, err = ScanAt(opts.SourceFD, roots.Source)
	} else {
		srcMan, err = Scan(roots.Source)
	}
	if err != nil {
		return Plan{}, err
	}
	var dstMan Manifest
	if opts.DestManifest != nil {
		dstMan = *opts.DestManifest
		dstMan.Root = roots.Destination
	} else if opts.DestFD != nil {
		dstMan, err = ScanAt(opts.DestFD, roots.Destination)
		if err != nil {
			return Plan{}, err
		}
	} else {
		dstMan = Manifest{Root: roots.Destination}
		if fi, err := os.Lstat(roots.Destination); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return Plan{}, pathUnsafe("sync", "destination must not be a symbolic link")
			}
			if !fi.IsDir() {
				return Plan{}, invalidArg("sync", "destination must be a directory")
			}
			dstMan, err = Scan(roots.Destination)
			if err != nil {
				return Plan{}, err
			}
		} else if !os.IsNotExist(err) {
			return Plan{}, wrap(KindRead, "sync", "", err)
		}
	}
	plan, err := BuildPlan(srcMan, dstMan)
	if err != nil {
		return Plan{}, err
	}
	plan.SourceRoot = roots.Source
	plan.DestRoot = roots.Destination
	return plan, nil
}

func syncJournaled(opts Options, roots Roots, res Result, start time.Time) (Result, error) {
	if opts.useAt() {
		if err := ensureMetaReadyAt(opts.DestFD); err != nil {
			return failResult(res, start, wrap(KindWrite, "sync", "", err))
		}
	} else {
		if err := os.MkdirAll(roots.Destination, 0o755); err != nil {
			return failResult(res, start, wrap(KindWrite, "sync", "", err))
		}
		if err := ensureMetaDir(roots.Destination); err != nil {
			return failResult(res, start, wrap(KindWrite, "sync", "", err))
		}
	}

	jpath := opts.JournalPath
	if jpath == "" {
		jpath = defaultJournalPath(roots.Destination)
	}
	res.JournalPath = jpath

	sess := opts.Journal
	if sess == nil {
		if opts.DestFD != nil {
			sess = OpenFileJournalAt(jpath, opts.DestFD)
		} else {
			sess = OpenFileJournal(jpath)
		}
	}
	prefix, err := sess.Open()
	if err != nil {
		return failResult(res, start, err)
	}
	defer func() { _ = sess.Close() }()

	st, ok := inspectPrefix(prefix)
	sameRoots := ok && st.Source == roots.Source && st.Destination == roots.Destination

	// Resume incomplete transaction using the durable plan snapshot (do not replan).
	if ok && sameRoots && st.HasPlan && st.Authorized && !st.Confirmed {
		var plan Plan
		var snapDig codec.Digest
		var err error
		if opts.DestFD != nil {
			plan, snapDig, err = loadPlanSnapshotAt(opts.DestFD)
		} else {
			plan, snapDig, err = loadPlanSnapshot(roots.Destination)
		}
		if err != nil {
			return failResult(res, start, err)
		}
		if snapDig != st.PlanDigest {
			return failResult(res, start, classify(KindConflict, "journal", "", "plan snapshot digest mismatch", nil))
		}
		plan.SourceRoot = roots.Source
		plan.DestRoot = roots.Destination
		res.Plan = plan
		res.PlannedOps = len(plan.Ops)
		res.PlanDigest = st.PlanDigest
		res.PlanDigestHex = hex.EncodeToString(st.PlanDigest[:])
		res.Resumed = true
		res.TransactionID = st.ID[:]
		res.TransactionHex = hex.EncodeToString(st.ID[:])

		if st.NextOp > len(plan.Ops) {
			return failResult(res, start, classify(KindConflict, "journal", "", "progress beyond plan", nil))
		}
		payload, err := encodeRecovery(uint32(st.NextOp), "resume")
		if err != nil {
			return failResult(res, start, wrap(KindInternal, "journal", "", err))
		}
		if err := sess.Append(st.ID, codec.TypeRecovery, payload); err != nil {
			return failResult(res, start, err)
		}
		return finishApply(sess, st.ID, roots, plan, st.PlanDigest, st.NextOp, int64(st.BytesCum), res, start, opts)
	}

	plan, err := buildFreshPlan(roots, opts)
	if err != nil {
		return failResult(res, start, err)
	}
	res.Plan = plan
	res.PlannedOps = len(plan.Ops)

	planDig, planRaw, err := planDigestOf(plan)
	if err != nil {
		return failResult(res, start, err)
	}
	res.PlanDigest = planDig
	res.PlanDigestHex = hex.EncodeToString(planDig[:])

	if ok && sameRoots && st.HasPlan && st.PlanDigest == planDig && st.Confirmed {
		res.Outcome = OutcomeSuccess
		res.TransactionID = st.ID[:]
		res.TransactionHex = hex.EncodeToString(st.ID[:])
		for _, op := range plan.Ops {
			if op.Action == ActionSkip {
				res.SkippedOps++
			} else {
				res.CompletedOps++
			}
		}
		res.BytesTransferred = int64(st.BytesCum)
		res.Duration = time.Since(start)
		return res, nil
	}

	id, err := beginNewTxn(sess, prefix, roots, plan, planDig, planRaw, opts.DestFD)
	if err != nil {
		return failResult(res, start, err)
	}
	res.TransactionID = id[:]
	res.TransactionHex = hex.EncodeToString(id[:])
	return finishApply(sess, id, roots, plan, planDig, 0, 0, res, start, opts)
}

func finishApply(
	sess JournalSession,
	id codec.TransactionID,
	roots Roots,
	plan Plan,
	planDig codec.Digest,
	startAt int,
	initialBytes int64,
	res Result,
	start time.Time,
	opts Options,
) (Result, error) {
	applyOpts := ApplyOptions{
		Hooks:        opts.Hooks,
		StartAt:      startAt,
		CountPrior:   true,
		InitialBytes: initialBytes,
		OnOpComplete: func(index int, op Op, bytesCum int64) error {
			payload, err := encodeProgress(uint32(index), op.Action, op.Rel, uint64(bytesCum))
			if err != nil {
				return wrap(KindInternal, "journal", "", err)
			}
			return sess.Append(id, codec.TypeProgress, payload)
		},
	}
	var applied ApplyResult
	var err error
	if opts.useAt() {
		applied, err = ApplyWithAt(opts.SourceFD, opts.DestFD, roots, plan, applyOpts)
	} else {
		applied, err = ApplyWith(roots, plan, applyOpts)
	}
	res.CompletedOps = applied.Completed
	res.SkippedOps = applied.Skipped
	res.BytesTransferred = applied.Bytes
	if err != nil {
		return failResult(res, start, err)
	}

	conf := encodeConfirmation(planDig, uint32(applied.Completed), uint32(applied.Skipped), uint64(applied.Bytes))
	if err := sess.Append(id, codec.TypeConfirmation, conf); err != nil {
		return failResult(res, start, err)
	}

	res.Outcome = OutcomeSuccess
	res.Duration = time.Since(start)
	return res, nil
}

func failResult(res Result, start time.Time, err error) (Result, error) {
	res.Outcome = OutcomeFailed
	res.Error = err.Error()
	res.ErrorKind = kindOf(err)
	res.Duration = time.Since(start)
	return res, err
}

func kindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindInternal
}
