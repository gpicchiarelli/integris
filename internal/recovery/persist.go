package recovery

// PersistIO is injected persistence for deterministic fault testing.
// Implementations must treat all operations as existence-tolerant where noted.
type PersistIO interface {
	// Checkpoint is invoked at a crash-catalog label before/after a boundary.
	// Returning a non-nil error simulates kill/power-loss at that label.
	Checkpoint(label CrashLabel) error

	// CleanupStaging removes staging in an existence-tolerant way.
	CleanupStaging() error

	// QuarantineStaging moves staging aside without inventing publication.
	QuarantineStaging() error

	// AppendConfirmation appends an at-most-once confirmation journal record.
	// Callers must not invoke this when a confirmation already exists.
	AppendConfirmation(txid [16]byte, payload []byte) error
}

// MemPersist is an in-memory PersistIO for fault-injection tests.
type MemPersist struct {
	FailAt CrashLabel

	Checkpoints []CrashLabel
	Cleanups    int
	Quarantines int
	Confirms    int
	ConfirmTX   [16]byte
	StagingGone bool
	Quarantined bool
}

// Checkpoint implements PersistIO.
func (m *MemPersist) Checkpoint(label CrashLabel) error {
	m.Checkpoints = append(m.Checkpoints, label)
	if m.FailAt != "" && label == m.FailAt {
		return ioErr(label, errInjectedFault)
	}
	return nil
}

// CleanupStaging implements PersistIO.
func (m *MemPersist) CleanupStaging() error {
	m.Cleanups++
	m.StagingGone = true
	return nil
}

// QuarantineStaging implements PersistIO.
func (m *MemPersist) QuarantineStaging() error {
	m.Quarantines++
	m.Quarantined = true
	m.StagingGone = true
	return nil
}

// AppendConfirmation implements PersistIO.
func (m *MemPersist) AppendConfirmation(txid [16]byte, payload []byte) error {
	_ = payload
	m.Confirms++
	m.ConfirmTX = txid
	return nil
}

type injectedFault struct{}

func (injectedFault) Error() string { return "injected fault" }

var errInjectedFault = injectedFault{}
