//go:build !unix

package recovery

func killSelfAt(label CrashLabel) error {
	return stateErr("KillAt unsupported on this OS")
}
