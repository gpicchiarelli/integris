//go:build darwin && cgo

package confine

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -lsandbox
#include <stdlib.h>
#include <sandbox.h>

static void integris_cfree(char *p) { free(p); }
*/
import "C"
import (
	"fmt"
	"runtime"
)

// engineeringSeatbelt denies path-based file mutation and process-exec while
// allowing inherited-descriptor I/O, unix IPC, and Mach/sysctl for the Go
// runtime. Not App Sandbox / Hardened Runtime equivalence.
const engineeringSeatbelt = `(version 1)
(deny default)
(allow signal)
(allow sysctl-read)
(allow mach*)
(allow process-info*)
(allow file-read-metadata)
(allow file-read-data)
(deny file-write*)
(deny file-write-create)
(deny file-write-unlink)
(deny process-exec*)
(deny process-fork)
(allow system-socket)
(allow network*)
`

func probeEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{{
		ID: "PROBE-SEATBELT", Platform: plat, Control: "seatbelt",
		Status: StatusAvailable, Detail: "sandbox_init(3) available via libsandbox (cgo)",
	}}
}

func applyEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	if err := sandboxInit(engineeringSeatbelt); err != nil {
		return []Finding{{
			ID: "APPLY-SEATBELT", Platform: plat, Control: "seatbelt",
			Status: StatusUnavailable, Detail: err.Error(),
		}}
	}
	return []Finding{{
		ID: "APPLY-SEATBELT", Platform: plat, Control: "seatbelt",
		Status: StatusAvailable, Detail: "deny file-write* + process-exec/fork; network/unix IPC + inherited fds allowed",
	}}
}

func sandboxInit(profile string) error {
	cProfile := C.CString(profile)
	defer C.integris_cfree(cProfile)
	var errBuf *C.char
	if rc := C.sandbox_init(cProfile, 0, &errBuf); rc != 0 {
		msg := "sandbox_init failed"
		if errBuf != nil {
			msg = C.GoString(errBuf)
			C.sandbox_free_error(errBuf)
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}
