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

	"github.com/gpicchiarelli/integris/internal/authority"
)

// Seatbelt profiles deny path-based file open/mutation and process-exec while
// allowing I/O on already-conferred descriptors, unix IPC, and Mach/sysctl for
// the Go runtime. Network is role-parameterized. Not App Sandbox / Hardened
// Runtime equivalence.
const engineeringSeatbeltBase = `(version 1)
(deny default)
(allow signal)
(allow sysctl-read)
(allow mach*)
(allow process-info*)
(allow file-read-metadata)
(deny file-read-data)
(deny file-write*)
(deny file-write-create)
(deny file-write-unlink)
(deny process-exec*)
(deny process-fork)
`

const engineeringSeatbeltAllowNet = engineeringSeatbeltBase + `(allow system-socket)
(allow network*)
`

const engineeringSeatbeltDenyNet = engineeringSeatbeltBase + `(deny system-socket)
(deny network*)
`

func probeEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{{
		ID: "PROBE-SEATBELT", Platform: plat, Control: "seatbelt",
		Status: StatusAvailable, Detail: "sandbox_init(3) available via libsandbox (cgo)",
	}}
}

func applyEngineering(role authority.ProcessRole) []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	profile := engineeringSeatbeltDenyNet
	detail := "deny ambient path read/write + process-exec/fork + system-socket/network*; inherited fds allowed"
	if RoleMayHoldNetwork(role) {
		profile = engineeringSeatbeltAllowNet
		detail = "deny ambient path read/write + process-exec/fork; system-socket/network + inherited fds allowed"
	}
	if err := sandboxInit(profile); err != nil {
		return []Finding{{
			ID: "APPLY-SEATBELT", Platform: plat, Control: "seatbelt",
			Status: StatusUnavailable, Detail: err.Error(),
		}}
	}
	return []Finding{{
		ID: "APPLY-SEATBELT", Platform: plat, Control: "seatbelt",
		Status: StatusAvailable, Detail: detail,
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
