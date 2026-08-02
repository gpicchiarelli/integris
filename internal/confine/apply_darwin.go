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
	"strings"

	"github.com/gpicchiarelli/integris/internal/authority"
)

func probeEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{{
		ID: "PROBE-SEATBELT", Platform: plat, Control: "seatbelt",
		Status: StatusAvailable, Detail: "sandbox_init(3) available via libsandbox (cgo)",
	}}
}

func applyEngineering(role authority.ProcessRole, opts ApplyOptions) []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	// RLIMIT_CORE before Seatbelt (M6a).
	out := []Finding{applyRlimitCoreFinding(plat)}
	profile, detail, err := buildSeatbeltProfile(role, opts.AllowRoots)
	if err != nil {
		return append(out, Finding{
			ID: "APPLY-SEATBELT", Platform: plat, Control: "seatbelt",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	}
	if err := sandboxInit(profile); err != nil {
		return append(out, Finding{
			ID: "APPLY-SEATBELT", Platform: plat, Control: "seatbelt",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	}
	return append(out, Finding{
		ID: "APPLY-SEATBELT", Platform: plat, Control: "seatbelt",
		Status: StatusAvailable, Detail: detail,
	})
}

func buildSeatbeltProfile(role authority.ProcessRole, roots []string) (profile, detail string, err error) {
	var b strings.Builder
	b.WriteString(`(version 1)
(deny default)
(allow signal)
(allow sysctl-read)
(allow mach*)
(allow process-info*)
(allow file-read-metadata)
`)
	mode := RoleArchiveFSMode(role)
	for _, root := range roots {
		if err := seatbeltSafePath(root); err != nil {
			return "", "", err
		}
		fmt.Fprintf(&b, "(allow file-read* (subpath %q))\n", root)
		if mode == ArchiveFSReadWrite {
			fmt.Fprintf(&b, "(allow file-write* (subpath %q))\n", root)
		}
	}
	b.WriteString(`(deny process-exec*)
(deny process-fork)
`)
	if RoleMayHoldNetwork(role) {
		b.WriteString(`(allow system-socket)
(allow network*)
`)
		detail = "Seatbelt; network allowed"
	} else {
		b.WriteString(`(deny system-socket)
(deny network*)
`)
		detail = "Seatbelt; deny ambient network"
	}
	switch {
	case mode == ArchiveFSNone || len(roots) == 0:
		detail += "; deny ambient path read/write (inherited fds ok)"
	case mode == ArchiveFSReadonly:
		detail += fmt.Sprintf("; readonly allow-roots=%d", len(roots))
	default:
		detail += fmt.Sprintf("; readwrite allow-roots=%d", len(roots))
	}
	return b.String(), detail, nil
}

func seatbeltSafePath(p string) error {
	if p == "" || strings.ContainsAny(p, "\"\n\r\x00") {
		return fmt.Errorf("unsafe allow-root path")
	}
	return nil
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
