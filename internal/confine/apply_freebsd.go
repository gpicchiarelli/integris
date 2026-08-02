//go:build freebsd

package confine

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"unsafe"

	"github.com/gpicchiarelli/integris/internal/authority"
	"golang.org/x/sys/unix"
)

// FreeBSD sys/jail.h flags for jail_set(2).
const (
	jailCreate = 0x01
	jailAttach = 0x04
)

func probeEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{
			ID: "PROBE-CAPSICUM", Platform: plat, Control: "cap_enter",
			Status: StatusAvailable, Detail: "cap_enter(2) available",
		},
		{
			ID: "PROBE-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit",
			Status: StatusAvailable, Detail: "cap_rights_limit(2) available",
		},
		{
			ID: "PROBE-JAIL-NOIP", Platform: plat, Control: "jail_set_ip_disable",
			Status: StatusAvailable, Detail: "jail_set(2) ip4/ip6=disable for !network roles",
		},
	}
}

// LimitConferredFDs reduces IPC/key fds to read/write/event before CapEnter.
func LimitConferredFDs(files ...*os.File) Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	rights, err := unix.CapRightsInit([]uint64{unix.CAP_READ, unix.CAP_WRITE, unix.CAP_EVENT})
	if err != nil {
		return Finding{
			ID: "APPLY-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	for _, f := range files {
		if f == nil {
			continue
		}
		if err := unix.CapRightsLimit(f.Fd(), rights); err != nil {
			return Finding{
				ID: "APPLY-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit",
				Status: StatusUnavailable, Detail: err.Error(),
			}
		}
	}
	return Finding{
		ID: "APPLY-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit",
		Status: StatusAvailable, Detail: "CAP_READ|CAP_WRITE|CAP_EVENT on conferred fds",
	}
}

func applyEngineering(role authority.ProcessRole, opts ApplyOptions) []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	out := make([]Finding, 0, 2)
	if !RoleMayHoldNetwork(role) {
		out = append(out, attachNoIPJail())
	}

	if err := unix.CapEnter(); err != nil {
		out = append(out, Finding{
			ID: "APPLY-CAPSICUM", Platform: plat, Control: "cap_enter",
			Status: StatusUnavailable, Detail: err.Error(),
		})
		return out
	}
	detail := "capability mode entered"
	if n := len(opts.AllowRootFDs); n > 0 {
		detail += "; allow-root directory fds=" + strconv.Itoa(n)
	} else if len(opts.AllowRoots) > 0 {
		detail += "; allow-roots paths set but no conferred directory fds"
	}
	out = append(out, Finding{
		ID: "APPLY-CAPSICUM", Platform: plat, Control: "cap_enter",
		Status: StatusAvailable, Detail: detail,
	})
	return out
}

// attachNoIPJail creates a non-persistent jail with IPv4/IPv6 disabled and
// attaches the current process (M3s). CapEnter alone does not deny AF_INET
// socket(); jail ip4/ip6=disable does. Caller must only invoke for roles that
// must not hold CapNetworkSockets (RequireApplyAvailable refuses Skipped).
func attachNoIPJail() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	name := fmt.Sprintf("integris-%d", os.Getpid())
	jid, err := jailSetAttachNoIP(name)
	if err != nil {
		return Finding{
			ID: "APPLY-JAIL", Platform: plat, Control: "jail_set_ip_disable",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	return Finding{
		ID: "APPLY-JAIL", Platform: plat, Control: "jail_set_ip_disable",
		Status: StatusAvailable,
		Detail: "jid=" + strconv.Itoa(jid) + " ip4=disable ip6=disable nopersist",
	}
}

func jailSetAttachNoIP(name string) (int, error) {
	// name/value pairs; booleans use a zero-length value (jail_set(2)).
	params := [][2]string{
		{"path", "/"},
		{"name", name},
		{"host.hostname", name},
		{"ip4", "disable"},
		{"ip6", "disable"},
		{"nopersist", ""},
	}
	bufs := make([][]byte, 0, len(params)*2)
	iov := make([]unix.Iovec, 0, len(params)*2)
	for _, kv := range params {
		kb := append([]byte(kv[0]), 0)
		bufs = append(bufs, kb)
		iov = append(iov, unix.Iovec{Base: &kb[0], Len: uint64(len(kb))})
		if kv[1] == "" {
			iov = append(iov, unix.Iovec{Base: nil, Len: 0})
			continue
		}
		vb := append([]byte(kv[1]), 0)
		bufs = append(bufs, vb)
		iov = append(iov, unix.Iovec{Base: &vb[0], Len: uint64(len(vb))})
	}
	_ = bufs // keep backing arrays live across the syscall
	r1, _, errno := unix.Syscall(
		unix.SYS_JAIL_SET,
		uintptr(unsafe.Pointer(&iov[0])),
		uintptr(len(iov)),
		uintptr(jailCreate|jailAttach),
	)
	if errno != 0 {
		return 0, errno
	}
	return int(r1), nil
}
