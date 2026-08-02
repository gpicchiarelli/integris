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

// FreeBSD sys/jail.h constants for jail_set(2).
const (
	jailCreate     = 0x01
	jailAttach     = 0x04
	jailSysDisable = 0 // JAIL_SYS_DISABLE — ip4/ip6 enum value
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
			Status: StatusAvailable, Detail: "jail_set CREATE|ATTACH path=/ ip4/ip6=JAIL_SYS_DISABLE for !network roles",
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
// socket(); jail ip4/ip6=JAIL_SYS_DISABLE does. Caller must only invoke for
// roles that must not hold CapNetworkSockets (RequireApplyAvailable refuses
// Skipped).
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
		Detail: "jid=" + strconv.Itoa(jid) + " ip4=disable ip6=disable",
	}
}

// jailSetAttachNoIP calls jail_set(JAIL_CREATE|JAIL_ATTACH) with path=/, a
// unique name, and ip4/ip6 set to JAIL_SYS_DISABLE (int, not the jail(8)
// string form — raw jail_set expects sizeof(int) enum values).
func jailSetAttachNoIP(name string) (int, error) {
	pathKey := append([]byte("path"), 0)
	pathVal := append([]byte("/"), 0)
	nameKey := append([]byte("name"), 0)
	nameVal := append([]byte(name), 0)
	ip4Key := append([]byte("ip4"), 0)
	ip6Key := append([]byte("ip6"), 0)
	ip4Val := int32(jailSysDisable)
	ip6Val := int32(jailSysDisable)

	iov := make([]unix.Iovec, 8)
	keep := []any{pathKey, pathVal, nameKey, nameVal, ip4Key, ip6Key, &ip4Val, &ip6Val}

	setStr := func(i int, b []byte) {
		iov[i].Base = &b[0]
		iov[i].SetLen(len(b))
	}
	setInt := func(i int, p *int32) {
		iov[i].Base = (*byte)(unsafe.Pointer(p))
		iov[i].SetLen(int(unsafe.Sizeof(*p)))
	}
	setStr(0, pathKey)
	setStr(1, pathVal)
	setStr(2, nameKey)
	setStr(3, nameVal)
	setStr(4, ip4Key)
	setInt(5, &ip4Val)
	setStr(6, ip6Key)
	setInt(7, &ip6Val)

	r1, _, errno := unix.Syscall( // nosemgrep: go.lang.security.audit.unsafe.use-of-unsafe-block
		unix.SYS_JAIL_SET,
		uintptr(unsafe.Pointer(&iov[0])),
		uintptr(len(iov)),
		uintptr(jailCreate|jailAttach),
	)
	runtime.KeepAlive(keep)
	runtime.KeepAlive(iov)
	if errno != 0 {
		return 0, errno
	}
	return int(r1), nil
}
