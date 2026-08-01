# Platform confinement matrix

Status: **Design target; empirical evidence pending**

There is no weak portable sandbox abstraction. Each port must implement and test
the strongest stable native primitives available for its declared minimum OS.
Missing required confinement causes startup refusal unless an explicit,
time-bounded development-only policy is selected; such mode cannot create a
release artifact or claim production support.

| Platform | Required composition | Capability discovery | Known residual risk |
|---|---|---|---|
| OpenBSD | dedicated account, pre-opened descriptors, `unveil`, then locked `unveil`, monotonically reduced `pledge` promises | startup self-test and child-specific negative probes | syscall categories remain broader than individual object capabilities |
| FreeBSD | dedicated account, pre-opened capability descriptors, `cap_rights_limit`, Capsicum capability mode, helpers for justified global lookup | rights query plus negative probes after `cap_enter` | kernel and helper compromise; ioctl rights require explicit review |
| Linux | dedicated account, `no_new_privs`, empty capability sets, Landlock, seccomp-BPF, service-manager hardening, optional namespaces and administrator MAC | Landlock ABI and seccomp architecture check before policy installation | Landlock ABI/filesystem variation; seccomp filters syscalls, not object semantics |
| macOS | dedicated launchd identities where deployable, explicit inherited descriptors, Keychain identity handles, code signing, Hardened Runtime, notarized installer; App Sandbox only where technically compatible; engineering children apply Seatbelt `sandbox_init` (cgo) | signature/entitlement inspection, Seatbelt apply probe, and runtime negative probes | no claimed equivalence to capability mode; Seatbelt ≠ App Sandbox; user-data consent and sandbox behavior vary by deployment |

For every component and OS release, evidence records the exact kernel/OS version,
policy, allowed operation set, denied probes, and discovered gaps. Documentation
must distinguish kernel-enforced, service-manager-enforced, discretionary, and
operational controls.

Engineering scaffold: `internal/confine` probes and applies best-effort child
confinement (`ApplyEngineeringOpts(role, opts)`: Linux Landlock with optional
path_beneath allow-roots for Apply/Index + `no_new_privs` + seccomp denylist;
OpenBSD role-parameterized `pledge`/`unveil` allow-roots; FreeBSD
`cap_rights_limit` then `cap_enter` (fd-only); Darwin Seatbelt with deny ambient
path read/write except EvalSymlinks'd allow-roots, and `deny network*` unless
net role). Role stubs report `NEG-FS-OPEN`, `NEG-FS-READ`, `NEG-FS-PATH`,
`NEG-FS-WRITE`, `NEG-EXEC`, `NEG-PTRACE`, and `NEG-ROLE-NET`. Provisional
session AEAD is draft [IP-C-0002](ip/IP-C-0002-session-aead.md). Dedicated
accounts and release-mode launch remain open.

## Primary references

- OpenBSD `pledge(2)` and `unveil(2)`: https://man.openbsd.org/pledge.2 and https://man.openbsd.org/unveil.2
- FreeBSD Capsicum: https://man.freebsd.org/cgi/man.cgi?query=cap_enter&sektion=2
- Linux Landlock and seccomp: https://docs.kernel.org/userspace-api/landlock.html and https://docs.kernel.org/userspace-api/seccomp_filter.html
- Apple platform security: https://developer.apple.com/documentation/security
