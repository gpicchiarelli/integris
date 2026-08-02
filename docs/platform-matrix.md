# Platform confinement matrix

Status: **Design target; empirical evidence pending**

There is no weak portable sandbox abstraction. Each port must implement and test
the strongest stable native primitives available for its declared minimum OS.
Missing required confinement causes startup refusal unless an explicit,
time-bounded development-only policy is selected; such mode cannot create a
release artifact or claim production support.

The same rule applies beyond confinement: per
[platform-optimization.md](specifications/platform-optimization.md) and
**INT-IC4-0001**, every port **MUST** use all qualifying stable native
optimizations (I/O, cloning, notification, durability, confinement). Portable
lowest-common-denominator paths are degraded mode only, never the sole release
path on a capable platform.

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
`cap_rights_limit` then `cap_enter` with conferred allow-root directory FDs
for Apply/Index/Journal/Audit (M3c product claim); Darwin Seatbelt with deny
ambient path read/write except EvalSymlinks'd allow-roots, and `deny network*`
unless net role). Role stubs report `NEG-CAP-MODE` (FreeBSD `cap_getmode`),
`NEG-FS-OPEN`, `NEG-FS-READ`, `NEG-FS-PATH`, `NEG-FS-WRITE`, `NEG-EXEC`,
`NEG-PTRACE`, and `NEG-ROLE-NET`. Product children under
`INTEGRIS_LAUNCH_MODE=release` also fail closed unless FreeBSD capability mode
is confirmed (`RequireCapModeAvailable`, M3m) and Capsicum
`cap_rights_limit` findings are Available or Skipped
(`RequireAllowRootLimitFinding` M3n, `RequireConferredLimitFinding` M3o) and
ambient path open is denied (`RequireAmbientFSReadDenied`, M3q).
On Linux/Darwin/OpenBSD, release mode also fails closed unless ambient
AF_INET is denied for non-network roles (`RequireAmbientRoleNetDenied`, M4d).
FreeBSD CapEnter leaves ambient AF_INET possible (`NEG-ROLE-NET` residual,
M3s; jail ip-disable is not used with allow-root CapRightsLimit;
`RequireAmbientRoleNetDenied` is a no-op on FreeBSD). FreeBSD
supervised StrictLaunch push first cut under CapEnter is covered by M3p;
StrictLaunch CapEnter RestartOne first cut by M3r; CapEnter parser-down
RestartOne by M3u; CapEnter auth-primary RestartOne by M3v; CapEnter M2j
auth ExtraPeer RestartOne by M3w; CapEnter M2j audit ExtraPeer RestartOne by
M3x; CapEnter M2j peer-key Once push by M3y; CapEnter M2j apply RestartOne by
M3z. FreeBSD CapEnter M2j parser-down RestartOne by M4a; CapEnter M2j peer
deny/admit by M4b. FreeBSD sealed MAC key FD
(`shm_open2`+`F_ADD_SEALS`) landed in M3t; Darwin/OpenBSD anon-unlinked key FD
residual documented in M4c (`DISC-KEY-FD` Unavailable). Darwin StrictLaunch
Seatbelt push first cut landed in M4e; Darwin StrictLaunch Seatbelt
RestartOne apply first cut landed in M4f; Darwin StrictLaunch Seatbelt
parser-down RestartOne landed in M4g; Darwin StrictLaunch Seatbelt
auth-primary RestartOne landed in M4h. Provisional
session AEAD is draft [IP-C-0002](ip/IP-C-0002-session-aead.md). Dedicated
accounts remain open.

## Primary references

- OpenBSD `pledge(2)` and `unveil(2)`: https://man.openbsd.org/pledge.2 and https://man.openbsd.org/unveil.2
- FreeBSD Capsicum: https://man.freebsd.org/cgi/man.cgi?query=cap_enter&sektion=2
- Linux Landlock and seccomp: https://docs.kernel.org/userspace-api/landlock.html and https://docs.kernel.org/userspace-api/seccomp_filter.html
- Apple platform security: https://developer.apple.com/documentation/security
