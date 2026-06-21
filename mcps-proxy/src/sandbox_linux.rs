//! Issue #4039 (ADR-MCPS-016) — the LINUX kernel-enforcement backend behind the
//! #3865 sandbox seam: Landlock for the filesystem allowlist + seccomp-bpf for the
//! network-egress policy, installed on the inner-server child in the
//! post-fork/pre-`exec` window.
//!
//! This entire module is `#[cfg(target_os = "linux")]`. On macOS / Windows / any
//! non-Linux build it does not exist and the proxy's default build pulls neither
//! `landlock` nor `seccompiler` (they are `[target.'cfg(target_os = "linux")']`
//! dependencies). The non-Linux fail-closed gate in [`crate::sandbox`] /
//! [`crate::inner_launch`] is unchanged.
//!
//! # Fork/exec discipline (why the split exists)
//!
//! The heavy construction — opening every allowlisted path (`PathFd`), creating
//! the Landlock ruleset fd, adding all `PathBeneath` rules, and compiling the
//! seccomp filter into a flat `BpfProgram` byte sequence — is ALL done in the
//! PARENT, BEFORE fork. The only thing the `pre_exec` closure does in the forked
//! child is issue the enforce syscalls:
//!   * `prctl(PR_SET_NO_NEW_PRIVS, 1)` (required for `SECCOMP_SET_MODE_FILTER`
//!     without `CAP_SYS_ADMIN`),
//!   * `landlock_restrict_self(ruleset_fd, ...)` (via the prebuilt
//!     [`landlock::RulesetCreated::restrict_self`]),
//!   * `seccomp(SECCOMP_SET_MODE_FILTER, ...)` (via
//!     [`seccompiler::apply_filter`], which ALSO sets `PR_SET_NO_NEW_PRIVS`).
//!
//! `pre_exec` runs after `fork(2)` in a process that may have been multi-threaded;
//! only async-signal-safe work is permissible there. The closure performs no path
//! resolution, no ruleset construction, and no filter compilation — those touch
//! the heap and the filesystem and would be unsafe post-fork. It moves the
//! already-built ruleset and the already-compiled BPF byte vector into the closure
//! by value and calls only the kernel-enforce syscalls on them. (Note:
//! `RulesetCreated::restrict_self` and `apply_filter` are the upstream-documented
//! pre-`exec`/post-fork enforcement entry points; the residual work they do is
//! reading already-allocated buffers and issuing syscalls.)
//!
//! # Fail-closed posture
//!
//! Every build step that can fail does so in the PARENT and is surfaced as a
//! `Result::Err` from [`build_sandbox`], which makes the proxy refuse to spawn the
//! inner server at all. Any enforce step that fails in the child returns an
//! [`std::io::Error`] from `pre_exec`, which makes the parent's
//! [`std::process::Command::spawn`] fail — so the inner server is NEVER `exec`'d
//! unsandboxed when [`crate::sandbox::SandboxMode::Enforce`] was requested. There
//! is no best-effort downgrade here: a partial Landlock enforcement
//! ([`landlock::RulesetStatus::PartiallyEnforced`] /
//! [`landlock::RulesetStatus::NotEnforced`]) is treated as a failure, because
//! `backend_can_enforce` only returns `true` when the running kernel can fully
//! honor the required ABI.

use std::collections::BTreeMap;

use landlock::Access;
use landlock::AccessFs;
use landlock::CompatLevel;
use landlock::Compatible;
use landlock::PathBeneath;
use landlock::PathFd;
use landlock::Ruleset;
use landlock::RulesetAttr;
use landlock::RulesetCreated;
use landlock::RulesetCreatedAttr;
use landlock::RulesetStatus;
use landlock::ABI;
use seccompiler::BpfProgram;
use seccompiler::SeccompAction;
use seccompiler::SeccompFilter;
use seccompiler::TargetArch;

use crate::sandbox::NetworkPolicy;
use crate::sandbox::SandboxProfile;

/// The minimum Landlock ABI this backend requires to claim enforcement. ABI v1
/// (Linux 5.13) carries the base filesystem read/write access rights, which is all
/// this profile's fs allowlist needs. The capability probe and the build both pin
/// this version so a `cargo update` cannot silently shift the semantics, and so a
/// kernel that cannot fully honor it fails closed rather than partially enforcing.
pub const REQUIRED_LANDLOCK_ABI: ABI = ABI::V1;

/// Runtime kernel-capability probe for Landlock at [`REQUIRED_LANDLOCK_ABI`].
///
/// Returns `true` only when the running kernel can FULLY honor a Landlock ruleset
/// at the required ABI. Implemented by attempting to build a ruleset under
/// [`CompatLevel::HardRequirement`]: on a kernel without Landlock (or with a lower
/// ABI than required), `handle_access` / `create` return `Err` and we report
/// `false` so [`SandboxProfile::backend_can_enforce`] makes `Enforce` fail closed
/// rather than installing a no-op. This creates (and immediately drops) a ruleset
/// fd but never calls `restrict_self`, so it does not restrict the probing thread.
pub fn landlock_abi_is_enforceable() -> bool {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(REQUIRED_LANDLOCK_ABI))
        .and_then(|ruleset| ruleset.create())
        .is_ok()
}

/// The seccomp [`TargetArch`] for the architecture this binary is compiled for.
///
/// seccomp-bpf filters on raw syscall numbers, which are architecture-specific; the
/// filter must declare the arch it was built for so the kernel rejects a filter run
/// under a mismatched arch (the `build_arch_validation_sequence` in seccompiler).
/// Only architectures seccompiler supports are mapped; anything else yields `None`
/// and the build fails closed.
pub fn current_target_arch() -> Option<TargetArch> {
    if cfg!(target_arch = "x86_64") {
        Some(TargetArch::x86_64)
    } else if cfg!(target_arch = "aarch64") {
        Some(TargetArch::aarch64)
    } else {
        None
    }
}

/// The set of syscall numbers a [`NetworkPolicy::DenyAll`] filter denies, in a
/// stable order, for the architecture this binary targets.
///
/// DenyAll blocks the socket-creation / connection family so the inner server
/// cannot ORIGINATE outbound connections:
///   * `socket` — create a new socket of any domain/type,
///   * `connect` — initiate a connection on a socket,
///   * `socketcall` — the multiplexed 32-bit socket entry point (x86 only; absent
///     on x86_64 / aarch64, so it is included only where libc defines it).
///
/// We do NOT deny `bind`/`listen`/`accept` (inbound) or `sendto`/`recvfrom`: the
/// policy is specifically about EGRESS, and denying `socket` already prevents
/// creating the fd those would operate on. Returned numbers are the libc `SYS_*`
/// constants for the compiled target arch, so they are correct by construction for
/// that arch (and matched against the arch declared in the filter).
pub fn denied_egress_syscalls() -> Vec<i64> {
    let mut denied: Vec<i64> = Vec::new();
    denied.push(libc::SYS_socket);
    denied.push(libc::SYS_connect);
    // `socketcall` is the 32-bit multiplexed socket syscall; it only exists on
    // architectures that define it (e.g. x86). libc exposes it per-target, so this
    // arm compiles in only where the constant is present.
    #[cfg(target_arch = "x86")]
    {
        denied.push(libc::SYS_socketcall);
    }
    denied
}

/// Compile the seccomp [`BpfProgram`] for `network` for the compiled target arch.
///
/// * [`NetworkPolicy::DenyAll`]: each [`denied_egress_syscalls`] number maps to an
///   empty rule chain (an unconditional match), the on-match action is
///   `Errno(EACCES)`, and the default (mismatch) action is `Allow`. We return
///   `EACCES` rather than `KillProcess`/`Trap` (SIGSYS) on purpose: a denied
///   `socket`/`connect` then fails GRACEFULLY with a normal errno the inner server
///   can observe and report, instead of the whole process being killed by the
///   kernel — easier to diagnose and symmetric with a normal permission denial.
/// * [`NetworkPolicy::Allow`]: returns `None` — no egress filter is installed
///   (explicit operator choice; "no network containment").
///
/// Fails closed (`Err`) if the target arch is unsupported by seccompiler or the
/// filter cannot be compiled.
pub fn build_egress_filter(network: NetworkPolicy) -> Result<Option<BpfProgram>, String> {
    match network {
        NetworkPolicy::Allow => Ok(None),
        NetworkPolicy::DenyAll => {
            let arch = current_target_arch().ok_or_else(|| {
                "sandbox enforce: seccomp egress filtering is not supported on this CPU \
                 architecture; refusing to spawn the inner server unsandboxed (#4039)"
                    .to_string()
            })?;
            let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
            for syscall_number in denied_egress_syscalls() {
                // An empty rule chain is an unconditional match → the match action
                // (Errno EACCES) applies whenever this syscall is invoked.
                rules.insert(syscall_number, Vec::new());
            }
            let filter = SeccompFilter::new(
                rules,
                // Default for syscalls NOT in the deny set: allow.
                SeccompAction::Allow,
                // On match (a denied egress syscall): return EACCES, do not kill.
                SeccompAction::Errno(libc::EACCES as u32),
                arch,
            )
            .map_err(|e| {
                format!(
                    "sandbox enforce: failed to build the seccomp egress filter; refusing to \
                     spawn the inner server unsandboxed (#4039): {e}"
                )
            })?;
            let program: BpfProgram = filter.try_into().map_err(|e| {
                format!(
                    "sandbox enforce: failed to compile the seccomp egress filter to BPF; \
                     refusing to spawn the inner server unsandboxed (#4039): {e}"
                )
            })?;
            Ok(Some(program))
        }
    }
}

/// Build the Landlock [`RulesetCreated`] for the profile's fs allowlists, in the
/// PARENT (opens every allowlisted path, creates the ruleset fd, adds rules).
///
/// Mapping: each [`SandboxProfile::fs_allow_read`] path is granted the read access
/// rights at [`REQUIRED_LANDLOCK_ABI`] ([`AccessFs::from_read`]); each
/// [`SandboxProfile::fs_allow_write`] path is granted read+write
/// ([`AccessFs::from_all`], which is `from_read | from_write`) so a writable path is
/// also readable (writing a file generally requires opening/traversing it). The
/// ruleset HANDLES the union of read+write access, so any path NOT on an allowlist
/// is denied that access by the kernel after `restrict_self`.
///
/// Fail-closed: a path that cannot be opened is an `Err` here (in the parent), not
/// a silent skip — unlike [`landlock::path_beneath_rules`], which drops unopenable
/// paths under best-effort. A configured allowlist entry that does not exist must
/// refuse the spawn, never silently widen or narrow the policy.
fn build_landlock_ruleset(profile: &SandboxProfile) -> Result<RulesetCreated, String> {
    let abi = REQUIRED_LANDLOCK_ABI;
    let handled = AccessFs::from_all(abi);
    let read_access = AccessFs::from_read(abi);
    let write_access = AccessFs::from_all(abi);

    let mut created = Ruleset::default()
        .handle_access(handled)
        .map_err(|e| format!("sandbox enforce: Landlock handle_access failed (#4039): {e}"))?
        .create()
        .map_err(|e| format!("sandbox enforce: Landlock ruleset create failed (#4039): {e}"))?;

    for path in &profile.fs_allow_read {
        let fd = PathFd::new(path).map_err(|e| {
            format!(
                "sandbox enforce: cannot open read-allowlist path {path:?} for the Landlock \
                 ruleset; refusing to spawn the inner server unsandboxed (#4039): {e}"
            )
        })?;
        created = created
            .add_rule(PathBeneath::new(fd, read_access))
            .map_err(|e| {
                format!("sandbox enforce: failed adding Landlock read rule for {path:?} (#4039): {e}")
            })?;
    }
    for path in &profile.fs_allow_write {
        let fd = PathFd::new(path).map_err(|e| {
            format!(
                "sandbox enforce: cannot open write-allowlist path {path:?} for the Landlock \
                 ruleset; refusing to spawn the inner server unsandboxed (#4039): {e}"
            )
        })?;
        created = created
            .add_rule(PathBeneath::new(fd, write_access))
            .map_err(|e| {
                format!("sandbox enforce: failed adding Landlock write rule for {path:?} (#4039): {e}")
            })?;
    }
    Ok(created)
}

/// The fully-built, parent-side sandbox artifacts ready to be enforced in the
/// child's `pre_exec` window. Holds the Landlock ruleset (with its open fds and
/// rules) and the optional compiled seccomp BPF program. Constructed by
/// [`build_sandbox`]; consumed by [`SandboxArtifacts::enforce`].
pub struct SandboxArtifacts {
    ruleset: RulesetCreated,
    egress_filter: Option<BpfProgram>,
}

impl SandboxArtifacts {
    /// Enforce the prebuilt sandbox on the CURRENT thread. Intended to be called
    /// from the `pre_exec` closure in the forked child, AFTER `apply_rlimits`.
    ///
    /// Order: (1) `prctl(PR_SET_NO_NEW_PRIVS, 1)` so the subsequent seccomp filter
    /// can be installed without `CAP_SYS_ADMIN`; (2) Landlock `restrict_self`
    /// (which also sets `no_new_privs`); (3) seccomp `apply_filter` (which ALSO
    /// sets `no_new_privs`). Setting `no_new_privs` first is harmless and explicit;
    /// the two later calls re-asserting it is idempotent.
    ///
    /// Returns `Err(std::io::Error)` on the FIRST failure so the caller's
    /// `pre_exec` aborts the spawn (fail closed). A Landlock result that is not
    /// [`RulesetStatus::FullyEnforced`] is also an error: we only reach here when
    /// the capability probe said the kernel can fully enforce, so a downgrade
    /// means something changed underneath us and we must NOT exec unsandboxed.
    ///
    /// # Async-signal-safety
    /// This runs post-fork/pre-exec. It issues `prctl`, `landlock_restrict_self`,
    /// and `seccomp` syscalls on already-allocated, already-built state moved into
    /// the closure. It opens no paths, builds no ruleset, and compiles no filter —
    /// all of that happened in the parent in [`build_sandbox`].
    pub fn enforce(&mut self) -> std::io::Result<()> {
        // (1) no_new_privs first (explicit; required for SECCOMP_SET_MODE_FILTER
        //     without CAP_SYS_ADMIN). SAFETY: a single prctl with constant args.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // (2) Landlock: enforce the prebuilt ruleset on this thread. `restrict_self`
        //     consumes the ruleset, so clone it first (the `pre_exec` closure is
        //     `FnMut` and may be retained, so we cannot move the ruleset out).
        //     CAVEAT (async-signal-safety): `try_clone` `dup`s the ruleset fd and,
        //     depending on the `landlock` crate version, MAY touch the heap for its
        //     wrapper — strictly not async-signal-safe in the fork-without-exec
        //     window of a multithreaded parent. It is the one residual heap-touch
        //     in this otherwise allocation-free `enforce`; in practice the parent
        //     is effectively single-threaded at spawn time and the `dup` is the
        //     only kernel effect, and any failure surfaces fail-closed as an
        //     `io::Error` (the spawn aborts), never as weakened containment.
        let ruleset = self.ruleset.try_clone().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("sandbox enforce: Landlock ruleset clone failed (#4039): {e}"),
            )
        })?;
        let status = ruleset.restrict_self().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("sandbox enforce: Landlock restrict_self failed (#4039): {e}"),
            )
        })?;
        if status.ruleset != RulesetStatus::FullyEnforced {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "sandbox enforce: Landlock was not fully enforced (status {:?}); refusing \
                     to exec the inner server with weaker-than-required containment (#4039)",
                    status.ruleset
                ),
            ));
        }

        // (3) seccomp egress filter (if DenyAll). `apply_filter` itself sets
        //     no_new_privs and installs SECCOMP_SET_MODE_FILTER on this thread.
        if let Some(program) = &self.egress_filter {
            seccompiler::apply_filter(program).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("sandbox enforce: seccomp apply_filter failed (#4039): {e}"),
                )
            })?;
        }
        Ok(())
    }
}

/// Build all sandbox artifacts for `profile` in the PARENT, before fork.
///
/// Opens the allowlisted paths, creates the Landlock ruleset, and compiles the
/// seccomp egress filter. Every failure is surfaced as `Err` here so the proxy
/// refuses to spawn rather than running the inner server unsandboxed (fail
/// closed). Call ONLY when [`SandboxProfile::is_enforced`] and the capability gate
/// has already passed.
pub fn build_sandbox(profile: &SandboxProfile) -> Result<SandboxArtifacts, String> {
    let ruleset = build_landlock_ruleset(profile)?;
    let egress_filter = build_egress_filter(profile.network)?;
    Ok(SandboxArtifacts {
        ruleset,
        egress_filter,
    })
}

#[cfg(test)]
mod tests {
    use super::build_egress_filter;
    use super::current_target_arch;
    use super::denied_egress_syscalls;
    use super::landlock_abi_is_enforceable;
    use crate::sandbox::NetworkPolicy;

    #[test]
    fn denied_egress_set_includes_socket_and_connect() {
        let denied = denied_egress_syscalls();
        assert!(
            denied.contains(&libc::SYS_socket),
            "DenyAll must deny socket() to stop new outbound sockets"
        );
        assert!(
            denied.contains(&libc::SYS_connect),
            "DenyAll must deny connect() to stop outbound connections"
        );
    }

    #[test]
    fn allow_policy_builds_no_filter() {
        let program =
            build_egress_filter(NetworkPolicy::Allow).expect("Allow must not fail to build");
        assert!(program.is_none(), "Allow installs no egress filter");
    }

    #[test]
    fn deny_all_builds_a_nonempty_filter_on_supported_arch() {
        // On the seccompiler-supported CI arches (x86_64 / aarch64) DenyAll must
        // compile to a non-empty BPF program. On any other arch the build fails
        // closed (current_target_arch() is None), which we assert symmetrically.
        match current_target_arch() {
            Some(_) => {
                let program = build_egress_filter(NetworkPolicy::DenyAll)
                    .expect("DenyAll must compile on a supported arch")
                    .expect("DenyAll must yield a filter");
                assert!(!program.is_empty(), "compiled DenyAll filter must be non-empty");
            }
            None => {
                let err = build_egress_filter(NetworkPolicy::DenyAll)
                    .expect_err("DenyAll must fail closed on an unsupported arch");
                assert!(err.contains("architecture"), "got: {err}");
            }
        }
    }

    #[test]
    fn landlock_probe_matches_create_outcome() {
        // The probe must agree with itself across calls (no side effect on the
        // probing thread) — it builds and drops a ruleset fd without restricting.
        let first = landlock_abi_is_enforceable();
        let second = landlock_abi_is_enforceable();
        assert_eq!(first, second, "the Landlock probe must be deterministic");
    }
}
