//! Issue #3865 (ADR-MCPS-016) — OS sandbox PROFILE for inner-server fs/network
//! containment, plus its FAIL-CLOSED platform gate.
//!
//! # What this module is — and is NOT
//!
//! [`SandboxProfile`] is the *declaration* of a containment policy for the inner
//! MCP server subprocess: a filesystem read-allowlist, a filesystem
//! write-allowlist, a network-egress policy, and a top-level mode. It is the
//! configuration surface and the fail-closed startup gate. **This module does NOT
//! itself perform the syscalls** — the actual kernel enforcement lives in the
//! Linux-only [`crate::sandbox_linux`] backend (issue #4039), reached through this
//! module's capability gate. On non-Linux platforms no kernel backend exists, so
//! enforcement is impossible and requesting it fails closed (see "Platform
//! matrix").
//!
//! Why a plain parent process cannot honestly enforce an fs/network allowlist:
//! the env-minimization, controlled working directory, and `setrlimit` ceilings
//! the proxy already applies ([`crate::inner_launch`], [`crate::rlimits`]) bound
//! what the child SEES and how much resource it may consume — they are explicitly
//! NOT a sandbox. Once the child is `exec`'d it runs with the proxy's OS
//! credentials and can open any path / connect to any socket those credentials
//! permit. Restricting that requires the KERNEL to mediate each `open`/`connect`
//! against a policy. There is no portable, config-only way to do this; it needs
//! per-OS kernel facilities.
//!
//! # Platform matrix (what CAN and CANNOT enforce this profile)
//!
//! * **Linux (kernel ≥ 5.13 for the relevant Landlock ABI):** ENFORCEABLE, and
//!   IMPLEMENTED (#4039) in [`crate::sandbox_linux`].
//!   - Filesystem allowlists: **Landlock** LSM — restrict the set of paths the
//!     child may read / write by installing a ruleset (built in the parent) and
//!     calling `restrict_self` in the child before `exec`.
//!   - Network egress: a **seccomp-bpf** filter that denies the `socket` /
//!     `connect` (and 32-bit `socketcall`) syscalls so the child cannot originate
//!     outbound connections; the denied syscalls return `EACCES` (a graceful
//!     errno) rather than killing the process.
//!   The install only happens on a capable kernel: [`backend_can_enforce`] runs a
//!   runtime Landlock-ABI probe, so a Linux kernel too old to enforce still fails
//!   closed instead of installing a no-op.
//!
//!   [`backend_can_enforce`]: SandboxProfile::backend_can_enforce
//! * **macOS / Windows / any non-Linux:** NOT ENFORCEABLE here. seccomp,
//!   Landlock, and Linux namespaces are Linux-kernel-only. macOS's own
//!   `sandbox_init(3)` (Seatbelt) is deprecated and not used here. On these
//!   platforms the profile can be DECLARED but never ENFORCED, so requesting
//!   enforcement must fail closed (refuse to start) rather than spawn the inner
//!   server unsandboxed while pretending otherwise.
//!
//! # Escape / bypass assumptions (the threat model, stated honestly)
//!
//! Even with the Linux backend enforcing, the containment this profile describes
//! is bounded — it is a real reduction in blast radius, not a perfect jail:
//!   * **seccomp filters SYSCALLS, not file paths.** A `connect`-denying filter
//!     stops new outbound sockets but does not, by itself, restrict which files
//!     `open` may reach; path restriction is Landlock's job. The two are
//!     complementary and BOTH are needed.
//!   * **Landlock needs a recent kernel** (≥ 5.13 for the base ABI; later ABIs
//!     for network/ioctl rules). On an older kernel the ruleset is unavailable —
//!     which is exactly why enforcement must be a fail-closed capability check,
//!     never a best-effort no-op.
//!   * **Already-open file descriptors survive.** Landlock restricts new path
//!     resolution; an fd the child inherits or opens before the ruleset is
//!     installed is not retroactively revoked. Ruleset installation must happen
//!     in the pre-`exec` window with a minimal inherited-fd set.
//!   * **TOCTOU.** Allowlist paths are policy strings; a path that is a symlink,
//!     or is swapped between check and use, can widen effective access. Paths
//!     should be canonicalized and the kernel ruleset, not a userspace check, is
//!     the authority.
//!   * **The inner can do anything the policy ALLOWS.** An allowlisted writable
//!     path is fully writable; `NetworkPolicy::Allow` is no network containment
//!     at all. The profile narrows, it does not eliminate.
//!
//! # Fail-closed posture (the load-bearing honesty property)
//!
//! If [`SandboxMode::Enforce`] is requested but the running platform/build cannot
//! actually enforce it, the proxy MUST refuse to start — it must NEVER spawn the
//! inner server unsandboxed while having been asked to sandbox it. That decision
//! is [`SandboxProfile::validate_platform`], checked at startup BEFORE any spawn,
//! mirroring [`crate::rlimits::RLimits::validate_platform`] and the
//! `--key-source env` / `--replay-cache shared` gates. On a capable Linux build
//! the gate PASSES (and [`crate::sandbox_linux`] enforces); on a Linux kernel too
//! old, or on any non-Linux platform (e.g. darwin), it fires and refuses to start.
//!
//! # The Linux enforcement backend (#4039, implemented)
//!
//! The kernel enforcement (Landlock fs rulesets + a seccomp-bpf egress filter,
//! installed as a `pre_exec` hook alongside the `setrlimit` hook) is implemented
//! in [`crate::sandbox_linux`] (Linux-only). It requires Linux + careful,
//! async-signal-safe syscall code. [`SandboxProfile::backend_can_enforce`] returns
//! `true` on a capable Linux build (gated on a runtime Landlock-ABI probe) and the
//! actual syscall sequence runs at the
//! [`crate::inner_launch::InnerLaunchConfig::apply_sandbox`] seam. It is Linux-only:
//! a non-Linux build excludes [`crate::sandbox_linux`] entirely and
//! `backend_can_enforce` returns `false`, so darwin/Windows still fail closed under
//! `Enforce`.

/// Top-level sandbox mode for the inner server.
///
/// Default is [`SandboxMode::Off`] — today's behavior exactly (no fs/network
/// containment; the existing env / working-dir / rlimit hardening still applies,
/// and the existing "NOT a sandbox" disclaimers remain accurate). [`Off`] never
/// triggers the fail-closed platform gate.
///
/// [`SandboxMode::Enforce`] REQUESTS real kernel containment. It is only honored
/// when the running platform/build can actually enforce it
/// ([`SandboxProfile::backend_can_enforce`]); otherwise startup is refused
/// (fail closed) rather than spawning the inner server unsandboxed.
///
/// [`Off`]: SandboxMode::Off
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    /// No fs/network containment (default). Existing behavior is unchanged.
    Off,
    /// Require real kernel containment of the inner server, or refuse to start.
    Enforce,
}

/// Network-egress policy for the inner server.
///
/// Default is [`NetworkPolicy::DenyAll`]: the inner server should originate NO
/// outbound network connections. The opposite, [`NetworkPolicy::Allow`], is no
/// network containment at all and is an explicit operator choice. (There is no
/// host/port allowlist in this profile — egress is all-or-nothing. On Linux,
/// `DenyAll` is enforced by a seccomp-bpf filter that denies the socket/connect
/// family ([`crate::sandbox_linux`]); a fine-grained per-host egress filter is a
/// possible later refinement, and declaring a granular policy that is not enforced
/// would overclaim.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// Deny all outbound network egress from the inner server (default).
    DenyAll,
    /// Allow outbound network egress (no network containment).
    Allow,
}

/// A declared OS-sandbox profile for the inner MCP server (issue #3865).
///
/// This is the CONFIGURATION + fail-closed gate, NOT the enforcement. See the
/// module docs for the platform matrix, escape/bypass assumptions, and why this
/// build deliberately ships no kernel enforcement. With the default
/// [`SandboxProfile::new`] (mode [`SandboxMode::Off`]) the profile is inert and
/// the proxy behaves exactly as before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxProfile {
    /// Top-level mode. [`SandboxMode::Off`] (default) = no containment;
    /// [`SandboxMode::Enforce`] = require kernel containment or refuse to start.
    pub mode: SandboxMode,
    /// Filesystem paths the inner server is allowed to READ (Landlock read
    /// allowlist, when enforced). Empty under `Enforce` means "read nothing
    /// outside the kernel's implicit minimum" — a deliberately tight default, not
    /// a silent widening. Each entry must be a non-empty path.
    pub fs_allow_read: Vec<String>,
    /// Filesystem paths the inner server is allowed to WRITE (Landlock write
    /// allowlist, when enforced). Same emptiness semantics as `fs_allow_read`.
    pub fs_allow_write: Vec<String>,
    /// Outbound network-egress policy. Defaults to [`NetworkPolicy::DenyAll`].
    pub network: NetworkPolicy,
}

impl Default for SandboxProfile {
    /// The inert secure default (see [`SandboxProfile::new`]).
    fn default() -> Self {
        SandboxProfile::new()
    }
}

impl SandboxProfile {
    /// The default profile: mode [`SandboxMode::Off`], empty fs allowlists,
    /// network [`NetworkPolicy::DenyAll`]. `Off` makes the profile inert, so the
    /// proxy's behavior is exactly today's; the `DenyAll` default is the
    /// safe-when-enforced posture, not something applied while `Off`.
    pub fn new() -> Self {
        SandboxProfile {
            mode: SandboxMode::Off,
            fs_allow_read: Vec::new(),
            fs_allow_write: Vec::new(),
            network: NetworkPolicy::DenyAll,
        }
    }

    /// Whether enforcement is requested (`mode == Enforce`).
    pub fn is_enforced(&self) -> bool {
        self.mode == SandboxMode::Enforce
    }

    /// Whether THIS build, on the platform it is running on, can ACTUALLY enforce
    /// kernel containment for the inner server.
    ///
    /// This is the single source of truth for the fail-closed gate. On a
    /// `target_os = "linux"` build it returns the result of a RUNTIME
    /// kernel-capability probe ([`crate::sandbox_linux::landlock_abi_is_enforceable`]):
    /// `true` only when the running kernel can FULLY enforce a Landlock ruleset at
    /// the required ABI ([`crate::sandbox_linux::REQUIRED_LANDLOCK_ABI`]), in which
    /// case the Landlock fs ruleset + seccomp-bpf egress filter are installed as a
    /// `pre_exec` hook at the
    /// [`crate::inner_launch::InnerLaunchConfig::apply_sandbox`] seam (issue #4039).
    /// On any non-Linux build it returns `false` (no kernel backend exists there).
    ///
    /// Keeping the gate keyed on a real capability — rather than merely on the
    /// target OS — means a Linux build whose kernel is too old (no Landlock, or a
    /// lower ABI than required) ALSO fails closed, instead of installing a ruleset
    /// that silently does nothing.
    #[cfg(target_os = "linux")]
    pub fn backend_can_enforce() -> bool {
        // Linux: probe the running kernel for Landlock support at the required ABI.
        // A kernel without Landlock (or too old) reports `false`, so `Enforce`
        // fails closed instead of installing a no-op ruleset.
        crate::sandbox_linux::landlock_abi_is_enforceable()
    }

    /// Non-Linux: no kernel-enforcement backend exists (seccomp/Landlock are
    /// Linux-only), so enforcement is never possible and `Enforce` always fails
    /// closed via [`SandboxProfile::validate_platform`].
    #[cfg(not(target_os = "linux"))]
    pub fn backend_can_enforce() -> bool {
        false
    }

    /// Validate that this profile can be honored on the current platform/build,
    /// failing CLOSED. Call at startup (config validation) so a request for
    /// containment that cannot be enforced refuses the proxy BEFORE any inner
    /// server is spawned — never spawning it unsandboxed while having been asked
    /// to sandbox it. Mirrors [`crate::rlimits::RLimits::validate_platform`] and
    /// the `--key-source env` / `--replay-cache shared` fail-closed gates.
    ///
    /// * [`SandboxMode::Off`] → always `Ok` (the profile is inert; behavior is
    ///   unchanged and the empty-allowlist / `DenyAll` fields are not applied).
    /// * [`SandboxMode::Enforce`] → `Ok` only if [`backend_can_enforce`] AND the
    ///   allowlists are well-formed; otherwise `Err` with a precise reason. On a
    ///   non-Linux build (e.g. darwin) `backend_can_enforce` is always `false`, so
    ///   `Enforce` errors here unconditionally; on Linux it passes only when the
    ///   running kernel can fully enforce Landlock at the required ABI.
    ///
    /// [`backend_can_enforce`]: SandboxProfile::backend_can_enforce
    pub fn validate_platform(&self) -> Result<(), String> {
        if !self.is_enforced() {
            return Ok(());
        }
        // Reject a malformed allowlist before the capability check so a typo can
        // never silently widen (or, here, be masked by) the gate. An empty path
        // segment is an error, mirroring `--client-crl` / `--inner-fs-allow-*`.
        self.validate_allowlists()?;
        if !SandboxProfile::backend_can_enforce() {
            return Err(
                "sandbox mode 'enforce' requested but this platform/kernel cannot enforce kernel \
                 containment (the Linux Landlock/seccomp backend is unavailable here: non-Linux \
                 platform, or a Linux kernel without Landlock at the required ABI); refusing to \
                 start the inner server unsandboxed — see #3865 / #4039"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Validate that every allowlist entry is a non-empty path. An empty entry is
    /// an error — a trailing comma or stray separator must NEVER be interpreted as
    /// "no restriction" / a silent widening of access. Pure and independent of the
    /// mode so it is black-box testable.
    pub fn validate_allowlists(&self) -> Result<(), String> {
        for path in &self.fs_allow_read {
            if path.is_empty() {
                return Err(
                    "--inner-fs-allow-read contains an empty path segment (a typo must not \
                     silently widen filesystem access)"
                        .to_string(),
                );
            }
        }
        for path in &self.fs_allow_write {
            if path.is_empty() {
                return Err(
                    "--inner-fs-allow-write contains an empty path segment (a typo must not \
                     silently widen filesystem access)"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::NetworkPolicy;
    use super::SandboxMode;
    use super::SandboxProfile;

    #[test]
    fn default_is_off_and_deny_all() {
        let profile = SandboxProfile::new();
        assert_eq!(profile.mode, SandboxMode::Off);
        assert_eq!(profile.network, NetworkPolicy::DenyAll, "egress default must be DenyAll");
        assert!(profile.fs_allow_read.is_empty());
        assert!(profile.fs_allow_write.is_empty());
        assert!(!profile.is_enforced());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn backend_cannot_enforce_on_non_linux() {
        // On a non-Linux build (e.g. darwin) there is no kernel enforcement
        // backend; the gate must rely on that and always refuse Enforce.
        assert!(
            !SandboxProfile::backend_can_enforce(),
            "non-Linux builds ship no kernel enforcement backend; the gate must rely on that"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn backend_capability_matches_runtime_probe_on_linux() {
        // On Linux the capability is a runtime kernel probe (#4039). We do not
        // assert a fixed value (the CI runner may or may not have Landlock); we
        // assert the gate's decision agrees with the probe the code keys on.
        assert_eq!(
            SandboxProfile::backend_can_enforce(),
            crate::sandbox_linux::landlock_abi_is_enforceable(),
            "backend_can_enforce must be exactly the Landlock-ABI runtime probe"
        );
    }

    #[test]
    fn off_mode_never_trips_the_gate() {
        // The default (Off) profile must validate cleanly on every platform — the
        // gate is for Enforce only, so today's behavior is unchanged.
        assert!(SandboxProfile::new().validate_platform().is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn enforce_fails_closed_on_non_linux() {
        // On darwin (and any non-Linux build) there is no kernel backend, so
        // requesting enforcement MUST refuse with the documented error — the
        // load-bearing honesty gate. This asserts the REAL gate via the same
        // capability the code uses.
        let profile = SandboxProfile {
            mode: SandboxMode::Enforce,
            ..SandboxProfile::new()
        };
        let err = profile
            .validate_platform()
            .expect_err("enforce without an enforcement backend must fail closed");
        assert!(err.contains("enforce"), "got: {err}");
        assert!(err.contains("refusing to start"), "got: {err}");
        assert!(err.contains("#3865"), "error must point at the follow-up: {err}");
        // The gate decision must agree with the capability probe (no enforcement
        // backend on non-Linux → enforce always refused here).
        assert!(!SandboxProfile::backend_can_enforce());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enforce_gate_tracks_capability_on_linux() {
        // On Linux the gate's decision must agree with the runtime capability
        // probe (#4039): if the kernel can enforce, validate passes; otherwise it
        // fails closed with the documented error. We do not assume the runner's
        // kernel either way.
        let profile = SandboxProfile {
            mode: SandboxMode::Enforce,
            ..SandboxProfile::new()
        };
        let result = profile.validate_platform();
        if SandboxProfile::backend_can_enforce() {
            assert!(
                result.is_ok(),
                "a kernel that can enforce must pass the gate: {result:?}"
            );
        } else {
            let err = result.expect_err("an unenforceable kernel must fail closed");
            assert!(err.contains("refusing to start"), "got: {err}");
        }
    }

    #[test]
    fn enforce_rejects_empty_allowlist_segment_before_widening() {
        // A typo'd (empty) allowlist entry must be an error, not a silent widening.
        let profile = SandboxProfile {
            mode: SandboxMode::Enforce,
            fs_allow_read: vec!["/etc/inner".to_string(), String::new()],
            ..SandboxProfile::new()
        };
        let err = profile
            .validate_platform()
            .expect_err("empty allowlist segment must fail closed");
        assert!(err.contains("empty path segment"), "got: {err}");
    }

    #[test]
    fn write_allowlist_empty_segment_is_rejected() {
        let profile = SandboxProfile {
            mode: SandboxMode::Enforce,
            fs_allow_write: vec![String::new()],
            ..SandboxProfile::new()
        };
        let err = profile
            .validate_allowlists()
            .expect_err("empty write-allowlist segment must fail closed");
        assert!(err.contains("--inner-fs-allow-write"), "got: {err}");
    }

    #[test]
    fn well_formed_allowlists_pass_segment_validation() {
        let profile = SandboxProfile {
            mode: SandboxMode::Enforce,
            fs_allow_read: vec!["/etc/inner".to_string(), "/var/data".to_string()],
            fs_allow_write: vec!["/tmp/inner".to_string()],
            ..SandboxProfile::new()
        };
        assert!(profile.validate_allowlists().is_ok());
    }

    #[test]
    fn network_policy_allow_flips_default() {
        let profile = SandboxProfile {
            network: NetworkPolicy::Allow,
            ..SandboxProfile::new()
        };
        assert_eq!(profile.network, NetworkPolicy::Allow);
    }
}
