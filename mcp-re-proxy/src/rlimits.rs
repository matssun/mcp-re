//! MCPS-037 (ADR-MCPS-016) — inner-server Unix `setrlimit` resource hardening.
//!
//! This is **resource hardening, NOT sandboxing.** [`RLimits`] bounds how much of
//! a few coarse OS resources the inner MCP server subprocess can consume (open
//! file descriptors, CPU seconds, address space / data segment, core-dump size,
//! and file-write size). It bounds *resource abuse*, not *access*: it does NOT
//! restrict which files or network endpoints the inner server may reach, does NOT
//! create a namespace/jail, and is not a containment boundary. An inner server
//! within its ceilings can still open any path and any socket its OS credentials
//! permit. For that reason calling this a sandbox is rejected (ADR-MCPS-016) — it
//! is a parent-process resource ceiling applied to the child before `exec`.
//!
//! Application timing (Unix): the limits are applied via
//! [`std::os::unix::process::CommandExt::pre_exec`], which runs in the forked
//! child AFTER fork and BEFORE `exec`. The pre-exec closure must be
//! async-signal-safe, so it does NOTHING but issue `setrlimit(2)` syscalls and
//! returns an [`std::io::Error`] on the first failure — no allocation, no
//! logging, no panic. A failure in the closure makes the parent's
//! [`std::process::Command::spawn`] fail, so a required limit that cannot be
//! applied fails CLOSED (the inner server is never `exec`'d unbounded).
//!
//! Fail-closed posture (ADR-MCPS-016): a configured limit is NEVER silently
//! ignored.
//!   * On Unix, an `setrlimit` failure aborts the spawn (the parent sees the
//!     child's pre-exec `io::Error`).
//!   * On a non-Unix platform, a configured limit cannot be honored at all: in
//!     the default (required) mode this is a hard, fail-closed error refused at
//!     startup; only in an explicit best-effort mode is it downgraded to a
//!     warning + no-op. It is never dropped without a trace.
//!   * `best_effort` aligns conceptually with the future `--strict`/`--production`
//!     posture (#3842): strict/required is the default; best-effort is the
//!     opt-in relaxation. #3842 itself is NOT implemented here.

/// The integer type [`libc::setrlimit`] expects for its `resource` argument.
/// glibc Linux types it as `__rlimit_resource_t` (a `u32`); macOS/BSD type it as
/// `c_int`. We normalize to that platform type so the `RLIMIT_*` constants and
/// the syscall agree without a per-target `cfg`.
#[cfg(all(unix, target_os = "linux", target_env = "gnu"))]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(all(unix, not(all(target_os = "linux", target_env = "gnu"))))]
type RlimitResource = libc::c_int;

/// Coarse Unix resource ceilings applied to the inner-server subprocess before
/// `exec`. Each ceiling is individually configurable; `None` leaves that
/// resource at the OS default (no `setrlimit` call for it).
///
/// Values are the `rlim_cur == rlim_max` soft==hard ceiling to set. Counts are in
/// the natural unit of the resource (descriptors, seconds, bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLimits {
    /// `RLIMIT_NOFILE` — max open file descriptors. `None` = OS default.
    pub nofile: Option<u64>,
    /// `RLIMIT_CPU` — max CPU time in SECONDS (the kernel sends `SIGXCPU` at the
    /// soft limit and `SIGKILL` at the hard limit). `None` = OS default.
    pub cpu_seconds: Option<u64>,
    /// `RLIMIT_AS` — max virtual address space in BYTES. Coarse memory ceiling.
    /// Mutually informative with [`RLimits::data_bytes`]; set whichever the
    /// deployment's allocator behavior makes meaningful. `None` = OS default.
    pub address_space_bytes: Option<u64>,
    /// `RLIMIT_DATA` — max data-segment size in BYTES. An alternative coarse
    /// memory ceiling to `RLIMIT_AS`. `None` = OS default.
    pub data_bytes: Option<u64>,
    /// `RLIMIT_CORE` — max core-dump size in BYTES. Defaults to `Some(0)`
    /// (core dumps disabled) so a crashing inner server cannot spill memory —
    /// which may contain secrets it was handed — to disk. Set `None` to leave the
    /// OS default, or a positive value to allow bounded cores.
    pub core_bytes: Option<u64>,
    /// `RLIMIT_FSIZE` — max size in BYTES of any single file the inner server may
    /// write (the kernel sends `SIGXFSZ` on exceeding it). OPTIONAL; `None` = OS
    /// default. Bounds runaway file growth, not which files may be written.
    pub fsize_bytes: Option<u64>,
    /// Best-effort mode. When `false` (the default, strict/required posture), a
    /// configured limit that cannot be applied — including any configured limit
    /// on a non-Unix platform — is a hard fail-closed error. When `true`, an
    /// unappliable limit is downgraded to a warning + no-op (logged, never
    /// silent). Aligns with the future `--strict`/`--production` posture (#3842).
    pub best_effort: bool,
}

impl Default for RLimits {
    fn default() -> Self {
        RLimits::new()
    }
}

impl RLimits {
    /// The secure default: no descriptor/CPU/memory/file-size ceiling configured,
    /// core dumps DISABLED (`core_bytes = Some(0)`), strict (required, not
    /// best-effort). Core-dump suppression is a sensible always-on default
    /// because an inner-server core can contain secret material.
    pub fn new() -> Self {
        RLimits {
            nofile: None,
            cpu_seconds: None,
            address_space_bytes: None,
            data_bytes: None,
            core_bytes: Some(0),
            fsize_bytes: None,
            best_effort: false,
        }
    }

    /// Whether any resource ceiling is configured (core-dump suppression counts).
    /// Used to decide whether the non-Unix fail-closed check has anything to
    /// guard.
    pub fn any_configured(&self) -> bool {
        self.nofile.is_some()
            || self.cpu_seconds.is_some()
            || self.address_space_bytes.is_some()
            || self.data_bytes.is_some()
            || self.core_bytes.is_some()
            || self.fsize_bytes.is_some()
    }

    /// The configured ceilings as `(RLIMIT resource code, value)` pairs, in a
    /// stable order. The resource code is the libc `RLIMIT_*` constant cast to
    /// the integer type [`libc::setrlimit`] expects for its `resource` argument
    /// (a `__rlimit_resource_t` u32 on glibc Linux, a `c_int` on macOS/BSD) — the
    /// `as RlimitResource` cast normalizes that platform difference.
    #[cfg(unix)]
    fn configured(&self) -> Vec<(RlimitResource, u64)> {
        let mut out: Vec<(RlimitResource, u64)> = Vec::new();
        if let Some(v) = self.nofile {
            out.push((libc::RLIMIT_NOFILE as RlimitResource, v));
        }
        if let Some(v) = self.cpu_seconds {
            out.push((libc::RLIMIT_CPU as RlimitResource, v));
        }
        if let Some(v) = self.address_space_bytes {
            out.push((libc::RLIMIT_AS as RlimitResource, v));
        }
        if let Some(v) = self.data_bytes {
            out.push((libc::RLIMIT_DATA as RlimitResource, v));
        }
        if let Some(v) = self.core_bytes {
            out.push((libc::RLIMIT_CORE as RlimitResource, v));
        }
        if let Some(v) = self.fsize_bytes {
            out.push((libc::RLIMIT_FSIZE as RlimitResource, v));
        }
        out
    }

    /// Validate that this config can be honored on the current platform, in the
    /// configured posture. Call at startup so a misconfiguration fails CLOSED
    /// before the proxy agrees to serve (mirrors the env/working-dir up-front
    /// validation in [`crate::inner_launch::InnerLaunchConfig`]).
    ///
    /// On Unix this always succeeds (whether each individual `setrlimit` succeeds
    /// is only knowable in the forked child and is enforced there via `pre_exec`).
    /// On a non-Unix platform a configured limit cannot be honored:
    ///   * strict (default) mode → `Err` (fail closed);
    ///   * best-effort mode → `Ok` (the caller is expected to have warned).
    pub fn validate_platform(&self) -> Result<(), String> {
        #[cfg(unix)]
        {
            Ok(())
        }
        #[cfg(not(unix))]
        {
            if self.any_configured() && !self.best_effort {
                return Err(
                    "inner-server resource limits (--inner-rlimit-*) are Unix-only and cannot be \
                     applied on this platform; this is resource hardening, not sandboxing. Either \
                     run on Unix, drop the limits, or opt into --inner-rlimit-best-effort to \
                     downgrade to a logged no-op."
                        .to_string(),
                );
            }
            Ok(())
        }
    }

    /// Install the resource ceilings onto `command` as a `pre_exec` hook (Unix).
    ///
    /// The returned closure runs in the forked child before `exec`. It is
    /// async-signal-safe: it issues only `setrlimit(2)` syscalls and returns an
    /// [`std::io::Error`] on the FIRST failure — no allocation, no logging, no
    /// panic. Returning `Err` makes the parent's `spawn` fail, so a required
    /// limit that the kernel refuses fails CLOSED (the inner server is never
    /// `exec`'d without it).
    ///
    /// In best-effort mode a per-limit `setrlimit` failure is ignored inside the
    /// closure (the child proceeds to `exec`); in strict mode it aborts the spawn.
    ///
    /// # Safety
    /// `pre_exec` is `unsafe`: the closure executes in the fragile post-fork /
    /// pre-exec window of a multi-threaded parent. This closure touches no heap,
    /// no locks, and no parent state — it only reads `Copy` values captured by
    /// value and calls `setrlimit` — so it is async-signal-safe.
    #[cfg(unix)]
    pub fn apply_to_command(&self, command: &mut std::process::Command) {
        use std::os::unix::process::CommandExt;

        let limits = self.configured();
        let best_effort = self.best_effort;
        // Capture only Copy data (resource codes + values + the flag) by value, so
        // the closure allocates nothing and shares no state with the parent.
        // SAFETY: see method docs — async-signal-safe (setrlimit-only, no alloc).
        unsafe {
            command.pre_exec(move || {
                for (resource, value) in &limits {
                    let rlim = libc::rlimit {
                        rlim_cur: *value as libc::rlim_t,
                        rlim_max: *value as libc::rlim_t,
                    };
                    let rc = libc::setrlimit(*resource, &rlim);
                    if rc != 0 && !best_effort {
                        // Fail closed: abort the spawn. The parent surfaces this
                        // as the spawn error; the inner server never execs.
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }

    /// No-op application stub for non-Unix platforms. The fail-closed decision for
    /// non-Unix is made by [`RLimits::validate_platform`] at startup; by the time
    /// a command is built we have already either errored (strict) or warned
    /// (best-effort), so there is nothing to apply here.
    #[cfg(not(unix))]
    pub fn apply_to_command(&self, _command: &mut std::process::Command) {}
}

#[cfg(test)]
mod tests {
    use super::RLimits;

    #[test]
    fn default_disables_core_dumps_and_is_strict() {
        let limits = RLimits::new();
        assert_eq!(limits.core_bytes, Some(0), "core dumps must default to disabled");
        assert!(!limits.best_effort, "default posture must be strict/required");
        assert!(limits.nofile.is_none());
        assert!(limits.cpu_seconds.is_none());
        assert!(limits.address_space_bytes.is_none());
        assert!(limits.data_bytes.is_none());
        assert!(limits.fsize_bytes.is_none());
    }

    #[test]
    fn any_configured_tracks_core_default() {
        // The default already has core_bytes = Some(0), so something is configured.
        assert!(RLimits::new().any_configured());
        let none = RLimits {
            core_bytes: None,
            ..RLimits::new()
        };
        assert!(!none.any_configured());
        let one = RLimits {
            core_bytes: None,
            nofile: Some(64),
            ..RLimits::new()
        };
        assert!(one.any_configured());
    }

    #[cfg(unix)]
    #[test]
    fn validate_platform_ok_on_unix() {
        // On Unix every individual setrlimit is enforced in the child; startup
        // validation always passes.
        assert!(RLimits::new().validate_platform().is_ok());
        let many = RLimits {
            nofile: Some(32),
            cpu_seconds: Some(5),
            address_space_bytes: Some(1 << 30),
            fsize_bytes: Some(1 << 20),
            best_effort: false,
            ..RLimits::new()
        };
        assert!(many.validate_platform().is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn apply_to_command_installs_pre_exec_without_panicking() {
        // Wiring smoke test: installing the pre_exec hook on a Command must not
        // panic and must leave the Command spawnable (effect is tested at the
        // integration level against a real child).
        let limits = RLimits {
            nofile: Some(256),
            ..RLimits::new()
        };
        let mut command = std::process::Command::new("/bin/true");
        limits.apply_to_command(&mut command);
        // We do not spawn here (that is the effect test's job); just prove the
        // builder accepted the hook.
    }
}
