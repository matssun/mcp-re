//! Library surface of the OUT-OF-TCB `stdio`↔HTTP bridge (ADR-MCPRE-051 Phase B).
//!
//! The binary ([`main.rs`](../main.rs)) is a thin HTTP front end; the reusable,
//! security-critical machinery — subprocess lifecycle, environment allow-listing,
//! Landlock/seccomp sandboxing, `setrlimit` ceilings, and the persistent stdio
//! session — lives in these modules so it can be exercised directly by the crate's
//! integration tests (the subprocess-hardening coverage relocated here from the
//! `mcp-re-proxy` PEP when the surface moved out of the TCB).

// ADR-MCPRE-051 Phase B / task C3: the subprocess/sandbox/rlimit machinery lives
// HERE now, out of the cryptographic PEP's TCB. These modules moved verbatim from
// `mcp-re-proxy`; the bridge owns its own copy of the diagnostic log seam too.
pub mod inner_launch;
pub mod log_sink;
pub mod persistent_inner;
pub mod rlimits;
pub mod sandbox;
// Issue #4039: the LINUX kernel-enforcement backend behind the #3865 seam. A
// non-Linux build excludes this module entirely and never links landlock/seccompiler.
#[cfg(target_os = "linux")]
pub mod sandbox_linux;
pub mod subprocess_inner;
