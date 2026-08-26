//! ADR-MCPRE-056 §5.4 — the optional-capability posture vocabulary.
//!
//! Every optional security seam this deployment can run is named by a [`Seam`], and
//! each one must be [`declare`](PostureLog::declare)d with a [`SeamState`] that says
//! whether it is ON or OFF. Both directions, always.
//!
//! # Why a seam that is silent when OFF is a defect
//!
//! An operator reading a startup transcript is asking one of two questions, and a
//! missing line answers neither: *is this capability off in this deployment*, or *does
//! this build not have this capability at all*? Those call for completely different
//! responses — a flag to set versus a binary to replace — and the consequence of
//! guessing wrong is that the capability stays off. Four seams were silent when off
//! before this module existed; the resulting failures read on the wire as client or
//! network problems, which is precisely what a startup posture exists to prevent.
//!
//! # Three checks, covering three different omissions
//!
//! They are not redundant, and none of them subsumes another.
//!
//! **One-sided announcement** — the decision is written, but only the ON arm says
//! anything. [`PostureLog::declare`] takes a `SeamState` **by value**, so a caller that
//! decides with an `if` must produce one on both arms and the `else` cannot be dropped
//! without a type error:
//!
//! ```ignore
//! let state = if enabled {
//!     proxy = proxy.with_thing(thing);
//!     SeamState::on("thing = ON: ...")
//! } else {
//!     SeamState::off("thing = OFF: ... pass --thing to enable it.")
//! };
//! posture.declare(Seam::Thing, state);
//! ```
//!
//! That is a LOCAL guarantee about one decision, and it is worth being precise about its
//! limit: it forces exhaustiveness only where the code constructs a `SeamState` from an
//! `if` or `match`. Leaving the `declare` call out altogether still compiles. The other
//! two checks exist because of exactly that.
//!
//! **A seam nothing declares at runtime** — [`PostureLog::assert_complete`] refuses to
//! serve unless every `Seam::ALL` entry was stated exactly once. In every build profile,
//! not only under `debug_assertions`; the reasoning is on the method.
//!
//! **A seam nothing declares in the source** — `scripts/seam_posture_gate.py` checks that
//! every variant is passed to `declare` exactly once in `app.rs`. This one exists for a
//! specific reason: no HERMETIC configuration reaches the posture phase, because it sits
//! after the replay tier is established and every tier validation accepts needs a live
//! Redis or etcd. So `assert_complete` — the stronger check — never runs in
//! `cargo test --workspace` or `bazel test //...`, and without the gate a seam added
//! without a declaration would ship green.
//!
//! The runtime check and the static gate answer different questions. The gate proves the
//! declarations EXIST in the source; only the runtime check proves the path actually
//! taken reached them.
//!
//! # A build without the feature still declares the seam
//!
//! `Seam::ALL` does not vary by `cfg`. A capability compiled out is declared OFF with a
//! detail naming the missing feature, because "this build cannot do it" is exactly the
//! state the transcript was failing to distinguish.
//!
//! # Lines are emitted where they are decided, never batched
//!
//! `declare` writes immediately. Collecting the posture and flushing it at one point
//! would discard everything printed so far whenever startup refuses partway through —
//! the moment an operator most needs it. The emission ORDER is therefore the decision
//! order, and it is observable behavior (ADR-MCPRE-056 §K1).

mod seam;

pub use seam::Seam;

/// Whether a seam is running, and the operator-facing line that says so.
///
/// The line is carried rather than generated because these lines are not
/// interchangeable: each one has to say what this specific capability being on or off
/// means for the calls this deployment serves, and an OFF line has to name the flag
/// that turns it on. A generated `"<seam> = OFF"` would satisfy the type and tell an
/// operator nothing actionable.
/// An enum rather than a struct with an `enabled: bool`, so the ON/OFF answer is the
/// value's own shape: a consumer matches on it instead of reading the prose back, which
/// is the direction ADR-MCPRE-056 asks the startup posture to move in.
pub enum SeamState {
    /// The capability is running. Carries the posture line, without the
    /// `mcp-re-proxy: ` prefix.
    On(String),
    /// The capability is not running — because it was not configured, or because this
    /// build does not have it. The line must say which, and what would turn it on.
    Off(String),
}

impl SeamState {
    pub fn on(line: impl Into<String>) -> Self {
        SeamState::On(line.into())
    }

    pub fn off(line: impl Into<String>) -> Self {
        SeamState::Off(line.into())
    }

    fn line(&self) -> &str {
        match self {
            SeamState::On(line) | SeamState::Off(line) => line,
        }
    }
}

/// The seams declared so far in one startup.
///
/// Threaded through the startup phase by `&mut` rather than kept in a global: two
/// proxies started in one test process must not see each other's declarations, and a
/// global would make `assert_complete` meaningless there.
#[derive(Default)]
pub struct PostureLog {
    declared: Vec<Seam>,
}

impl PostureLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit this seam's posture line and record that it was stated.
    ///
    /// Emission is immediate and at the decision site (§K1). A seam declared twice is
    /// caught by `assert_complete`, since a repeat means one decision site is standing
    /// in for another and the transcript now contradicts itself.
    pub fn declare(&mut self, seam: Seam, state: SeamState) {
        eprintln!("mcp-re-proxy: {}", state.line());
        self.declared.push(seam);
    }

    /// Seams that were never declared, in `Seam::ALL` order.
    fn undeclared(&self) -> Vec<Seam> {
        Seam::ALL
            .iter()
            .filter(|s| !self.declared.contains(s))
            .copied()
            .collect()
    }

    /// Seams declared more than once.
    fn duplicated(&self) -> Vec<Seam> {
        Seam::ALL
            .iter()
            .filter(|s| self.declared.iter().filter(|d| d == s).count() > 1)
            .copied()
            .collect()
    }

    /// Refuse to serve unless every seam stated its posture exactly once.
    ///
    /// # Why this refuses in a RELEASE build too
    ///
    /// An incomplete posture is an internal programming defect, not something an operator
    /// caused or can fix, and the first instinct is to make it a `debug_assertions`-only
    /// panic so no release build gains a new way to fail to start. That reasoning is
    /// wrong here, and the reason is what the posture IS.
    ///
    /// The transcript is the deployment's statement of which security controls are
    /// running. A build that emits an incomplete one has an operator reading a list of
    /// enforced controls that silently omits an entry — which is the same failure the
    /// whole vocabulary exists to prevent, arriving through the vocabulary itself. It is
    /// worse in release than in debug, because release is where someone acts on it.
    ///
    /// The state is impossible by construction: [`Seam::ALL`] is fixed at compile time,
    /// the declarations are a straight line through one function, and
    /// `scripts/seam_posture_gate.py` fails the build if one is missing from the source.
    /// Refusing to start in a state that cannot occur costs nothing and is the honest
    /// response if it somehow does.
    ///
    /// The static gate does NOT make this redundant: it proves the declarations exist
    /// syntactically, which is not the same claim as every executed path reaching exactly
    /// one of them.
    pub fn assert_complete(&self) -> Result<(), String> {
        let missing = self.undeclared();
        if !missing.is_empty() {
            return Err(format!(
                "startup declared no posture for {missing:?}: an operator would read this \
                 deployment's list of security controls without being able to tell whether \
                 those capabilities are off or absent from the build. This is a defect in \
                 mcp-re-proxy, not in the configuration — declare each one with \
                 SeamState::off(..) on the branch that does not wire it."
            ));
        }
        let repeated = self.duplicated();
        if !repeated.is_empty() {
            return Err(format!(
                "startup declared {repeated:?} more than once: the transcript states one \
                 capability's posture twice and a reader has no way to know which line \
                 governs. This is a defect in mcp-re-proxy, not in the configuration."
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{PostureLog, Seam, SeamState};

    fn declare_all(log: &mut PostureLog) {
        for seam in Seam::ALL {
            log.declare(*seam, SeamState::off("test seam = OFF"));
        }
    }

    /// The completeness check is the mechanism that closes the gap this module exists
    /// for, so it has to actually fire. Without it, a seam whose OFF branch is missing
    /// is invisible until an operator hits it in production.
    #[test]
    fn a_seam_that_is_never_declared_is_refused() {
        let mut log = PostureLog::new();
        for seam in Seam::ALL.iter().skip(1) {
            log.declare(*seam, SeamState::off("test seam = OFF"));
        }
        let err = log
            .assert_complete()
            .expect_err("an undeclared seam must refuse");
        assert!(err.contains("declared no posture for"), "got: {err}");
        // The refusal has to name the seam: "something is missing" leaves the reader
        // diffing seven declaration sites against an enum.
        assert!(err.contains("SecurityAuditRecord"), "got: {err}");
    }

    /// Two sites declaring the same seam produce a transcript that states one
    /// capability's posture twice, possibly contradicting itself. That is as much a
    /// defect as silence, and it is the shape a copy-pasted decision site takes.
    #[test]
    fn a_seam_declared_twice_is_refused() {
        let mut log = PostureLog::new();
        declare_all(&mut log);
        log.declare(Seam::EvidenceRetention, SeamState::off("again"));
        let err = log
            .assert_complete()
            .expect_err("a doubly-declared seam must refuse");
        assert!(err.contains("more than once"), "got: {err}");
        assert!(err.contains("EvidenceRetention"), "got: {err}");
    }

    #[test]
    fn declaring_every_seam_exactly_once_passes() {
        let mut log = PostureLog::new();
        declare_all(&mut log);
        assert!(log.assert_complete().is_ok());
    }

    /// The check does not depend on `debug_assertions`: a release build refuses an
    /// incomplete posture too, because release is where an operator acts on the list of
    /// controls it prints.
    #[test]
    fn completeness_is_enforced_independently_of_debug_assertions() {
        let log = PostureLog::new();
        assert!(
            log.assert_complete().is_err(),
            "an empty posture must be refused in every profile"
        );
    }

    /// Two startups in one process must not satisfy each other's completeness check.
    /// This is why the log is threaded rather than global.
    #[test]
    fn one_startups_declarations_do_not_satisfy_another() {
        let mut first = PostureLog::new();
        declare_all(&mut first);
        assert!(first.assert_complete().is_ok());

        let second = PostureLog::new();
        assert!(
            second.assert_complete().is_err(),
            "a second startup must state its own posture"
        );
    }

    /// The ON/OFF answer is the value's own shape, not something recovered by reading
    /// the prose back — the inversion ADR-MCPRE-056 asks for (production owns the
    /// vocabulary; the human line is one rendering of it).
    #[test]
    fn state_answers_enabled_without_parsing_the_line() {
        assert!(matches!(SeamState::on("x = ON"), SeamState::On(_)));
        assert!(matches!(SeamState::off("x = OFF"), SeamState::Off(_)));
    }
}
