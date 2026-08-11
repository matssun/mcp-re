<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-060: Modular Decomposition, Mechanical Enforcement, and the Real-Time Verification Loop

**Status:** 🟡 DRAFT — captured, NOT ratified, NOT published as a Discussion.
Source of record for owner directives on the modular refactor.
**Date captured:** 2026-08-11 (first pass), re-captured in full from the owner's
repeat transmission the same day — the repeat carried substantial new material
(§5, §7, §8) that the first pass never received.
**Captured from:** owner (Mats Sundvall). Verbatim where marked.
**Relates to:** [ADR-MCPRE-056](https://github.com/matssun/mcp-re/discussions/524),
[ADR-MCPRE-057](https://github.com/matssun/mcp-re/discussions/525),
[ADR-MCPRE-058](https://github.com/matssun/mcp-re/discussions/526),
[ADR-MCPRE-059](https://github.com/matssun/mcp-re/discussions/527); `CLAUDE.md`;
`work/REFACTOR-COLLECTION.md` (private collection file).

> **Placement.** ADR bodies are retired from the repo — the ADRs are GitHub
> Discussions in the **ADRs** category, the single source of truth
> (`docs/adr/README.md`). This is a **draft body staged for publication**, held
> in-tree until the owner rules on R-5. It is under `docs/` and therefore tracked;
> it must never live under `work/`, which is gitignored (`.gitignore:25`).
>
> **060 is the next free number:** 056–059 are Discussions #524–#527.

---

## §0 Governance — how directives are handled

Owner rules about the handling of owner rules. These bind every future session and
every subagent.

**G-1.** Every instruction the owner gives is captured, in full. Capture is not
optional and not subject to the assistant's judgement about relevance.

**G-2.** *"You are not the one who decide here."* Scope, thresholds, ordering, and
method are owner decisions.

**G-3.** *"If you think something is wrong, you shall argue with me, but you shall
not select to not act on it or save instructions I give you."* Disagreement is
expressed as an argument, in the open, at the time — never by omission, by quiet
substitution of a different value, or by declining to record. **Arguing is expected.
Silently dropping is forbidden.**

**G-4.** *"I won't repeat myself."* An instruction is given once. Losing it is a
defect of this document.

**G-5.** Where two owner sources conflict, record **both**, mark the conflict, and
ask for a ruling. Never pick one silently.

**G-6.** *"So I will give you some ideas here and then we're gonna talk about it."*
Ideas are discussed before they are executed. Collection and discussion precede the
plan. Reinforced by the later instruction to gather everything into a collection file
first "because there will be a lot more to come."

### Capture defects

Instances where this document's own capture failed — a silently-substituted
threshold, five dropped clauses, and one false report — are logged privately with
their corrections, per the routing rule in §0 of the collection file. They are
process hygiene for the capture, not part of the decision.

---

## §1 Diagnosis — why the codebase is in this state

Owner's stated root cause, captured verbatim because it defines what any fix must
counteract:

> LLMs default to creating monolithic files and monster functions in Rust because
> generating everything in a single file avoids managing module declarations (`mod`),
> visibility keywords (`pub`, `pub(crate)`), and trait imports across file
> boundaries. Left unconstrained, an AI agent will treat Rust like procedural C or
> script-heavy Python.

And the governing observation on enforcement:

> LLMs respond poorly to vague conversational instructions ("please write clean
> code"), but respond predictably when compiler/linter rules fail their execution
> runs.

**The consequence being asserted:** prose standards do not work on this class of
author. Only a failing build works. Any plan whose enforcement is documentation is
rejected by this directive.

**The prescribed remedy, stated as one sentence:**

> To fix this, you can apply a direct translation of the OO "One Class, One File"
> pattern to Rust: **"One Primary Type (or Trait) per Module File", backed by strict
> compiler and linter rules that force the agent to break code down.**

The clause *"backed by strict compiler and linter rules that force the agent to break
code down"* is not decoration. The structural rule (§2) and the mechanical
enforcement (§4, §7) are one directive, not two. Adopting §2 without §4/§7 does not
satisfy this ADR.

---

## §2 Translating "One Class, One File" to Rust

> In Rust, the module (`.rs` file) is the fundamental boundary for encapsulation and
> visibility, just as a class file is in C++ or Python.

**D-1.** Every major `struct` or `enum` gets its own file. No dumping of multiple
data structures and logic into a single `lib.rs` or `service.rs`.

**D-2.** Structure directories as **module trees**. Owner's hierarchy, verbatim:

```text
src/
├── core/
│   ├── mod.rs             // Re-exports public interfaces
│   ├── session.rs         // Contains `struct Session` + its impl block
│   ├── token.rs           // Contains `struct Token` + validation logic
│   └── validator.rs       // Contains `trait SecurityValidator` + impl
├── pipeline/
│   ├── mod.rs
│   ├── stage_parse.rs     // Single responsibility stage
│   └── stage_execute.rs
└── lib.rs                 // Declares top-level modules (e.g., `pub mod core;`)
```

**D-3.** Keep **data, behavior, and unit tests for a single concept localized inside
its dedicated file.** Owner's layout for `src/core/session.rs`, verbatim:

```rust
use crate::core::token::Token;
use crate::error::Result;

/// Primary type for this module
pub struct Session {
    id: String,
    token: Token,
}

impl Session {
    pub fn new(token: Token) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            token,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.token.verify_signature()
    }
}

// Unit tests live directly at the bottom of the file
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_validation() {
        // Localized unit test
    }
}
```

**D-4.** To avoid deeply nested import paths across the codebase, the parent `mod.rs`
presents a clean public API via `pub use`:

```rust
// src/core/mod.rs
mod session;
mod token;
mod validator;

// Re-export types so external callers import `use core::Session;`
pub use session::Session;
pub use token::Token;
pub use validator::SecurityValidator;
```

---

## §3 Breaking down 1,000+ line functions

> Monster functions in security-critical code usually suffer from mixing
> **orchestration, parsing, validation, and side effects.** Rust offers three primary
> mechanisms to decouple them.

### D-5 (A) The Type-State Pattern — compile-time state machines

Instead of one massive function with nested `if`/`else` checks validating state
transitions (e.g. `Unverified -> Authenticated -> Authorized`), encode states as
separate Rust types.

```rust
// Separate types for separate pipeline phases
pub struct UnverifiedRequest { pub raw_payload: Vec<u8> }
pub struct AuthenticatedRequest { pub user_id: String, pub payload: Vec<u8> }

impl UnverifiedRequest {
    pub fn authenticate(self, key: &[u8]) -> Result<AuthenticatedRequest, AuthError> {
        // Small, focused signature verification function
    }
}
```

**Benefits** (captured because they are this mechanism's acceptance criteria): the
compiler prevents executing actions on unverified requests. **Each step becomes a
20-30 line pure transformation function that is trivial to unit test in isolation.**

### D-6 (B) Composition via small traits

In C++ one might use abstract base classes or inheritance. In Rust, define
single-method traits to inject dependencies and enable mocking/testing.

```rust
pub trait KeyVerifier {
    fn verify(&self, key: &[u8]) -> bool;
}

pub trait AuditLogger {
    fn log_access(&self, user_id: &str);
}

// SecurityProcessor composes tiny behavior traits
pub struct SecurityProcessor<V, L> {
    verifier: V,
    logger: L,
}
```

### D-7 (C) Splitting large `impl` blocks

If a struct genuinely requires many methods, they need not all be in one `impl` block
or one file. Split `impl` blocks across files within the same module, or split them
by trait implementation:

```rust
// src/core/session/security.rs -> impl Session { pub fn Audit(...) }
// src/core/session/serialization.rs -> impl Session { pub fn to_bytes(...) }
```

---

## §4 Enforcing architectural boundaries via tooling

**D-8.** Compiler flags at the top of `lib.rs` / `main.rs` make monolithic code a
compile/lint error. Owner's list, verbatim:

```rust
// src/lib.rs

// Force clippy warnings into errors for oversized code
#![deny(clippy::too_many_lines)]          // Triggers on functions > 100 lines (configurable)
#![deny(clippy::cognitive_complexity)]    // Catches heavily nested control flow
#![deny(clippy::large_stack_frames)]
#![deny(clippy::module_lines)]            // Triggers if a single .rs file gets too long
```

**D-9.** Exact thresholds live in `.clippy.toml` at the repository root:

```toml
# .clippy.toml
too-many-lines-threshold = 60
cognitive-complexity-threshold = 10
```

**Status D-9: LANDED** 2026-08-11. `/.clippy.toml` created with these values
verbatim; both keys validated as accepted under the pinned toolchain.

**Status D-8: NOT LANDED.** Two reasons, both requiring a ruling — see §10 C-3
(`clippy::module_lines` does not exist) and §10 C-8 (landing the denies turns the
build red immediately). Not dropped; blocked.

---

## §5 Claude Code Instruction Rules (`CLAUDE.md`)

> When working with Claude Code, put explicit architectural constraints into your
> repository's `CLAUDE.md` file. **This prevents the agent from falling back to
> monolithic scripts.**

The owner states these are rules **he has added to `CLAUDE.md` as hard rules** — they
are current owner directives asserted in this session, **not** inherited background.
The first capture pass mis-filed them as pre-existing standing entries; corrected
here.

Owner's template, verbatim:

### D-10 Module & File Structure

1. **One Main Type Per File**: Every major `struct`, `enum`, or `trait` must reside
   in its own file under a domain module (e.g., `src/domain/user_repository.rs`).
2. **File Size Limit**: No single `.rs` file may exceed **250 lines of code
   (excluding unit tests)**. If a file exceeds this, split it into sub-modules.
3. **Module Re-exports**: Use `mod.rs` to encapsulate module internals and re-export
   public interfaces using `pub use`.

### D-11 Function Boundaries & Security

1. **Function Line Limit**: No function may exceed **50 lines of code**. Split
   complex logic into private helper functions (`pub(crate)` or `fn`), or pipeline
   stages.
2. **Cognitive Complexity**: Avoid nested `match` or `if let` statements **deeper
   than 2 levels**. Use early returns (`?` operator or `let-else` statements).
3. **Security Code**: Parsing, authentication, and execution **MUST** be isolated
   into distinct types/functions. **Do not combine I/O operations with cryptographic
   or authorization logic in the same function.**

### D-12 Testing Requirements

1. Every file must include a `#[cfg(test)] mod tests` block at the bottom containing
   unit tests for the types defined in that specific file.
2. Run `cargo clippy -- -D warnings` after every edit. **Do not mark a task complete
   if Clippy emits warnings or functions exceed complexity thresholds.**

---

## §6 The Recommended Refactoring Sequence

> Before prompting your agent, apply this step-by-step strategy to refactor an
> existing **1,300-line function**.

**D-13.** The prescribed order of operations. Applied **before** prompting any agent.

1. **Create the Target Module Directory Structure** — set up the folders and blank
   `mod.rs` files manually or via a quick command.
2. **Define Data Structures First** — tell the agent to extract all internal
   `struct`s, `enum`s, and state representations into separate files under the new
   directory.
3. **Extract Pure Helper Functions** — have the agent extract pure logic (parsing,
   validation, formatting) into small functions within the corresponding type files,
   **accompanied by immediate unit tests**.
4. **Rebuild the Orchestrator** — rewrite the main entry point function so that it
   **only calls the newly created modular functions in a top-down pipeline**.
5. **Run Clippy** — require the agent to pass
   `cargo clippy -- -D clippy::too_many_lines` to verify that **no remnants of the
   monster function remain**.

---

## §7 The real-time security feedback loop

Owner's stated objective for this whole section:

> To achieve a real-time security feedback loop where issues are caught **instantly
> on save — without burning tokens on massive downstream AI audits** — you need to
> build a multi-layered automated pipeline.
>
> Formal verification frameworks like Verus, static analysis tools like Clippy, and
> real-time execution engines form the ideal defense stack.

This is the direct answer to the cost constraint in §9 D-31. The mechanism for not
repeating the 70%-of-a-daily-quota burn is **to move detection off the LLM and onto
the toolchain.**

### 7.1 Deepening formal verification with Verus

Verus uses mathematical specs (`requires`, `ensures`) and SMT solvers (Z3) to prove
that code is bug-free across all execution paths — eliminating entire classes of
security vulnerabilities (overflow, memory corruption, authorization bypass,
invariant breaks).

**D-14. Isolate Verified Code.** Do **not** try to verify the whole codebase. Keep
verified logic in dedicated, **tiny** modules (e.g. `src/security/auth_verifier.rs`,
`src/crypto/token.rs`).

**D-15. Define Ghost Invariants.** Use Verus specifications to define access-control
invariants. Owner's example, verbatim:

```rust
// Spec: User must be active AND hold admin scope
pub open spec fn is_valid_admin(user: User) -> bool {
    user.is_active && user.has_scope(Scope::Admin)
}

pub fn execute_privileged_action(user: User) -> (res: Result<(), Error>)
    requires is_valid_admin(user), // Must be proven by caller at compile-time!
    ensures res.is_ok(),
{ ... }
```

**D-16. Verify in Local Pipelines.** Wire Verus checks directly into the local
verification tools so specs are checked **alongside standard type-checking**.

### 7.2 Configuring Clippy as a strict security guard

> Clippy is Rust's built-in, highly configurable static analysis engine. It goes far
> beyond standard linting to catch subtle logic bugs, panics, and security footguns.

**D-17. Workspace lints in the root `Cargo.toml`.** Configure it to strictly forbid
unsafe constructs, silent failures, and cognitive bloat. Owner's block, verbatim:

```toml
# Cargo.toml
[workspace.lints.clippy]
# Security & Safety
unwrap_used = "deny"              # Prevents explicit panics/crashes in prod code
expect_used = "deny"              # Forces explicit error handling
indexing_slicing = "deny"         # Prevents out-of-bounds panics (e.g., arr[i])
arithmetic_side_effects = "deny"  # Forces explicit overflow/underflow handling
wildcard_enum_match_arm = "deny"  # Ensures all security states are handled explicitly

# Complexity & Architecture
too_many_lines = "deny"           # Enforces function length limits
cognitive_complexity = "deny"     # Forces breaking down deeply nested logic
module_lines = "deny"             # Keeps files lightweight and modular

# Performance & Code Quality
pedantic = { level = "warn", priority = -1 }
```

### 7.3 The instant "on-save" verification loop

> To catch bugs **the exact millisecond you hit Ctrl+S / Cmd+S**, set up
> `cargo-watch` locally. This provides immediate terminal or IDE feedback **without
> waiting for CI or triggering AI runs.**

**D-18. Install `cargo-watch`:**

```bash
cargo install cargo-watch --locked
```

**D-19. The Ultimate "On-Save" Security Command.** Keep a terminal pane running this
**while developing or directing the AI**:

```bash
cargo watch -s "cargo check --all-targets && cargo clippy -- -D warnings && cargo test"
```

Whenever a file is saved:

- `cargo check` verifies structural compilation.
- `cargo clippy` evaluates all custom security rules and complexity limits.
- `cargo test` executes the unit tests for that modular file.

**If any check fails, the process stops instantly, showing the exact line number to
fix before progressing.**

### 7.4 The testing strategy for deconstructed Rust code

> When you split monolithic files into small single-type modules, your testing
> strategy becomes dramatically cleaner.

**D-20. The layout:**

```text
src/
├── auth/
│   ├── mod.rs
│   ├── jwt.rs           <-- Unit tests live inside (focused on parsing/signing)
│   ├── permission.rs    <-- Unit tests live inside (focused on access logic)
│   └── validator.rs     <-- Verus specs / property tests live here
tests/
├── security_pipeline.rs <-- Integration tests (combines types in end-to-end flows)
```

**D-21. (A) Localized Unit Tests (`#[cfg(test)]`).** Every small file should test its
own primary type. Because types are isolated, **tests execute in parallel and run in
milliseconds.**

**D-22. (B) Property-Based Testing (`proptest` / `quickcheck`).** For
security-sensitive **parsers, bounds, and algorithms**, use property-based testing
**instead of** static example tests:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_token_parser_never_panics(input in ".*") {
        // Generates millions of random inputs to prove parser safety
        let _ = parse_security_header(&input);
    }
}
```

**D-23. (C) Fuzzing Engine (`cargo-fuzz`).** For code handling **untrusted network
input or binary deserialization**, set up a dedicated fuzz target:

```bash
cargo fuzz run fuzz_target_1
```

---

## §8 Agent Execution Protocol

> Before handing the agent tasks, update your repository's local context
> (`CLAUDE.md`) with this workflow rule.

**D-24.** Owner's protocol, verbatim:

1. Split large files into single-type module files (**max 200 lines**).
2. Ensure every function is **under 50 lines** and passes
   `#![deny(clippy::too_many_lines)]`.
3. Verify locally on save via `cargo clippy -- -D warnings` and `cargo test`.
4. **Do NOT attempt broad architectural rewrites without passing local linter gates
   first.**

Clause 4 is a sequencing constraint on this entire refactor: the gates come before
the rewrites, not after.

---

## §9 Session directives — scope, constraint, and the questions asked

**D-25.** *"This codebase is in chaos and we are going to fix it now. We are going to
do it in a structured way and I will guide you with detailed instructions."*

**D-26.** *"I have updated the claude.md file to give you some guidance. Some hard
rules that I have added."* — §5 is that content. It is **new owner-asserted hard
rules**, not inherited background.

**D-27. Investigate, do not act.** *"When I ask you to investigate something you
should investigate, but not head on and do something before I say: Go!"*

**D-28. The hard constraint.** *"We need to find a way to refactor the modules and do
it without breaking everything."*

**D-29. The analysis mandate.** *"I want you to prepare or analyse the codebase. See
what parts of the codebase that we have. **What can we do without breaking the
rest?**"*

**D-30. The questions the plan must answer**, as asked:

- Which crate/directory first? (`mcp-re-client`, `-client-core`, `-client-proxy`,
  `-conformance`, "and so on".) Can we work through them one at a time?
- Even in one sub-directory there might be many files — so where shall we start?
- **What is the core of MCP-RE?** Or shall we start from the top — **which is the
  entry point?**
- *"So make a plan which directory first and in that directory how do we attack it?"*

**D-31. The cost constraint.** A prior attempt to remediate security findings by
running successive rounds of agents over a single large file cost a great deal and
ended with a higher defect count than it started with. The measured figures are
recorded privately per the §0 routing rule.

Both halves are binding: the per-file cost and the negative net result. Any plan that
reproduces either is rejected. §7 is the owner's own prescribed countermeasure — move
detection onto the toolchain so the LLM is not the instrument of discovery.

---

## §10 Conflicts requiring an owner ruling

Recorded per G-5. **Not resolved by the assistant.** Cross-referenced to the
`R-` numbering in `work/REFACTOR-COLLECTION.md` §6.

**C-1 — Function line threshold: four different numbers are now in play.**

| source | value |
|---|---|
| `.clippy.toml` (D-9) | **60** |
| `CLAUDE.md` template (D-11.1) | **50** |
| Agent Execution Protocol (D-24.2) | **under 50** |
| D-8's own comment / clippy default | 100 |

Two owner sources say 50 and one says 60. **A single value must be chosen and the
other documents corrected.** Measured impact: **>60 → 67 functions; >50 → 99
functions**; total functions 1420.

**C-2 — File line threshold: 250 vs 200.**
`CLAUDE.md` template (D-10.2): *"may not exceed 250 lines of code (excluding unit
tests)"*. Agent Execution Protocol (D-24.1): *"single-type module files (max 200
lines)"*. Both are owner text from the same transmission. Measured: **62 of 139 files
exceed 250**; the count at 200 is higher and not yet measured pending the ruling.

**C-3 — `clippy::module_lines` does not exist. This now blocks two directives.**
Probed against clippy 0.1.97 / toolchain 1.97.1:

| lint | status |
|---|---|
| `too_many_lines` | ok |
| `cognitive_complexity` | ok |
| `large_stack_frames` | ok |
| **`module_lines`** | **DOES NOT EXIST** |
| `excessive_nesting` | ok — not requested; see C-5 |

Clippy has **no file-length lint at all**, under that or any other name. This blocks
D-8's fourth clause **and** D-17's `module_lines = "deny"` entry — and an unknown
lint name in `[workspace.lints.clippy]` is itself a build error, so D-17 cannot be
landed verbatim. Per G-3 the intent is **not** dropped: the file-length rule needs a
repository gate script (the existing `scripts/*_gate.py` family). **Ruling needed on
the substitution and the value (see C-2).**

**C-4 — D-17's safety lints will not land silently.** `unwrap_used`,
`expect_used`, `indexing_slicing`, and `arithmetic_side_effects` set to `deny` across
an 89k-line workspace is a very large immediate breakage, and `pedantic` at `warn`
adds thousands more. The violation counts have **not** been measured yet. Ruling
needed on whether these land as `deny` at once, or ratchet in per-crate. **Measuring
this is the assistant's next task and needs no ruling.**

**C-5 — `clippy::excessive_nesting` is not in any owner list**, but it is the only
mechanical enforcement for D-11.2 (*"nested `match` or `if let` deeper than 2
levels"*), which currently has none. It has its own `excessive-nesting-threshold`
key. Add or decline — recorded either way.

**C-6 — §7.1's Verus directives overlap a published, Accepted ADR.**
ADR-MCPRE-059 (Discussion #527, *"Accepted - staged implementation"*) already governs
incremental formal verification, the Verus lane, and the evidence graph, and its
implementation is partly landed. D-14/D-15/D-16 must be reconciled with it — do they
amend #527, restate it, or is #527 the authority and §7.1 merely its summary? **Do
not implement §7.1 as though #527 did not exist.**

**C-7 — ADR-MCPRE-058 §5 is titled "No Arbitrary Line-Count Rule."** It explicitly
refuses the enforcement D-8, D-9, D-13.5, D-17, and D-24 all mandate. §5's rule:

> A security-critical function is too flat when independent invariants, states,
> authorities, failure modes, or lifecycle obligations are represented only by local
> variables, source order, comments, or distant checks inside one procedural scope.

**Assistant's argument, offered per G-3 — the owner decides:** these are not opposed,
and the strongest form is both. ADR-058's rule is the better *review* standard; it
catches a 40-line function hiding three authorities, which no line count ever will.
But it is unenforceable against an LLM author, because it requires judgement the
author is the least reliable party to exercise — the exact failure mode §1 names, and
§5 is itself the clause under which ADR-058 went unfollowed. A line threshold is a
dumb rule a machine cannot argue with, and that is its entire value. **Recommendation:
ratify the thresholds as the enforced floor, keep §5 as the review layer above it,
and amend §5 from "rejected" to "necessary but not sufficient."** An argument, not a
decision.

**C-8 — ADR-MCPRE-058 was not followed, and its authority is unsettled.**
Owner: *"If there is an ADR it has not been followed that is for sure."* Measured:
**0 directory modules** in any of 12 crates; 62 of 139 files over 250 lines; 67
functions over 60; no `.clippy.toml` existed; no crate declared a clippy lint
attribute. Does ADR-058 retain authority, get amended, or get superseded?

**C-9 — Identity and publication of this document.** Publish as ADR-MCPRE-060, fold
into #526 as an amendment, or demote to a standing `docs/` file. **Nothing is
published without a `Go!`** — posting to Discussions is outward-facing. Note also
that §5 and §8 are `CLAUDE.md` content by the owner's own framing; a Discussion is
not read by an agent mid-task, `CLAUDE.md` is.

---

## §11 Verified facts about the toolchain

Established by probe, not assumption. Re-verify on any toolchain bump.

- Pinned toolchain is **1.97.1** (`rust-toolchain.toml`, mirrored in
  `MODULE.bazel`); clippy is **0.1.97**.
- **Homebrew's `cargo` at `/opt/homebrew/bin/cargo` shadows rustup and ignores the
  pin.** Use `rustup run 1.97.1 cargo …` or `scripts/use_pinned_toolchain.sh`.
  Measurements taken with the wrong `cargo` are void.
- `.clippy.toml` keys `too-many-lines-threshold` and `cognitive-complexity-threshold`
  are both accepted; no unknown-field error.
- Lint existence as tabulated in C-3.
- **`cargo-watch` (D-18) is not yet installed** and has not been verified against
  this workspace. Note for D-19: this repo's canonical hermetic build is
  `bazel test //...`, and per `CLAUDE.md` a plain `cargo test` does **not** compile
  the feature-gated lanes (`async_serve`, `redis_replay`, the KMS backends). The
  on-save loop is therefore a fast local gate, **not** evidence for a feature-gated
  property — the standing "do not report a green that measured nothing" rule applies
  to it unchanged.
