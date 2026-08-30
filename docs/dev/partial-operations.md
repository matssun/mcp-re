# Partial operations in security-bearing code

The record of MCPRE-176: an audit of every production `clippy::expect_used`,
`clippy::indexing_slicing` and `clippy::arithmetic_side_effects` site in the seven runtime
crates — `mcp-re-core`, `mcp-re-http-profile`, `mcp-re-proxy`, `mcp-re-client-core`,
`mcp-re-client-proxy`, `mcp-re-client` and `mcp-re-transport`.

The closure condition was never "make Clippy quiet". It was:

> no reachable partial operation, no unexplained bound assumption, and no unexplained
> integer algebra remains in a security-bearing production path.

Every site was resolved into exactly one of the classes below. This file exists so a site's
justification can name its class in a line instead of restating the argument, and so the
next reader can tell a reviewed site from an unreviewed one.

## What the audit changed, by class

### R — reachable failure, now reported

The `Err`/`None` can arise from the wire, from configuration, from a clock, from a provider,
or from concurrency, and the code asserted it away. These became typed refusals carried to
an owner that can decide them. None became a default value: a lossy fallback answers a
question the caller asked honestly with a value nobody computed.

The refusal always takes the **restrictive** direction. A rotation threshold that cannot be
computed reads as *reached*, not as *far away*; a freshness edge that cannot be widened
reads as *outside the window*; a drain deadline that cannot be represented reads as
*already elapsed*. Overflow must never turn a restrictive security value into a permissive
one, and the direction is stated at each site because it is the part a reader cannot check
by inspection.

### B — the bound made load-bearing

The access was total, but only because a check somewhere else had run. These became
operations that carry their own bound: `get` / `get_mut` instead of an index behind a
length test; `split_at_checked` and `split_once` instead of two ranges each re-deriving one
offset; slice patterns instead of an arity check followed by indexed reads; `checked_sub`
used **as** the branch condition rather than beside it.

The test applied was the audit's operational one: *can the check be deleted and still leave
the access total?* Where the answer was no, the bound moved into the access.

### C — structurally bounded, and the bound is named

Direct indexing or plain arithmetic remains, with a narrow `#[allow]` naming what makes it
total. Four invariants account for nearly all of them:

- **Slice-index arithmetic.** A cursor is an index into a slice, or one or two positions
  past it. No slice may be longer than `isize::MAX` bytes, so `+ 1` or `+ 4` on one cannot
  reach `usize`'s range. Bytes from the wire choose which branch runs, never how large a
  cursor becomes. Every *read* at such a site still goes through `get`.
- **Capacity hints.** `Vec::with_capacity(a.len() + b.len() + k)` over slice lengths, for
  the same reason.
- **An enum mapped into a fixed table.** The table's width is the enum's cardinality, and
  that is a compile-time assertion rather than a count someone kept in their head — see
  `stage_timers.rs`.
- **A machine-checked proof.** `parse_rfc3339_utc` and `days_from_civil` are inside the
  Verus cone: THM-0002 proves totality on arbitrary bytes, and the lane re-establishes it on
  every change. That is the one case where a function-scoped allowance is safe on a long
  function — an unproved operation added inside it fails the prover, not merely a reviewer.

A `const fn` evaluated in a const context belongs here too: const evaluation is the checker.

### A — an assertion that stays, and why

An `expect` survives only where failure means this crate's own primitives are wrong, or
where there is no safe value to return at all. Each carries a narrow `#[allow]` naming which.

Two shapes recur:

- **`serde_json::Value` → bytes.** `to_vec` fails on a `Serialize` that errors or a
  non-string map key. `Value`'s own `Serialize` is infallible and the objects in question
  are built from literals, so neither is reachable.
- **No safe value exists.** The OS CSPRNG declining to produce a signing seed or a nonce is
  an environment failure with no fallback: continuing would mint a key or a nonce that is
  predictable, which silently defeats the property the value exists for. Aborting is the
  fail-closed outcome, and where it happens at startup the abort *is* the refusal to start.

## What was deliberately left alone

- `mcp-re-demo`, `mcp-re-test-paths`, and `SeededNonceSource` in `mcp-re-host` — demos and
  fixtures, outside the audited surface. `SeededNonceSource` is `cfg`-gated so it cannot
  compile into a production binary; that gate, not this note, is the boundary.
- `clippy::excessive_nesting` and the module-size tail: a different question, and not this
  audit's.

## The standing rule

A new partial operation in these crates now shows up as a ratchet failure, because
`config/clippy-debt.toml` records the audited lints at **zero** for all seven crates rather
than dropping their entries. An entry at zero is a measured fact. Removing it would make the
next occurrence look like a lint nobody had ever counted there.
