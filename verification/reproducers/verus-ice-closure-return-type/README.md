<!-- SPDX-License-Identifier: Apache-2.0 -->

# Reproducer — prover ICE on a closure parameter's unspecified return type

Run, from this directory, with the pinned prover on `PATH`:

```sh
PATH=/opt/verification/verus/0.2026.08.09.92f466f:$PATH cargo-verus verify
```

Twelve lines of `src/lib.rs` produce an internal panic instead of a diagnostic. The
narrowing sequence and the workaround are documented in that file.

Kept outside the workspace so it is never built by an ordinary `cargo build`; it exists to
be sent upstream, and to stop this being rediscovered from scratch. ADR-MCPRE-059 WP2,
ceiling 1.
