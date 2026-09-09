# The extraction artifact: what the assurance proposition requires, and what it does not

Owner ruling, 2026-09-09, remeasuring #541 from first principles after four sessions of
container-registry debugging that had begun to read as architecture.

> Lean evidence must identify the exact extraction/prover environment that produced it,
> reproducibly and immutably enough that the evidence can be invalidated when that
> environment changes.

That is the requirement. *"The extraction image must live in GHCR"* is not, and this record
establishes the difference by measurement rather than by assertion.

## The four layers, kept apart

```
semantic requirement   Lean evidence identifies the exact extraction environment,
                       immutably, and is invalidated when that environment changes
       |
toolchain identity     which INPUTS were declared
       |
reproducible artifact  which BYTES those inputs actually produced
       |
storage/distribution   where those bytes happen to be kept
```

The bottom layer is a mechanism. It has no authority over any of the three above it, and the
finding below is that it had quietly acquired some.

## 1. What assurance proposition requires the extraction container?

Every `lean://` claim, and today exactly one: THM-0128, *the civil-date conversion is total
on the domain its caller can supply*. Its evidence is a Lean proof over a model produced by
Charon and Aeneas from `mcp-re-core/src/time/format.rs`.

The container is what makes *"this Charon, this Aeneas, this Lean"* a definite description.
Charon is a rustc driver linking the private compiler crates and does not build on the macOS
host at all, and both tools' behaviour depends on how they were built, not only on which
commit they were built from. Without a named environment the proposition degrades to "some
extraction of that Rust was checked by some prover", which invalidates nothing when the
prover moves.

## 2. Which parts of its identity must be measured?

Two sets, and conflating them is what produced MCPRE-181.

**Declared inputs**, already computed by `tools/verification/_extraction_identity.py` and
recorded as `tag`:

| input | pinned by |
|---|---|
| Charon commit | `[charon].commit` |
| Charon's rustc | `[charon].rust_toolchain` (a dated nightly) |
| Aeneas commit | `[aeneas].commit` |
| OCaml compiler | `[aeneas].ocaml_compiler` |
| Lean toolchain | `[lean].toolchain` |
| mathlib revision | `[aeneas_lean_backend].mathlib_revision` |
| the build definition | `definition_digest` — the Dockerfile's own bytes |
| platform | `linux/arm64`; an amd64 build of identical pins is a different instrument |

**The residue the inputs do not determine.** Measured on this tree, the Dockerfile silently
resolves five moving external inputs:

| input | why it moves |
|---|---|
| `FROM debian:bookworm-slim` | a mutable tag; Debian rebuilds it |
| `apt-get install …` (12 packages) | unpinned versions from the archive |
| `https://sh.rustup.rs` | a moving installer script |
| `elan-init.sh` from `master` | explicitly a moving ref |
| `opam install …` (~15 libraries) | unpinned versions — **and these build the Aeneas binary** |

The last one is material rather than theoretical: a different `visitors` or `zarith` produces
a different Aeneas, which can produce a different extracted model from identical Rust.

**Therefore the build is not reproducible, and an ARTIFACT identity is required.** It cannot
be derived from the declared inputs; it has to be recorded from the build that actually
happened. That is what the `[extraction_container]` digest has always really been, and
naming it accurately is most of this ruling.

## 3. Which of those requirements need a remote registry?

None.

Immutability and invalidation are properties of a *digest*, not of where the bytes are kept.
A content digest over an image identifies those bytes whether they sit in a registry or in a
local image store; the lock's own note gives the rationale as *"pinned by DIGEST, never by
tag: a tag is a mutable pointer"*, and a local image identity is not a mutable pointer.

A remote registry buys exactly one thing the local store does not: **another machine can
obtain the same bytes.** No current proposition claims that. The extraction lane runs on one
self-hosted runner, `verify-lean` refuses to run anywhere else, and no theorem, unit,
assumption or trust boundary asserts cross-machine reproduction of the model.

## 4. Is GHCR named by any accepted ADR or security proposition?

**No.** Measured across the tree:

| where GHCR appears | what it is |
|---|---|
| `verification/policy/toolchains.lock.toml` | the `image` field — a mechanism value |
| `tools/verification/extraction-image` | `DEFAULT_IMAGE` — a default |
| `.github/workflows/extraction-image.yml` | the publisher |
| `.github/workflows/verification.yml` | the consumer |
| one review packet | describing the then-current step |

No ADR, no theorem, no unit, no assumption and no trust boundary names it. It entered as the
place the first image happened to be pushed, on 2026-08-10, by hand.

## 5. Can the proposition be satisfied without it?

**Yes — by a locally built image on the verification runner, with the artifact identity
recorded.** That is the smallest mechanism that preserves every property above:

* the declared inputs stay exactly as they are;
* the artifact identity remains a content digest, and remains immutable;
* a rebuild produces a different identity, which invalidates the evidence — which is
  correct, and is the honest consequence of a non-reproducible build;
* MCPRE-181's invariant survives unchanged: a recorded identity that does not follow from
  the declared definition fails closed.

**What it gives up, stated plainly:** the bytes exist on one machine. If that machine's image
store is cleared, the lane reports that it cannot run rather than reporting a pass — the
fail-closed direction — and the remedy is to rebuild and re-pin, which invalidates the
affected evidence exactly as any other toolchain change does. That is a durability cost, not
an assurance one.

**Google Artifact Registry** is the alternative if a centrally published artifact is ever
genuinely required. It is preferred over GHCR because MCP-RE already operates it, so it adds
no second package-control plane. It is not adopted now because nothing needs distribution,
and a published artifact would have to be kept visibly separate from runtime and release
images: **the extraction image is a formal-verification toolchain artifact, never a
deployable MCP-RE product image, and its digest is an artifact identity rather than a
release or deployment claim.**

## Ruling

GHCR is removed as a requirement of #541 and demoted to what it always was — one possible
place to keep bytes. The artifact identity becomes storage-agnostic, and the lane builds and
verifies locally on the verification runner.

Escalate and revisit only if a proposition appears that genuinely requires a centrally
published artifact, in which case the answer is the existing Artifact Registry rather than a
second control plane.

---

## Addendum, same day — a digest is identity, not preservation

The ruling above is accepted and unchanged. One consequence of §5 was stated as a durability
cost and is corrected here, because it was larger than the sentence admitted.

§5 said: *"If that machine's image store is cleared, the lane reports that it cannot run
rather than reporting a pass — the fail-closed direction — and the remedy is to rebuild and
re-pin, which invalidates the affected evidence exactly as any other toolchain change does."*

**Rebuilding is not a remedy here, and §2 is why.** The same measurement that forces an
artifact identity — apt and opam resolve versions nothing pins, and the opam libraries are
linked into the Aeneas binary — means a rebuild produces a *different* instrument under
identical declared pins. So "rebuild and re-pin" does not restore the environment a standing
`lean://` claim was checked against. It replaces it, and every claim resting on the old one
is invalidated by an ordinary `docker image prune`.

That leaves an established claim **identifiable but no longer reproducible**: the lock names
an environment, and nothing on earth can execute it again.

### The correction

The exact artifact bytes are preserved outside Docker's disposable state, in a
content-addressed directory on the verification runner:

```
/opt/verification/extraction-artifacts/sha256/<artifact_digest>.tar
```

`[extraction_container]` records two digests, because they answer two questions:

| field | question |
|---|---|
| `artifact_digest` | which image EXECUTES, once the archive is loaded |
| `archive_digest` | whether the file in the store IS that image's preserved form |

`tools/verification/extraction-image load` is what every consumer runs. It checks that the
archive exists and digests to the recorded value, loads it if the image is not already
present, and prints an **image id** — never a tag, because a tag resolves through the local
cache, and the local cache is the thing that is not the evidence store.

Fail-closed, with the two non-passing outcomes kept apart:

* **absent** → UNAVAILABLE. The lane cannot run here. It never rebuilds and never falls back
  to a same-tag image;
* **digest mismatch** → FAIL. A file sitting under an identity it does not have is
  substituted or truncated, and nothing may execute from it.

### What this does NOT do

It does not reopen the registry question — the bytes stay on one machine and moving them is
an operator act (`scp`), exactly as §3 concluded. And it does not claim reproducibility. The
residual unpinned apt/opam closure remains a measured limitation, deliberately not pinned as
part of #541. The claim a preserved artifact supports is the honest, weaker one:

> this theorem was checked against THIS exact preserved extraction artifact

and not

> this exact artifact can be reconstructed indefinitely from the Dockerfile.

Full build reproducibility is future assurance work. Docker's cache is an execution
optimisation; it was never an evidence store.
