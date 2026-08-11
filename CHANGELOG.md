<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to MCP Runtime Evidence (MCP-RE, formerly MCP-S) are
recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until
1.0 the public surface is explicitly unstable: minor versions may break API
or wire-format compatibility while the design lines from
[`docs/adr/`](docs/adr/) settle.

## [Unreleased]

## [0.16.0] — 2026-08-10

### Added — the exchange lifecycle is a value, and refusals derive their retry contract from it (ADR-MCPRE-057, ADR-MCPRE-058)

The serving path has always moved through a fixed sequence of states; until now no value
held which one it was in. Each state was a position of the program counter, and a refusal
answered "may the client simply retry this?" from its own position in the function.

That could not be answered locally. It needs two facts at once — whether the backend ran,
and whether a human's approval was already spent — and one reachable combination was
unrepresented: a continuation consumed to enforce one-shot, followed by a refusal before
the dispatch. The approval is destroyed, the action never ran, and an ordinary retry cannot
recover it. Such refusals now carry
`retry_safety: unsafe_without_new_elicitation` with `continuation_status: consumed`.

`exchange_state.rs` holds the lifecycle as a closed transition relation with an explicit
execution threshold, plus four sibling projections — the fate of the approval this exchange
spent, whether the backend can have acted, who authored the response bytes, and the fate of
the continuation leg this exchange's own reply opens. Correctness lives in invariants over
that tuple rather than in an enumeration of it, and the consequence of an exchange is
monotone by construction: no transition and no store observation can move it to a weaker
claim about what has happened.

Nothing about the request-side wire format changed for an exchange that succeeds.

### Changed — every post-dispatch failure now states that the call may have executed

Refusals below the execution threshold used to say nothing about it. Exactly one code
carried the contract — `mcp-re.evidence_retention_indeterminate`, which the rejection
builder special-cased by name — so an unrecognized `resultType`, a response-signing
failure, a 202 that could not be signed, and a continuation-record failure at **HTTP 503**
all returned a bare status after the tool had already run. 503 is the status clients retry,
and the retry carries a fresh nonce that passes replay admission.

Every rejection emitted at or after the inner dispatch now carries:

```json
{ "execution_status": "possibly_executed", "retry_safety": "unsafe_without_reconciliation" }
```

derived from the exchange machine rather than from a list of wire codes, so a
post-dispatch exit added later cannot silently fail to be on the list.
`evidence_retention_indeterminate` keeps its more specific body, which additionally names
which obligation failed.

Pre-dispatch refusals are unchanged, and still report that nothing executed.

### Changed — a backend reply must be a legal JSON-RPC 2.0 response before it is signed

MCP requires MCP messages to follow JSON-RPC 2.0. MCP-RE did not check it. A backend reply
was signed and served with no verification that `jsonrpc` was `"2.0"`, that the response
`id` matched the request it answered, or that exactly one of `result` / `error` was
present — and a body that was not JSON at all was signed as opaque payload, whereupon the
client's own verifier rejected a message the enforcement boundary had vouched for.

Worse, what checking existed was **conditional on unrelated configuration**: the only real
envelope inspection lived inside the MRTR open-leg recorder, which returns early when no
continuation store is wired. Whether MCP-RE refused a malformed protocol response depended
on whether an operator had configured Redis.

Validation is now unconditional and runs before the signature. A reply that is not a legal
response to the outstanding request is refused with **502 `mcp-re.upstream_response_invalid`**.

The check stops at the protocol control envelope — syntax, `jsonrpc`, `id` correlation,
`result` XOR `error`, the `error` member's shape, and the MCP `resultType` /`requestState`
lifecycle members. Everything else inside `result` remains opaque application payload that
MCP-RE carries and signs without reading. A JSON-RPC error is treated as what it is: a
valid terminal protocol response, distinct from both a malformed reply and a transport
failure.

### Changed — MCP-RE no longer returns an `input_required` response it cannot honour

**Deployments using elicitation / multi-round-trip flows must configure continuation
storage.**

A deployment with no continuation store served an `input_required` reply with a 200 and
then refused every answer leg that followed, as `mcp-re.continuation_binding_failed` — a
code that on the wire reads like an attack signal. The proxy was emitting a state
transition it had kept nothing to honour, and the client discovered it one leg later.

The refusal now happens where the obligation is incurred:
**503 `mcp-re.replay_cache_unavailable`** with `execution_status: possibly_executed`. Set
`--replay-redis-url` to serve these flows. The startup posture line already announced this
seam as OFF; it now announces a refusal rather than a deferred one.

### Changed — an inner-transport failure is no longer served as a successful response

The inner-server seam returned bytes and nothing else, so six outcomes arrived identical
and were signed at **HTTP 200** as `-32603 "inner server unavailable"` — indistinguishable
from the backend genuinely replying with that error:

```text
no in-flight permit / every backend ejected   nothing was transmitted
connect error, per-request timeout            transmitted, no answer — execution UNKNOWN
non-2xx status, non-JSON body                 the backend answered, unusably
```

A timeout is the textbook may-have-executed case, and serving it as a signed 200 was the
strongest available signal that the exchange had completed normally.

The seam now reports which outcome occurred, and the exchange derives consequence from it:

| outcome | now | retry |
| --- | --- | --- |
| the plane cannot begin a dispatch | 503 `mcp-re.inner_plane_unavailable`, refused **before** the execution threshold | safe — nothing was transmitted |
| transport failed after transmission | 504 `mcp-re.inner_dispatch_indeterminate` | `possibly_executed` |
| the backend answered unusably | 502 `mcp-re.upstream_response_invalid` | `possibly_executed` |

The rejection body is still a JSON-RPC error object, so parsers are unaffected; the status
and the added consequence statement are what changed. A refused connection is deliberately
classified as indeterminate rather than as a definite non-execution, because the transport
cannot prove nothing reached the peer.

Local saturation and a fully-ejected backend set are the cases that got strictly better:
they are facts about the proxy, knowable without transmitting anything, and are now
retry-safe refusals instead of exchanges that had to report `possibly_executed`.

### Fixed — terminal trust staleness and signing retirement could be reversed by an in-flight worker

Both the trust and delegated-signing planes retire their artifact on drop and then halt
their worker, but a worker observes its halt only between cycles. A trust reload already
mid-read could complete afterwards and call `mark_fresh`, reviving a resolver whose only
remaining job was to refuse; a delegated mint already in flight could publish after
`retire`, handing a signer that outlived its plane a fresh key and a fresh `exp` that
nothing rotates and no trust-epoch advance can revoke.

Neither is closeable by ordering at the drop site — the two steps are on different threads.
Each child machine now distinguishes "temporarily unhealthy, and allowed to recover" from
"the owner is terminating, and recovery is forbidden", with a terminal latch for the
second. The recoverable transitions stay recoverable.

### Fixed — three configuration rules could be bypassed by a programmatically built `Config`

Each rule was enforced in `parse_args` and nowhere else, so a `Config` assembled in code —
an embedder, a harness, a bespoke launcher — reached the serving path having met no parser.
All three now live at the validation boundary, which no route into the runtime can skip.
Command-line users see the same diagnostics as before.

* **An empty or scheme-less `--target-uri` disabled the request-target reconstruction
  check** rather than weakening it. The comparison is answerable only for an absolute
  target, and the "no mismatch" answer propagated for every request while the deployment
  went on reporting the binding as in force. The verifier's own audience comparison cannot
  catch it: both sides are the same configured string.
* **Contradictory TLS-key custody** — a delegated, non-exporting handshake key asserted
  alongside an exported one — means the key is custodied in a device it is supposed never
  to leave while a copy of it sits in a file on the pod. Nothing downstream noticed,
  because the key-source builder ignores a selector belonging to another source.
* **`--admission-allow-degraded` with a zero propagation bound.** The old diagnostic
  claimed a zero window "would fail closed on every unreachable-authority call". It does
  not: P is a floor on the degraded window, never the whole of it, so an unreachable
  authority still admitted any assertion younger than the clock-skew tolerance — a window
  in which a revoked workload keeps being served, on a deployment that configured no window
  at all.

### Changed — every optional capability states ON or OFF at startup (ADR-MCPRE-056)

Four seams — the verified-context carrier, online OCSP, the MCP transport contract and
admission currency — announced themselves only when enabled, so an operator reading a
startup transcript could not tell "this capability is off here" from "this build does not
have it". Those call for different responses (set a flag versus replace the binary), and
the cost of guessing wrong is that a security control stays off.

All seven optional capabilities now declare a posture exactly once, and the proxy refuses
to serve unless every one of them has — in every build profile, not only under debug
assertions. Each OFF line names what turns the capability on, or why nothing can, and says
what the deployment does not enforce without it.

### Changed — the composition root, the runtime lifecycle, and teardown have owners

Startup was a single 782-line function in which roughly 38 fallible steps held their
successful acquisitions as plain locals, so a later failure unwound them in reverse
declaration order rather than the documented teardown order. Resources are now owned the
moment they are acquired, and the runtime lifecycle is a value with a closed transition
relation rather than a set of program-counter positions.

No behaviour changes on a successful startup. A FAILED startup now releases resources in
the documented order.

### Fixed — the trust store published two locks that could be read torn

The verification keys and the kid → signer coordinate were held in separate locks under a
comment saying both "must move in the same swap". They did not: between the two write
locks the store held a resolver from one read of the trust file and a signer map from the
previous one. The window failed closed, but by accident of how resolution consumes the
composite pair rather than by anything the publication guaranteed. Both views now come from
one read, behind one lock.

### Added — the formal-verification platform, phases 0–4 (ADR-MCPRE-059, in progress)

An evidence graph that computes freshness rather than reporting structure: a unit is fresh
only while every input its previous conclusion depended on still hashes the same, with no
mutable clean flag anywhere. Attestations record the fingerprint components rather than a
single digest, because "something moved" cannot tell a reviewer which input moved.

This is developer-facing infrastructure with no runtime surface. The ADR is not complete
and the Verus pilot boundary is unresolved — Verus verifies per crate, and the candidate
lifecycle modules live in a crate large enough that the trusted computing base would
swamp the theorem.


### Changed — `--authz reference` states its refusal once, at the validation boundary

The refusal of the reference authorization profile was stated in two places with two
different diagnostics — one at parse time, one about 180 lines into startup. Both were
true and both fired, so nothing could slip past either; but one prohibition enforced at
two arbitrary altitudes is ambiguous about which layer owns it, and the two messages had
already drifted apart. They are now one predicate carrying both facts (the reference
profile is never the production authority, and authorization is not wired on the RFC 9421
serving path at all), consulted by parse-time validation and by the programmatic boundary.

A programmatically built configuration now refuses before any resource is materialized
rather than partway through startup. Command-line users see no change.

### Changed — the two undeployable transport bindings are refused at the validation boundary

`--transport-binding lb-assertion` (Mode B) and `--transport-binding attested-ingress`
(Mode C) are refused by configuration validation rather than by the composition root. No
mode became deployable and none was removed; both were already refused before any request
was served.

The two halves were different problems. `lb-assertion` was refused by configuration
validation *and* again in the composition root — one rule at two altitudes, which is not
redundant defence but a duplicated invariant waiting to drift; the second copy is gone.
`attested-ingress` was refused in the composition root and nowhere else, so a caller
assembling a `Config` in code — an embedder, a harness, a bespoke launcher — reached the
serving path carrying a binding whose verifier the async fleet does not consult, with
identity coming from wherever the fallback strategy took it. That refusal moved to the
boundary, where no construction path skips it.

They also now refuse separately, naming the mode. One shared message read as a single
unsupported feature when they are two decisions with different futures.

Mode C is **retained** as a future capability rather than deleted; its verifier keeps its
tests. Admitting it will require stating, in the specification, what an attestor is
permitted to assert and where the node's own authority begins.

Operators passing either flag see the refusal earlier in startup, naming the specific mode.

### Fixed — `--revocation-list` could bypass its refusal off the parsed path

Fixed programmatic configuration validation so `--revocation-list` cannot bypass the
existing CLI refusal. No policy changed and no capability was added: the flag was already
refused, because the policy-layer deny-list is consumed only by an authorization profile
and no production profile has landed, so a supplied list would enforce nothing.

The refusal lived only in `parse_args`, and `revocation_list_paths` is a public field of
`Config`, so a caller building one in code reached the serving path carrying a revocation
control that nothing reads — an operator would believe a compromised grant was revoked
while it kept being authorized. The decision now lives in one predicate consulted from both
`parse_args` (which keeps the flag's diagnostic and its place in the refusal order) and
`unsafe_config_violations`, which `ValidatedConfig::try_from` runs and which no route into
the runtime skips.

Operators passing `--revocation-list` on the command line see no change: it was refused
before and is refused now, with the same message. Whether the capability is later
implemented, formally deprecated or redefined is left to a future release.

### Fixed — `--client-ocsp require` could bypass its refusal off the parsed path

Fixed programmatic configuration validation so `client_ocsp = Require` cannot bypass the
existing CLI refusal. No policy changed: the flag was already refused, because online OCSP
is implemented only on the blocking serve loop while the production data plane is the
per-core async fleet, which performs no responder round trip. What changed is that *all*
construction paths now enforce that same restriction.

The refusal lived only in `parse_args`. `Config` has public fields, so a caller building
one in code — an embedder, a harness, a bespoke launcher — could set `client_ocsp` and
reach the serving path, where startup announced `ONLINE OCSP client-cert revocation
enabled` on a deployment that admits every revoked client certificate. The decision now
lives in one predicate consulted from both `parse_args` (which keeps the flag's specific
diagnostic and its position in the refusal order) and `unsafe_config_violations`, which is
what `ValidatedConfig::try_from` runs and which no route into the runtime can skip.

Operators passing `--client-ocsp require` on the command line see no change: it was
refused before and is refused now, with the same message pointing at `--client-crl`.

## [0.15.0] — 2026-08-06

### Changed — TLS session resumption is restored, bound to a trust epoch (ADR-MCPRE-055)

v0.14.0 refused TLS session resumption outright. That was a real security fix — a resumed
session skips chain building, so a withdrawn CA stayed honoured for the lifetime of a
ticket — but it cost 21% of throughput, and refusing was a heavier answer than the problem
needed.

Resumption is restored and bound to a **trust epoch**: a digest over the client-CA set and
the client-auth policy, computed at config build and carried in every stored session.
Withdrawing a CA or changing the policy changes the epoch, which invalidates every
outstanding ticket — so a resumed session can never outlive the trust that admitted it.
Sessions whose epoch no longer matches are evicted rather than merely rejected. Early data
stays disabled (`max_early_data_size = 0`).

CRL contents are deliberately **excluded** from the epoch: a CRL refresh must not
invalidate the whole session cache, and per-request revocation already covers it.

The startup line now reads `tls_session_resumption=epoch-bound`. Four tests drive real
in-memory rustls handshakes and assert on `HandshakeKind`, including that withdrawing a CA
forces a full handshake with the verifier deliberately left unchanged.

### Changed — serving runtime topology: shards keep a worker pool (ADR-MCPRE-051 §1 amended)

Each serving shard was a single-threaded `tokio` runtime: one thread driving the I/O
reactor *and* polling every task. With hundreds of concurrent futures per shard a readied
task waited ~10.6 ms to be polled while the process used 0.49 of 14 cores — nothing
CPU-bound, nothing I/O-bound, the work simply not scheduled.

Shard count and pool depth are now independent, configured parameters:

* `--cores N` — serving shards, each an `SO_REUSEPORT` listener. Default: one per cpu.
* `--workers-per-shard W` — Tokio workers inside each shard. Default `min(8, cpus)`.
  `1` restores the previous single-threaded shard.

The two are **not** interchangeable and neither substitutes for the other: shards
parallelise `accept` (a single listener serialises connection establishment — 8x1 measured
4,628.8 rps against 1x8's 1,538.9 on a cold-mTLS envelope), while depth parallelises
polling (8x8 reached 44,803 rps against 8x1's 10,362 on a keepalive workload). The default
therefore keeps a shard per cpu and adds depth on top, never trading one for the other.

The local §7 anchor moved 5,530.9 → **15,454.9 rps** (p50 21,794 → 7,927 us) and was
re-baselined to v6. `scripts/runtime_topology_sweep.sh` measures the matrix on a given
host, because the optimum is hardware-, kernel- **and workload**-specific.

Security posture unchanged: replay integrity never depended on single-threaded sequencing
(admission is a server-side atomic `SET NX PX`, and `Fresh` can only come from a winning L2
insert), and `--max-in-flight` is still divided per shard so deeper pools do not widen the
in-flight bound.

### Fixed — the cloud SLO lane measured a debug build

`tools/slo/run_slo_job.sh` and `deploy/docker/Dockerfile.bench` ran `cargo test` without
`--release` while the local lane used it throughout, so every GKE §7 number ever recorded
was unoptimised — e2-standard-8 4,390.0 rps on release against 358.1 debug, 12.3x. The
declared production targets derive from those numbers and are now marked
`invalidated-pending-remeasurement`; the gate skips the capacity checks and says why rather
than passing against a floor ~45x too low.

### Fixed — the kind fleet lane could pass on stale evidence

Three defects in the lane that gates cloud spend: it rebuilt images only when ABSENT (so a
4-day-old binary was validated against today's chart, CrashLooping on a flag it predated);
Proof 1 reported a client TLS failure as "replica B accepted a nonce already spent on A",
a false security alarm about a request never sent; and port-forward readiness was a
`sleep`, which cannot distinguish a bound socket from a wired tunnel. Images are now
stamped with the build revision, a security claim requires the client to have reached a
verdict, and readiness is a real TLS handshake. The GKE harness also seeds the
trust-epoch counter it previously only read — the proxy's fail-closed guard on an absent
key was newer than the harness.

### Added — the client-side ambassador ships as a binary (`mcp-re-client`)

`FileManifestFloor` and `load_signed_manifest_with_floor` had no caller outside tests,
and `mcp-re-client-proxy` declares only `[lib]`. The floor is the highest trust-anchor
manifest version a verifier has ever accepted, and its whole purpose is to survive a
restart — so a library can *offer* one and only a deployable can *keep* one.
"Restart-durable rollback protection" was therefore a property the test suite could
demonstrate and no deployment had.

The new `mcp-re-client` crate is that deployable: a loopback plain-MCP listener that
signs outbound as RFC 9421 + RFC 9530, verifies the delegated-signed reply, and loads
its trust anchors from a signed manifest through a durable floor, refreshed on a cadence
into the snapshot every route reads. See
[`docs/client-sidecar-deployment-guide.md`](docs/client-sidecar-deployment-guide.md).

- **The bind refuses a non-loopback address** unless `local.allow_non_loopback` is set.
  The local leg is unauthenticated by construction, so anything that reaches it gets
  requests signed under this client's identity.
- **The floor must be named** — `durable` or `ephemeral`. A client that silently got the
  ephemeral floor would report the same posture as one with a durable floor while
  providing none of it across the restart that matters.
- **A failed refresh keeps the last good anchors; an EXPIRED manifest withdraws them.**
  Holding the anchors of a document that expired is the stale trust picture the expiry
  check exists to refuse, reached by a different route.
- **Anchored routes can now carry notifications.** `verify_delegated_accepted_202_anchored`
  closes a gap where the trust-anchor mode — the one a signed manifest distributes — had
  no signed-202 verifier and could only refuse one-way messages.

### Added — evidence retention on the serving path (ADR-MCPRE-054)

The SCITT surface was reachable only from tests, conformance vectors and interop
harnesses: nothing on the serving path produced a statement, reconstructed a chain, or
retained anything, so `retained_evidence.rs` was dead code inside the serving crate.

- **`--retained-evidence-dir <path>`** retains the full request and response messages of
  every served call. Opt-in and named, because it changes what a deployment stores about
  every call.
- **Retention fails closed.** A store failure refuses the exchange with the new frozen
  `mcp-re.evidence_retention_unavailable`. A deployment that turned retention on is
  asserting it can account for what it served; the audit sink takes the opposite posture
  deliberately, because a lost log line does not change what the deployment can prove.
- **Attestation stays off the request path.** `mcp_re_proxy::transparency::attest_chain`
  reconstructs a chain from retained hops and issues a Signed Statement committing to it.
  A PEP attesting per hop could only commit to a one-hop record, which for a continuation
  is a truncated one. Submission to a real Transparency Service remains the ADR's open
  external dependency.

### Security — round-6 audit remediation (BREAKING for some deployments)

A file-by-file pass over the round-6 security audit: 126 findings fixed, including all
25 high-severity ones. The operator-visible changes:

- **`--trust-domain` is now REQUIRED.** It defaulted to the `example.com` placeholder
  the Helm chart refuses outright, so the binary silently accepted the one value the
  chart exists to reject, and two installs that both left it unset shared an identity
  coordinate.
- **`--revocation-tier live|push` now requires `--trust-reload-secs`.** Both tiers state
  their revocation window in terms of consulting the trust store, and `--trust` was read
  once at startup — so revoking a request-signer key needed a restart of every replica
  while the startup line advertised a near-zero window. The store is now a snapshot a
  reload task swaps atomically.
- **The shared trust-epoch key must EXIST before the proxy starts** (`SET <key> 0`). An
  absent key read as epoch 0, indistinguishable from a live counter — which left the
  Tier-3 kill switch silently inert, or let a restarted replica re-mint under an epoch
  the operator had already revoked.
- **A per-core in-flight ceiling now applies by default** (64). Unbounded in-flight
  requests are attacker-controlled buffering ahead of the verify gate, and it also left
  HTTP/2 `max_concurrent_streams` unset.
- **mTLS connections are closed at a bounded age** (`--max-connection-age-secs`, default
  300s) and **TLS session resumption is refused**. The client certificate's chain, CRL
  status and validity window are checked at the handshake and nowhere else, so a peer
  that never reconnected kept full access after expiry or revocation — and a RESUMED
  TLS 1.3 session restores the stored peer chain without re-running client auth at all.

  **This moves the ADR-MCPRE-051 §7 throughput baseline by ~17%** on the §7 envelope
  (1 core / concurrency 128 / cold, a fresh handshake per request): 5451 rps with
  resumption, 4547 without, measured A/B on one box with every other round-6 change in
  place. The envelope is the worst case — a deployment with keep-alive pays a full
  handshake once per connection, not once per request. The prior number was measuring a
  proxy that skipped client-certificate verification on ~7999 of those 8000 handshakes.
  Re-baselining §7 is an owner declaration and has NOT been done.
- **Admission assertions must name the actor they were issued to**
  (`mcp_re_admitted_actor`). Without it an assertion was a bearer token any verifying
  peer could present. This is a wire-format change to an unratified surface.
- **The Rust signing seam enforces the 128-bit nonce floor** both SDKs already had, and
  refuses `expires <= created`.
- **New:** `--audit-sink none|stderr` (the ADR-MCPS-035 record had no deployment surface
  at all), `--verified-context-carrier disabled|trusted`, `--drain-grace-secs`.

### Added
- **SCITT statements and receipts are real CBOR/`COSE_Sign1`** (#494). The prototype
  serialized JSON as an explicit stand-in, which meant nothing on the wire was
  interoperable and no vector could honestly be frozen — pinning those bytes would
  have certified a non-wire format.

  A Signed Statement is now a tagged `COSE_Sign1` (RFC 9052 §4.2) whose protected
  header carries the RFC 9943 CWT claims (`iss`/`sub`/`iat`), the algorithm, the kid
  and the content type, and whose payload is the CBOR evidence commitment — the RFC 9943
  §6.1 CDDL. A Receipt is a tagged `COSE_Sign1` satisfying RFC 9942 §5.2.1: `vds`
  (label **395**) in the protected header, because the structure identifier selects how
  the proof is read and a verifier steered by unprotected data could be pointed at the
  wrong walk; the proof under `vdp` (label **396**) → `inclusion-proof` (label **-1**)
  in the **unprotected** header, as an array of bstr-wrapped
  `[tree-size, leaf-index, inclusion-path]`; and the RFC 9162 Merkle Tree Hash as the
  payload. Unprotected is correct rather than lax: the proof is the path a verifier
  walks, not a claim the service signs, so forging it cannot forge inclusion, only fail
  to re-derive the signed root.

  Two normative checks the walk depends on: a `vds` this verifier does not implement is
  refused at parse rather than walked as if it were RFC9162_SHA256, and a `leaf-index`
  at or beyond `tree-size` fails the proof (RFC 9942 §5.2, quoting RFC 9162) — a tree of
  size N has no leaf N, and arithmetic settles it before any hashing.

  Verification now runs over the **received** octets rather than reconstructing them.
  That removes a canonicalization dependency: re-deriving the signed bytes would have
  made the check depend on this encoder reproducing another implementation's CBOR
  byte-for-byte, which is exactly what COSE's `Sig_structure` exists to avoid. The
  algorithm is read from the protected header and must be EdDSA — accepting whatever
  the message named is the classic COSE/JOSE algorithm-confusion shape.
- **Frozen SCITT conformance vectors** (#494), in
  `mcp-re-conformance/tests/vectors/scitt/`: a complete record, an incomplete one that
  verifies and stays labelled incomplete, a same-length payload tamper that must fail
  as a *signature* rather than a decode, a genuine receipt paired with a different
  genuine statement (the substitution a verifier that checked signatures alone would
  accept), and a statement naming an unresolvable issuer. Three more pin what a
  conforming verifier must REFUSE while the service's signature stays valid: a sibling
  hash flipped inside the unprotected inclusion path, a `leaf-index` equal to
  `tree-size`, and a `vds` naming a structure this verifier does not implement. Each
  receipt is registered into a log that already holds an entry, so every vector pins a
  proof that has to be walked — a single-leaf log yields an empty path, which
  `inclusion-path = [ + bstr ]` does not admit and which folds nothing.

  Per-file SHA-256 plus a corpus digest, a determinism test that regenerating reproduces
  the octets, and a guard that the corpus directory holds no vector the manifest does
  not list. The digest catches a deleted fixture; nothing caught an extra one, and an
  unlisted vector is read by no test, so its expectation drifts out of date invisibly.

  `mcp-re-conformance/tools/scitt_cross_verify.py` checks the corpus with **no MCP-RE
  code**: cbor2
  for CBOR, `cryptography` for Ed25519, and the RFC 9052 §4.4 `Sig_structure`, the
  RFC 9942 §5.2.1 header shape and the RFC 9162 fold built from the RFC text. A corpus
  validated only by the encoder that produced it agrees with itself whatever labels it
  picks.

- **ES256 receipt verification, scoped so it is not a signing-policy change** (#501). A
  transparency service is not ours and signs receipts with `ES256` (RFC 9942's own
  examples do), so `CoseVerificationKey` adds ECDSA P-256 to the SCITT receipt verifier.
  The key names the algorithm and the protected `alg` must agree with it — a message that
  chose its own verification algorithm is the COSE/JOSE confusion shape. Refused:
  algorithm/key mismatch, unsupported algorithms, off-curve points, coordinates that are
  not exactly 32 octets (RFC 9053 §7.1.1 is fixed-width, so a 31-octet `x` is a different
  encoding rather than a number to left-pad), and DER-encoded ECDSA signatures — DER is
  variable-length and admits several encodings of one signature, which would break the
  one-signature-one-byte-string property `Sig_structure` rests on.

  MCP-RE's own request and response signing is untouched and stays Ed25519-only;
  `mcp-re-core` still refuses `ES256` by name and does not depend on `p256` at all.
  `scripts/es256_containment_gate.py` machine-checks that separation — `p256` confined to
  one crate and one module, absent from the signing core — because the quiet failure is
  someone reaching for the verifier already in the workspace to "support ES256 clients",
  widening MCP-RE's signing policy with no decision recorded.
- **Transparency-service trust pins** (#501). `ScittServiceTrustPin`
  (`mcp-re-scitt-service-trust-pin/v1`) records which key an interoperability run
  verified against, and where it came from: kid, algorithm, key, RFC 9679 COSE Key
  thumbprint, discovery URI and a digest of the discovery document's exact bytes. The
  algorithm comes from the pin, never from the receipt. `tools/scitt_fetch_service_key.py`
  does the fetch, because `mcp-re-http-profile` is pure and a verifier that called the
  service at verify time would not be verifying offline. A pin does not say the service
  is trustworthy, its log append-only, or its operator independent — it makes the run
  reproducible, which "the receipt verified" against a key nobody wrote down is not.
- **A content-addressed retained-evidence store** (#501). `RetainedEvidenceStore` +
  `EvidenceDigest` in the pure crate, `FsRetainedEvidenceStore` in `mcp-re-proxy` where
  fs access belongs. Narrow on purpose — `put`/`get` over immutable SHA-256-named blobs,
  no lifecycle or index; an evidence-retention platform is not what closing an
  interoperability issue calls for. `verify_retained_evidence` connects the halves, and
  keeps two digests distinct: the store addresses objects by a plain SHA-256, while a
  commitment names them by the §7.1 ROLE-LABELLED handle
  `sha256(label ‖ 0x00 ‖ bytes)` — so the same signature base in a request and a
  response role are two different values and cannot be swapped. A verified receipt is not
  retention, and a test pins that: the receipt verifies with no retained bytes present.

  What an interoperability *claim* still needs (#501): receipts signed with ES256 —
  RFC 9942's own examples use it, and this verifier requires EdDSA — and
  transparency-service keys resolved from a fetched-and-pinned key set — both now done,
  above.

- **Interoperability demonstrated against two independent implementations, and a leaf
  profile qualifier because they disagree** (#501). `@transmute/cose` (npm, authored by
  RFC 9942's editor) reads receipts produced here, and a receipt built by its RFC 9162
  tree and proof encoder verifies here offline. `capsule-anchor` (action-state-group,
  Apache-2.0), a real SCITT Transparency Service run locally, accepted the exact frozen
  `s01` Signed Statement over `POST /transparency/register-statement` and returned a
  detached-payload receipt that verifies here with its service stopped. Both corpora are
  frozen under `tests/vectors/scitt/interop/`.

  The two peers disagree about the Merkle LEAF PREIMAGE. RFC 9162 §2.1 hashes the i-th
  ENTRY and RFC 9943 says the service registers the Signed Statement, but neither says
  whether the entry is the statement's octets or a digest of them — a real gap, and the
  two implementations sit on opposite sides of it. So `StatementLeafProfile` is a
  qualifier on the PINNED service artifact: `statement-bytes` (the default, and the more
  direct reading, which `@transmute/cose` uses) or `statement-digest` (which
  `capsule-anchor` uses and its own source calls an exception to its own leaf rule).
  Exactly one profile applies to a verification and there is no fallback — trying both
  and accepting either would hand an attacker two chances at the fold and destroy the
  property the proof exists for, which is pinning WHICH entry was logged. The profile
  comes from the pin an operator wrote down, never from the receipt being checked; a test
  pins that the same real receipt is REFUSED under the wrong profile.
- **Detached-payload receipts verify** (#501). RFC 9942 §4.4 permits a Receipt to carry no
  payload — its own §5.2.1 Figure 6 shows one, and `capsule-anchor` emits one — and this
  was previously refused. Detached is a tighter binding, not a looser one: the root is
  re-derived from the statement and the inclusion path and the signature is checked over
  THAT, so the receipt cannot be verified without the statement it is about. The root is
  never taken from the caller.

  What the peer exchange still waits on. Measured, not assumed: the
  `scitt-community/scitt-api-emulator` is archived, expects CWT claims at label **14**
  (the pre-registry placeholder; RFC 9597/9943 assign **15**) and so rejects a conforming
  statement outright, and its receipts are a bare two-element CCF countersignature array
  with no `vds`, no `vdp` and no COSE tag. `microsoft/scitt-ccf-ledger` targets
  Architecture draft 11 with CCF tree-algorithm profile draft 3; DataTrails advertises
  draft 10 and MMRIVER, which RFC 9942's registry does not list. RFC 9943 published in
  June 2026 and no available implementation has caught up, so exchanging bytes with one
  today would mean emitting statements at label 14 and accepting non-RFC receipts — the
  fix above, reverted. The peer exchange is deferred rather than faked.
- **The §7 admission-currency check is on the serving path** (#493). ADR-MCPRE-053
  built the evidence — an authority-signed admission assertion and the binding that
  ties a call to it — and `check_admission` verified both. Nothing called it: every
  `admission` reference in the serving path was *replay* or *connection* admission,
  and no deployment surface referenced it at all. So a call carrying a fresh,
  correctly-bound assertion was served after its workload had been superseded or
  revoked, because currency is a comparison against state the deployment never
  supplied.

  `HttpProfileProxy::with_admission` closes that: the gate runs before replay
  admission and before the inner backend, because both are irreversible. A superseded
  generation, a revoked status, an untrusted authority, or an unreachable one now stop
  the call with the tool never having run.

  Three parts had to exist first, and each is a decision worth naming:

  - **the assertion travels in the request evidence block**, as `server_delegation`
    does on the response side. E-3 admits a new MCP-RE header field only where the
    message shape leaves no alternative, and a request has a body. Binding and
    assertion are both-or-neither: either alone verifies structurally and enforces
    nothing.
  - **`AsyncAdmissionSource` distinguishes reachable-and-absent from unreachable.** A
    healthy authority that has never heard of a workload is a definitive negative;
    only an outage reaches the §5.2 degraded fork. Collapsing them would serve an
    unknown caller on its own assertion — admitted by being unknown.
  - **`RedisAdmissionSource` is a live per-request read, not a cached copy**, so the
    propagation number means store visibility plus one round trip rather than a cache
    TTL. A deployment that adds a cache is making a different claim and must measure
    it separately.

  `--admission off|optional|required` with `--admission-authority-kid/-pubkey`,
  `--admission-redis-url`, and the degraded pair. Enforcing without an authority or
  without a source is refused at parse: a gate that looks enabled and verifies nothing
  is the most dangerous of the three states, because the deployment believes it has
  admission control.
- **Cross-replica revocation propagation is MEASURED** (#493) — the fourth
  ADR-MCPRE-053 acceptance criterion, open since 2026-07-17 and mislabelled as
  waiting on a live GKE fleet. Two `HttpProfileProxy` replicas share one Redis-backed
  source and nothing else; an authority revokes on a third connection; the interval to
  the first refusal on the sibling replica is measured. **Observed: 3ms, on the first
  request after the revoking write, against a declared P bound of 2000ms.**

  It is a local number and says so: measured against a Redis on the same host, it
  bounds the mechanism, not a production fleet, which adds network RTT and replication
  lag. What it establishes is that the mechanism propagates at all, to a replica with
  no prior knowledge of the workload, and what the floor looks like when the store is
  not the bottleneck.
- **`RequestSigningInputs::with_admission`** — clients could not present admission
  evidence at all; the block builder hardcoded `admission: None`.

### Known gap
- A degraded-mode serve is **indistinguishable from a live-confirmed one in the audit
  stream**. `VerifiedAdmission::degraded` carries the difference, and ADR-MCPS-035 §3
  freezes the success-event allowlist — no third success event without an ADR. Named
  rather than closed by quietly widening a pinned vocabulary.
- An admission refusal reaches the client as `mcp-re.actor_binding_failed`: the wire
  taxonomy is frozen and every code is a core token, so a revoked workload, an unknown
  one, and an authority outage are indistinguishable to a client and to an operator
  reading only the code.
- **Both SDKs drive the ADR-MCPS-047 answer leg** (#419). An `InputRequiredResult`
  pauses a call rather than finishing it, so the transport adapter now signs the
  answer leg over the *verified* handles of the leg before it, posts it, verifies
  the reply, and repeats until a terminal result — which is what the caller's
  single `await` resolves to. The decided surface is one handler at parity:
  `answer_input_required` / `answerInputRequired`, returning the `inputResponses`
  or nothing to decline; `on_input_required` stays a pure observer.

  The answer leg is an independent request with its own JSON-RPC id (SEP-2322
  §retry) and its own freshness (continuation profile §10.1); the terminal reply
  is relabelled to the id the caller issued before delivery. That relabelling is
  honest only because every hop verified inside the adapter, which is what makes
  the delivered result a complete record under §9.3 rather than a spliced one.
  `max_continuation_rounds` / `maxContinuationRounds` (default 4) bounds how long a
  server may keep one call in an elicitation cycle, and is checked *before* the
  handler runs so no answer is solicited that could not be sent.

  Covered by a recorded two-leg chain in `sdk/fixtures/delegated_response_replay.json`
  — the proxy accepted those exact answer-leg bytes when the fixture was recorded,
  and both SDKs reproduce them byte-for-byte.
- **Both SDKs ship the mTLS connect helper** (#413, slice 2). `connect_mtls_http` /
  `connectMtlsHttp` build the adapter's HTTP leg as a verifying mutual-TLS
  connection, mirroring the Rust client's `MtlsRemoteTransport`: only the configured
  CA authenticates the proxy, the certificate must be valid for the configured
  server name (kept separate from the address dialled), a client certificate is
  presented, one connection per exchange, and every bound — connect/read timeout,
  response ceiling — fails closed. There is no switch to disable verification.

  Tested against a real TLS server with client-auth required, on X.509 minted at
  test time by `tools/gen_mtls_test_material.py` (never committed —
  `scripts/tracked_secrets_gate.py` forbids a tracked PEM key, and is right to).
  The load-bearing cases are the refusals, including a certificate the trusted CA
  *did* sign for a different name: a chain-of-trust-only client accepts that one.
- **The `http_profile_proxy` example serves MRTR continuations**, with an in-memory
  correlation store. The proof front previously passed no continuation context to
  the dispatcher, so every answer leg failed closed on
  `mcp-re.continuation_binding_failed` and the SDK harness could not exercise a
  multi-round-trip call at all. Single-process only: a fleet wires the shared Redis
  store, and the difference is the store, not the protocol.

### Changed
- **BREAKING (SDK behaviour): an elicitation that cannot be answered is refused,
  not delivered as a result** (#419). Both adapters previously handed a verified
  `InputRequiredResult` up as the reply to `call_tool`, which presents a call still
  waiting for input as one that finished — the continuation profile's §5.2 / §9.3
  misrepresentation, and the same failure `unrecognized_result_type` already covered
  from the other direction. It now fails closed as `ContinuationNotAnswered` when no
  handler is installed, when the handler declines, or when the round ceiling is
  reached. A caller who wants the old shape installs a handler and gets the terminal
  result instead.
- **A completed or abandoned continuation chain leaves no correlation state.** An
  open leg is associated without being consumed (ADR-MCPS-047), and nothing retired
  it: every elicitation leaked an entry until the transport closed, which a peer
  able to elicit could drive.
- **BREAKING (wire): the MCP-RE JSON-RPC error code moved from `-32003` to
  `-31000`** (#426). MCP 2026-07-28 is now the current protocol revision, and its
  final §Error Codes text partitions JSON-RPC's implementation-defined band
  completely: `-32000..=-32019` is legacy that new implementations "SHOULD NOT use
  ... at all", and `-32020..=-32099` is reserved for codes the MCP specification
  itself defines. Codes for purposes MCP does not define belong outside
  `-32768..=-32000`. The old code sat in the legacy sub-range — the earlier
  RC-shape guard checked only the MCP-reserved sub-range and recorded a rationale
  the final text contradicts.

  Nothing parses the integer for meaning: the frozen `mcp-re.*` wire code in
  `error.data` is and remains the authoritative signal, and the HTTP status is a
  signed routing hint. The migration is therefore confined to the rejection body
  bytes — vectors h18–h22 and the corpus digest were regenerated.

### Fixed
- **The 2026-07-28 alignment guards now check the final text, not the RC**
  (#426). Confirmed against the published specification: the SEP-2322
  `resultType: "input_required"` snake_case discriminator, `complete` as the
  terminal value, and the requirement that clients read an *absent* `resultType`
  as complete.
- **An unrecognized `resultType` fails closed instead of reading as a completed
  call** (#495). MCP 2026-07-28 closes the set: unrecognized MUST be considered
  invalid. Classification gains a third outcome — the danger is specific, not
  theoretical, because an extension's *non-terminal* result read as terminal ends
  the exchange, closes the correlation entry, signs no answer leg, and hands a
  continuation to the application as a finished tool result.

  The PEP refuses to sign such a reply (before signing, and whether or not the
  deployment runs MRTR); chain reconstruction labels the record incomplete **at
  that hop** rather than guessing whether the turn ended; both SDKs refuse one
  arriving from a non-conformant server. Wire code
  `mcp-re.continuation_type_unsupported` — the same frozen token an unrecognized
  continuation `type` already used, for the same reason. Vector h51, and a
  recorded fixture replayed in both SDKs.

  Found by this: the reference inner backend
  (`tools/fastmcp_inner_backend.py`) emitted `resultType: "completed"`. The
  specification's terminal value is `complete`.

## [0.14.0] — 2026-07-28

**A security-audit release.** Fourteen rounds of the audit funnel over the serving
path, the signing core, the deploy surface and both SDKs closed **57 finding
clusters**, each fix carrying a negative control that fails when the fix is reverted.
The dominant defect shape was not a missing control but an unreachable one: a control
that exists, is announced at startup, and is never reached by the production data
plane. Twelve such controls were wired in round 1 alone.

Alongside it: the first **live GKE fleet run** of the four coherence proofs (and a
free kind rehearsal that caught six deploy defects before any cloud spend), one
**breaking profile change** to bodyless-202 binding (owner ruling C019b), and
notification support in both SDKs.

### Added
- **One local gate, run before anything else — and a gate against the command that
  measured nothing.** `scripts/local_gate.sh` runs every free stage in cost order,
  stopping at the first failure: structural gates → both cargo suites (the default
  workspace battery does not compile the non-default feature backends) → `bazel test
  //...` → the ADR-MCPRE-051 §7 SLO lane → optionally the fleet proofs on kind
  (`--with-kind`). It is now the documented precondition for every PR and every cloud
  run ([`docs/dev/local-gate-order.md`](docs/dev/local-gate-order.md)).

  The SLO half is `scripts/local_slo_lane.sh`, which exists because the documented
  invocation was wrong in four places — the GKE runbook, both `docs/bench/` docs, and
  the bench image's own `ENTRYPOINT` — all of them passing `-- --ignored`.
  `tls_load_harness_bench` is deliberately **not** an `#[ignore]` test (the file is
  gated to the `redis_replay` feature lane instead), so `--ignored` selects **zero**
  tests, exits **0**, and writes no report: a lane that looks green while having
  measured nothing. `scripts/slo_invocation_gate.py` (with self-test, wired into CI
  and stage 1) now fails any tracked invocation carrying `--ignored` or missing
  `redis_replay`, so the form cannot come back.

  The lane script also fixes three quieter traps: it builds the **bin** with the
  serving features (the harness spawns the real `mcp-re-proxy` as a child, so a
  test-only build is not enough), it forces an absolute `MCP_RE_LOADGEN_OUT` (cargo
  runs a test from the *package* root, so a relative path lands where the gate cannot
  read it), and it **refuses to measure on a loaded box** — the loadgen is co-located
  with the proxy, and that exact false alarm already cost a full A/B/B/A investigation
  in which v0.12.1 measured ~3225 rps against its own 4906.9 rps anchor.
- **Both SDKs carry and verify one-way notifications (#418, C055).** A `notifications/*`
  message is now its own signed POST — the ordinary request rules, no new signing — and the
  signed bodyless `202` it earns is verified before the message counts as delivered:
  `signNotification` / `sign_notification` and `verifyAccepted202` / `verify_accepted_202`
  in both bindings, over `mcp_re_client_core::build_signed_notification` and
  `verify_delegated_accepted_202`. The acknowledgement was emitted in production and checked
  by nothing on the client side; an intermediary could strip, forge, or substitute it and no
  SDK would notice.

  The envelope omits `id` entirely rather than sending `null`, because the serving path
  classifies a notification by the ABSENCE of the key; a present-but-null id would be
  dispatched as a request and answered with a bodied reply nothing awaits. A verified
  acknowledgement claims exactly that the enforcement boundary authenticated and accepted
  the message — never that any action completed.

  Proved live against the real `http_profile_proxy` + FastMCP in both languages, and
  offline through the re-recorded replay fixture, which now carries the notification
  exchange and its real 202. The demo proxy that both e2e proofs run against had itself
  drifted from the production serving path here — it had no notification branch, so the
  message fell through to the bodied signer — which is why a serving-path test now drives
  `build_signed_notification`'s own envelope end to end.

- **The ADR-MCPS-035 audit surface the serving path claimed to have.**
  `HttpProfileProxy::handle` emitted nothing on any exit, so a deployment relying on
  the documented audit trail for post-incident attribution had no record of which
  actor was admitted, which wire code caused a rejection, or which key signed a
  response. The profile's 23 wire codes proved to be a strict subset of the frozen
  43-code `McpReError` taxonomy, so the surface is emitted without minting a parallel
  set of reason names; a drift guard now asserts the containment holds.
- **A client leg that can actually carry the profile.** `mcp-re-transport` was an
  object-profile-era crate: bytes-in/bytes-out was a complete transport API only while
  evidence lived in a JSON `_meta` block. ADR-MCPRE-050 moved evidence to RFC 9421
  headers and the status line — the two things that API discards. On the request side
  the request line was a fixed literal with no header parameter at all, so a signed
  request arrived carrying **no evidence whatsoever** (C057/C061/C071).
- **Live GKE fleet validation, and a free local rehearsal of it.** The four coherence
  proofs now run on a real GKE fleet (2× `e2-standard-2`, zonal, Workload Identity,
  Cloud KMS root, Artifact Registry images), and identically on a local kind cluster
  via `PROVIDER=kind`. The kind lane found six deploy defects — three fatal to the
  cloud run — before a cluster was created.

### Changed
- **BREAKING (profile): a signed bodyless `202` binds to a TRANSMISSION, not to
  content (owner ruling C019b).** The content-level binding in §3.4 is replaced, not
  retained as a weaker optional mode. Under it, a captured `202` could be presented as
  evidence for a later byte-identical retransmission that the server had in fact
  rejected as a replay: the server could distinguish the two transmissions while the
  client could not determine which one the acknowledgement belonged to.
  Proof-of-acceptance semantics must not collapse distinct delivery attempts.
- **BREAKING (SDKs): `unsafe_drop_notifications` / `unsafeDropNotifications` and their
  observers are removed, along with `NotificationsUnsupported` and (Python)
  `UnsafeConfigurationRefused`.** They existed only because the notification profile did
  not; retaining a knob that silently discards `notifications/cancelled` now that it does
  would keep a superseded weaker mode alive. A notification whose acknowledgement does not
  verify raises `NotificationNotAcknowledged` and fails the transport closed.
- **Both SDKs refuse a client→server RESPONSE explicitly (`ClientResponseUnsupported`).**
  Previously it fell into the same branch as a notification, which was harmless while that
  branch dropped everything. Now that the branch transmits, a response — which has no
  `method` — could only be carried by signing a fabricated message and reporting ITS
  acknowledgement as if the response had been delivered. MCP-RE profiles a signed request
  and a signed notification; a response is neither, so it fails closed.
- **Conformance corpus: `h50_bodyless_202_retransmission`.** The transmission-distinct
  splice — two notifications identical in method, target and body, differing only in nonce —
  pinned as `mcp-re.request_binding_mismatch`. `h37` covers the content-distinct half; this
  is the case content-level binding could not express at all (owner ruling C019b).

### Fixed

*Controls that existed but were never reached by the serving path (round 1, 12 root
causes over 21 clusters):*
- **No `VerifierPolicy` was ever attached.** `app.rs` never called
  `with_verifier_policy`, so `VerifierPolicy::default()` always won:
  `--max-clock-skew` reached only replay retention while the freshness gate ran a
  hardcoded 30s, and `McpTransportPolicy` was unreachable from any shipped
  deployment. One value now drives both the acceptance window and `retain_until`.
- **The revocation-tier resolver was built, its guarantee printed, and dropped**
  (`let _ = &resolver;`). The PEP resolved signers from a boot-time `HashMap`, so a
  revoked key kept verifying until restart on **every** tier — including
  `--revocation-tier live`, which advertises a near-zero window.
- **CRL hot-reload wrote to a config nothing re-read.** The `TlsAcceptor` was built
  outside the accept loop, so the documented per-connection read never happened.

*Trust, revocation and credential identity:*
- **The trust-epoch kill switch did not survive a replica restart** (C007/C017). A
  restarted replica adopted the advanced shared counter as its own baseline and kept
  minting an epoch verifiers still accepted — the switch was process-relative, not
  durable. The emitted epoch is now a pure function of (base label, shared counter).
- **A revoked root still verified its descendants** (C064/C065). `verify_delegated_
  response` takes a root resolver and a revocation source as independent arguments; a
  caller who built the resolver from a `TrustedIssuerSet` but passed an empty
  revocation list verified credentials under a root they had marked REVOKED. The
  negative control returned `Success` — a full bypass of the one action that
  invalidates every descendant credential.
- **The delegation credential `jti` collided across a fleet** (C034). It was
  `issuer_kid#counter` with a per-instance counter starting at 0, while `jti` is a
  *revocation* identifier: revoking one revoked the corresponding credential on every
  replica, and after a restart a freshly-minted credential could be born already on a
  denylist. Now `{issuer_kid}#{delegated_kid}#{counter}`.
- **The server-signer pin bound to the wrong key** (C004b). It now binds to the root
  issuer kid — the anchor a credential proves a chain to — not the delegated kid, an
  RFC 7638 thumbprint the rotor mints fresh every TTL.
- **A trust-store outage was indistinguishable from an unknown keyid** (C079). The
  verifier seam was `Fn(&str, SignerSlot) -> Option<ResolvedActor>`, and an `Option`
  cannot carry that difference, so an outage was reported as `actor_binding_failed`
  and `mcp-re.trust_resolver_unavailable` had no emission site in the tree.

*Ordering and the MRT continuation:*
- **Nothing irreversible may precede admission** — and the MRTR continuation was both
  reachable and destructible. Its store key was `SHA-256(requestState)` with no actor
  component, and `requestState` is minted by the inner application. The audit called
  this a cross-tenant DoS; the added negative control returns **200**, so a second
  verified actor could *complete* the victim's human-approval round trip. The entry
  was also read destructively by `GETDEL` before the binding was checked, so merely
  naming another actor's `requestState` deleted the retained bases for good.

*Signing core and canonicalization:*
- **String signature parameters had no escaping contract** (C092). `split_dictionary`
  toggled its in-quotes state on every `"` with no regard for backslash escapes, and
  the splitters run before any value can be validated. Refused rather than escaped,
  following the existing `parse_i64` rule.
- **RFC 8941-invalid integers were accepted** (`created=+1700000000`) by rebuilding
  `@signature-params` from parsed values rather than the covered bytes — a signature
  verified over bytes it never covered. Duplicate covered-component identifiers are
  now refused per RFC 9421 §2.5.
- **Bodyless requests did not cover conditionally-mandatory headers** (C047/C093).
  `authorization`, `dpop` and the coverable MCP transport headers were signed and
  required on a bodied request but neither covered nor required on a bodyless one, so
  a bodyless request could present an `authorization` header outside the signature.
  Both paths now share one source of truth.
- **`@target-uri` reconstruction was not compared** (C008/C045/C046). Operator
  assertion is the sanctioned mechanism for a TLS-terminating deployment; what was
  missing was the word EXACT.
- **The nonce floor was enforced where nonces are accepted, not where they are
  emitted** (C080/C088) — so the `nonce_factory` / `nonceFactory` override, the actual
  gap, was unchecked. Both production generators already clear the floor.
- **A retained chain was verified against the caller's live clock** (C033), so an
  intact multi-turn record older than one freshness window could never be labelled
  `Complete` — the label decayed with age instead of describing the evidence. Every
  fixture had signed all hops inside one window, which is why 18 tests passed over it.

*Replay tier, KMS and configuration:*
- **`REDIS_WAIT_QUORUM` was demanded by config and unimplemented on the async store
  that actually serves.** A tier declaring "WAIT" returned `Fresh` the moment the SET
  landed on the primary, so a nonce could be admitted and then lost with the primary.
- **The KMS endpoint override was substituted into request URLs with no validation**
  (C054/C083). That URL carries the root-key trust bootstrap, and on GCP every request
  also carries a live workload-identity bearer token — so an attacker-named endpoint
  both exfiltrates a replayable credential and supplies the root signing key, with
  every local fail-closed check still passing self-consistently. `https://` is now
  required, `http://` only to loopback.
- **The delegated-key rotor hot-spun the root KMS through the whole overlap window**
  (C012) — a root outage during the overlap, exactly what the overlap exists to
  absorb, produced a tight retry loop instead of the bounded jittered backoff written
  for it, because a failed issuance was reported as success.
- **Three config-surface fail-open paths** (round 6): `--signing-key-seed` was
  required for every key source, so a `gcpKms` deployment had to provision a raw
  Ed25519 seed it never reads; the key-file permission check was pointed only at the
  signing seed, so `tls.key` was never checked outside `fileSeed` custody.
- **A strict key-file floor made non-root pods unstartable** (C053b) — a Kubernetes
  Secret mounted for a non-root uid is delivered mode 0440, so a security control
  blocked a security improvement. Resolved by teaching the check the mount model
  (explicit opt-in + the group must be one the process is actually in), not by
  relaxing it.
- **A PKCS#11 PIN on argv, a colliding credential id, and an unbounded await**
  (round 8).

*Deploy surface:*
- **Every deployed image tag now resolves from `VERSION`** and is gated
  (`scripts/deploy_image_tag_gate.py`), including a *deployed-but-never-built* check:
  the SLO bench lived in its own Cloud Build config, so `gcloud builds submit` produced
  a registry that looked complete and silently lacked it. All four images build from
  one config.
- **The inner-plane NetworkPolicy was inert on a cluster created without
  `--enable-network-policy`.** The inner plane speaks plain HTTP with no auth of its
  own, so any pod in the cluster could POST straight past the PEP — no signature, no
  replay admission, no audit record. The v0.11/v0.12.1 runs were in exactly that state.
- **The proof client never sent the path it signed** — it hardcoded `POST /` while
  signing `@target-uri = …/mcp`.
- **Bazel/cargo parity was broken for three test targets**, two since round 1, so
  every round reported as verified in between had been verified on the cargo lane only.

- **CI installed an upstream `mcp` the package forbids.** The Python wheel job named
  `"mcp>=1.16"` itself instead of installing the wheel's own `mcp` extra, so it
  bypassed the `<2.0` cap `pyproject.toml` declares. When upstream published **mcp
  2.0.0** — in which `JSONRPCMessage` stopped being a RootModel and became a plain
  union alias, so it is neither callable nor carries `.root` — the job installed it
  and 33 SDK tests failed on a branch that had not touched the SDK. The constraint now
  has one source. (Supporting mcp 2.x is separate, deliberately unclaimed work.)
- **Python SDK: the nonce floor was defined but never called on the signing path.** The
  C080/C088 check shipped with its unit tests passing while the production call site still
  used the unchecked factory, so a caller-supplied sub-floor `nonce_factory` was accepted
  exactly as before — in Python only, with TypeScript enforcing it. Both SDKs now check at
  sign time, for requests and notifications alike.

### Security
- **`cryptography` 46.0.7 → 48.0.1** (Dependabot #13). Wheels below 48.0.1 statically
  link a vulnerable OpenSSL (high; OpenSSL secadv 20260609). This pin is the repo's
  sole `cryptography` declaration — the RFC 9421 cross-verification no-merge gate —
  and Ed25519 sign/verify is RFC 8032-stable across these versions, so the
  deterministic gate's agreement result is unchanged.
- **TypeScript SDK (`@mcp-re/sdk`) → 0.1.1.** Forced the dev/peer-tree `@hono/node-server`
  to `^2.0.10` via an npm `overrides` entry, clearing GHSA-frvp-7c67-39w9 (moderate; Windows
  `serve-static` path traversal via encoded backslash). The advisory's only fix is in the 2.x
  major, which `@modelcontextprotocol/sdk@1.29.0` blocks through its `^1.19.9` pin — the
  override is the sole resolvable path (Dependabot reported `security_update_not_possible`).
  Verified compatible: the MCP SDK's single `getRequestListener` usage is unchanged in 2.x,
  `tsc` clean, 129/129 tests green. Same `overrides` also pins `fast-uri` to `^3.1.4`
  (GHSA-v2hh-gcrm-f6hx, high). `npm audit` now reports 0 vulnerabilities.

## [0.13.0] — 2026-07-18

### Added
- **v0.13 conformance to the published HTTP-profile set (epic #435; rev-2 profiles in
  Discussions #414/#415/#416).** The RFC 9421 + RFC 9530 serving path was aligned to the
  audited profile text across the whole surface: §3.4 JSON-mode enforcement on covered
  exchanges (`text/event-stream` responses refused, #423); the §4.1 MCP transport + version
  contract covering `mcp-method` / `mcp-name` / `mcp-protocol-version` and rejecting a
  covered-header/body method divergence (#425); a typed algorithm registry with thumbprint
  keyids and bounded, symmetric clock skew (#428, #432); the verified-context carrier with a
  reserved-field guard that strips caller-seeded context on every request (#429); continuation
  §9/§13 retained-chain reconstruction with incomplete-chain labelling and a multi-hop
  conformance corpus with role domain separation (#430, #431); admission-assertion binding to
  §7 evidence (#433); and a content-pinned vector corpus (per-file SHA-256 + manifest digest,
  #427). MCP protocol version **2026-07-28** is RC-aligned (#426); the final-text conformance
  declaration follows its publication.
- **Delegated bodyless signed-202 acknowledgement (#424; owner ruling for #418).** A one-way
  notification is answered with a signed HTTP 202 whose compact-JWS delegation credential
  rides in a covered `mcp-re-delegation` header (the one narrow bodyless exception), bound to
  the request evidence via `;req`. It states that the enforcement boundary authenticated and
  accepted the message — never that any action completed.
- **Layer-5 portable audit receipts on SCITT (RFC 9943), offline-verifiable prototype (#434).**
  An offline-verifiable receipt mapping; the external transparency-service submission and the
  CBOR/COSE (RFC 9942) wire interop remain follow-ups.
- **SDK request/response transport adapter (`McpReHttpTransport`), Python and TypeScript.**
  A standard `mcp.ClientSession` / `Client` now speaks MCP-RE by construction: the adapter
  signs each outgoing request and verifies each incoming delegated response underneath it,
  so application code calls `session.call_tool(...)` and never invokes sign/verify itself.
  This is the ADR-MCPS-044 wrap-or-fork endpoint — the transport is the only seam with
  exact-byte control, because both MCP SDKs serialize JSON-RPC *inside* each transport.
  Freshness (nonce) is adapter-generated rather than caller-supplied: a nonce that repeats
  in-window is a defect, not a policy knob. Every failure is delivered as a JSON-RPC error
  correlated to its request — an unverifiable response can neither reach the application
  nor hang it. Exchanges run concurrently, bounded by `max_concurrent_exchanges` /
  `maxConcurrentExchanges` (default 8).

  **It was not a general standard-MCP transport at this release.** Sending a one-way
  `notifications/*` message failed closed (`NotificationsUnsupported`) because MCP-RE had
  not yet ratified the one-way notification **+ acknowledgement** profile (#418); a
  standard client could not complete its mandatory `notifications/initialized` without the
  interim `unsafe_drop_notifications` / `unsafeDropNotifications` opt-in, which a hardened
  `SignerPolicy` refused outright (`UnsafeConfigurationRefused`). Both the profile and the
  SDK support landed after this release — see Unreleased. Callers still supply the HTTP leg via an injected
  `poster`; `connect_mtls_http` / `connectMtlsHttp` remain unbuilt (#413). The
  ADR-MCPS-047 open leg is implemented (`on_input_required` surfaces the answer leg's
  handles) but the adapter does not drive the answer leg (#419).
- **A recorded delegated-session fixture** (`sdk/fixtures/delegated_response_replay.json`,
  regenerated by `tools/gen_sdk_transport_fixture.py`). The live proxy e2e tests self-skip
  in the SDK downloader lanes — the one place the shipped artifact is gated — so both SDKs
  replay a recording of a genuine delegated session offline instead: an accepted call, an
  ADR-MCPS-047 elicitation open leg, and a delegated rejection receipt. Recorded through
  the adapter itself and request-byte-asserted on replay, so the fixture also extends the
  cross-language parity oracle from the primitives to the transport.

### Fixed
- **The kind/GKE multi-replica validation harness pointed the proxy at the inner backend
  without a trailing slash.** FastMCP serves Streamable HTTP at `/mcp/` and 307-redirects
  `/mcp`; the proxy's raw inner client does not follow redirects, so ordinary `tools/list`
  calls fail-closed to a signed `-32603`. The four fleet proofs still passed (they assert the
  security-envelope verdict — replay, trust-epoch, continuation, zero-drop — not the inner
  result), but the served path never reached the backend. Corrected to `/mcp/` (matching
  `deploy/k8s/inner-fastmcp.yaml`); the proofs now return real inner results.
- **TypeScript `Signer.signRequest` dropped authorization bindings.** The
  `bindingsJson` argument was never forwarded to the core, so a provider-supplied artifact
  binding could not reach the evidence from TypeScript. The Python binding was unaffected.
- **The two SDK adapters disagreed on concurrency.** Python's pump awaited each exchange
  before reading the next request, serializing every call on a session (one slow tool call
  blocked all others); TypeScript ran them concurrently and unbounded. Both now run
  bounded concurrent exchanges with the same default, asserted by a cross-SDK test that
  measures peak in-flight posts. Freshness, correlation, and fail-closed behaviour are
  unaffected — each exchange already carried its own nonce and correlation entry.
- **The concurrency bound was unvalidated.** A bound of `0` did not throttle, it
  deadlocked: every sender waited for a slot that could never be released, silently.
  Both SDKs now refuse a non-positive / non-integer bound where the value enters.

### Changed
- **Transport shutdown contract (#421), both SDKs.** `close()` is abortive, matching the
  upstream client's rejection of pending requests: new work is refused the instant close
  begins, in-flight exchanges are aborted and fail connection-closed, poster work is
  cancelled where possible, abandoned correlation state is cleared, and **no message
  callback fires after the close callback**. It makes no claim that already-dispatched
  remote work has stopped. TypeScript gains an explicit one-way `NEW → OPEN → CLOSING →
  CLOSED` state (`TransportState`) and `ConnectionClosed`; Python's lifecycle is the
  `async with` block. Two real defects fixed: TypeScript delivered `onmessage` *after*
  `onclose` and let a `send()` after `close()` reach the poster; Python abandoned
  correlation entries on exit.
- **The SDK is not releasable yet, and says so.** One boundary remains: the one-way
  notification + acknowledgement profile (#418). `main` carries the honest fail-closed
  implementation; shipping waits on it.
- **The SDK parity contract is written down** (`sdk/PARITY.md`). Byte parity and
  behavioural parity are separate gates: the frozen fixtures pin what the SDKs *emit* and
  cannot see what they *do*. Concurrency, resource bounds, error propagation, lifecycle,
  notification handling and shutdown must each be measured in both languages. Deliberate
  asymmetries are recorded there rather than left to be rediscovered. Shutdown moved from
  "undecided" to a covered behavioural dimension in the same cycle (#421).
- **`@mcp-re/sdk` declares `@modelcontextprotocol/sdk` as an optional peer** and ships the
  adapter from the subpath `@mcp-re/sdk/transport`. The upstream MCP SDK is needed only to
  open a session, so the root entry point keeps no hard runtime dependency — the same line
  the Python package draws with its `mcp` extra.

## [0.12.1] — 2026-07-14

**First live KMS-via-Workload-Identity GKE run — a real bug fixed, the run made
deterministic, and the §7 SLO baseline re-measured on the current serving path.**
A patch release: a proxy bugfix that only a live Workload-Identity-on-GKE run can
surface, plus the validation tooling and baselines that run turned up.

### Fixed
- **Cloud KMS Workload-Identity token URL.** `mcp-re-proxy` fetched the GKE
  metadata-server access token from the singular path
  `/computeMetadata/v1/instance/service-account/default/token` (HTTP 404), instead
  of the correct plural `/service-accounts/…`. Under `keySource=gcpKms` +
  `useMetadata` (the on-GKE custody), this failed key resolution and crash-looped
  the fleet. Local/kind never hit it (kind uses the operator-token path, not the
  metadata server), so only a live WI-on-GKE run exposed it
  (`mcp-re-proxy/src/gcp_kms_keysource.rs`).

### Changed
- **GKE validation harness is one deterministic cluster shape.**
  `docs/security/gke-multi-replica-validation.sh` now provisions a **Standard,
  zonal** `e2-standard-2 ×2` cluster with `--workload-pool` (Workload Identity),
  matching the SLO runbook §2, instead of an Autopilot **regional** cluster that
  overran the free-trial 16-vCPU cap (the prior `FailedScheduling`). The KMS path
  requires the GSA annotation via helm and refuses the operator-token path on GKE.
- **ADR-MCPRE-051 §7 baselines re-measured on the delegated-required-only path.**
  The local anchor (`docs/bench/adr-051-baseline-local.json`) was recorded before
  the delegated-required-only cutover; re-recorded (median of 6 reps) at 4906.9 rps
  (was 5866.4) — the expected cost of always issuing a delegated-credential-backed
  response signature, not a regression. The GKE production measurements
  (`docs/bench/adr-051-slo-targets.json`) were refreshed on real hardware,
  KMS-rooted via WI: e2-standard-8 395.6 rps / c3-standard-8 492.9 rps (8-core),
  both gated PASS; declared floors unchanged.

### Added
- `docs/security/gke-kms-wi-setup.sh` — fenced, idempotent, non-destructive
  Workload-Identity → Cloud KMS binding (GSA + key-scoped `cloudkms.signerVerifier`
  + WI binding).
- `docs/security/gke-slo-phase.sh` — the SLO runbook §4 as one rerunnable script
  (drop fleet → two 8-vCPU class pools → four jobs → gate).

### Known issues
- **Proof 4 (zero-drop rolling update) is not yet green on GKE** — a rollout dropped
  2 of 590 in-flight requests (a GKE kube-proxy endpoint-propagation timing gap; the
  in-process and kind lanes pass). Likely resolved by a longer `drainPreStopSeconds`;
  tracked as a follow-up.

## [0.12.0] — 2026-07-13

**Serving-path consolidation + a re-measured GKE SLO baseline.** v0.12 finishes the
RFC 9421 cutover on the proxy serving path and re-baselines the ADR-MCPRE-051 §7 SLO
on real GKE hardware under the v2 canonical envelope.

### Changed
- **Proxy serving refactor.** The serving / replay-tier / transport-binding wiring
  moves out of `main.rs` and `cli.rs` into a dedicated `App` runner
  (`mcp-re-proxy/src/app.rs`); `main.rs` and `cli.rs` become thin argument-parse +
  delegation. The production listener runs the RFC 9421 `HttpProfileProxy` path.
- **OCSP is always fail-closed.** The `--ocsp-soft-fail` (fail-open) relaxation was
  removed; an online-OCSP `require` build now rejects on any
  indeterminate/unreachable/timeout result. Hardening — the secure default and the
  only remaining posture.
- Pruned now-unused workspace dependencies (`Cargo.lock`, `MODULE.bazel.lock`).

### Added
- **ADR-MCPRE-051 §7 SLO baseline — re-measured on GKE under the v2 envelope and
  DECLARED.** RFC 9421 carrier, cold TLS1.3-mTLS, concurrency 128 / 8000 requests:
  e2-standard-8 71.5→402.1 rps (per-core 0.703); c3-standard-8 93.0→499.4 rps
  (0.671). `production_slo` in `docs/bench/adr-051-slo-targets.json` flips
  `pending`→`declared`; `scripts/slo_gate.py` accepts report schema v1 or v2.
- Containerised SLO runner: `tls_load_harness_bench` honours
  `MCP_RE_LOADGEN_REDIS_URL`; `tools/slo/run_slo_job.sh` provisions a
  primary+2-replica Redis as native sidecars.
- SDK downloader smoke tests restored (`sdk/python/tests`, `sdk/typescript/test`):
  wheel/napi import + an RFC 9421 signing round-trip against the built artifact.

## [0.11.0] — 2026-07-10

**The HTTP-profile release.** v0.11 makes the RFC 9421 + RFC 9530 HTTP standards
profile the sole carrier (ADR-MCPRE-050), lands the async per-core serving fleet
(ADR-MCPRE-051) and delegated signing (ADR-MCPRE-052), **removes stdio from MCP-RE
entirely**, retargets both SDKs to the HTTP model, and proves the whole thing end to
end on a **live GKE fleet — including an SLO baseline measured on real cloud
hardware.**

> **Net effect of this cycle on stdio.** Several entries in this section were added
> earlier in the 0.11 cycle and then **removed by the owner decision that stdio is
> out of scope for MCP-RE** — `mcp-re-stdio-bridge`, the stdio demo/fileserver and
> server, `mcp-re-client-proxy-cli`, `mcp-re-walkthrough`, and the stdio conformance
> harness were all deleted (not kept as compat), along with the Helm stdio-bridge
> sidecar. The **shipped 0.11 contract is HTTP in, HTTP out only**; a stdio-only MCP
> server is fronted by an external plain-MCP adapter (e.g. FastMCP) that speaks HTTP
> to the proxy. Read the detailed subprocess/bridge entries below as *cycle history*,
> superseded by "stdio removed" in the release highlights.

### Release highlights (completing 0.11)

- **ADR-MCPRE-050 controlling — one HTTP profile.** RFC 9421 + RFC 9530 is the sole
  over-the-wire carrier; the legacy JCS/object envelope is superseded and new evidence
  is JOSE/JWS.
- **stdio removed — HTTP-profile only** (owner decision, see the note above).
- **ADR-MCPRE-052 delegated signing** — JOSE/JWS delegation credential + custody, 22
  golden vectors (d01–d22), and an independent python-cryptography JOSE cross-verify
  gate (both directions), CI-wired.
- **mTLS transport binding (RFC 8705 x5t#S256)** proven over a real mutual-TLS
  handshake against the production stack: own channel accepts, a relayed request over
  another valid channel fails closed.
- **Both SDKs retargeted to the HTTP profile.** Python (PyO3) + TypeScript (napi-rs)
  bind the audited `mcp-re-client-core`; `McpReHttpTransport` / `connectMtlsHttp` sign
  outbound / verify inbound bytes so an unmodified `mcp` client speaks plain MCP over
  one signed mTLS POST. **Live cross-process e2es against the real `mcp-re-proxy`**
  front an in-process HTTP MCP backend; `read_file` declares an `outputSchema` so the
  round trip is genuinely validated. (SDK stdio driver/transport removed.)
- **Kubernetes / deployment surface.** HTTP-profile-only Helm chart (`strict` +
  `fleet`, fail-safe defaults, gcpKms Workload-Identity custody), new chart knobs
  `transportBinding` (default = the proxy's fail-safe `exact`) and `drainPreStopSeconds`
  (preStop delay closing the L4 LB endpoint-propagation race); `deploy/docker/
  Dockerfile{,.inner,.bench}`; a FastMCP Streamable-HTTP inner backend
  (`tools/fastmcp_inner_backend.py`, `deploy/k8s/inner-fastmcp.yaml`); native amd64
  builds via `deploy/cloudbuild/*`.
- **Live GKE validation.** On a real 2-node GKE fleet (strict + exact binding, FastMCP
  inner): **cross-replica replay coherence** (nonce accepted on replica A → rejected as
  replay on B via the shared tier) and a **zero-drop rolling update** over a real L4
  LoadBalancer. Runbook: `docs/security/gke-slo-baseline-runbook.md`.
- **Live GCP Cloud KMS lanes** — object-signing, delegated-TLS handshake, draft-02, and
  RFC 9421 request/response all signed by a real Cloud KMS Ed25519 key and verified by
  the unmodified verifier (tamper / wrong-key / untrusted-client negatives).
- **ADR-MCPRE-051 §7 SLO — production baseline DECLARED, two complementary gates.**
  The MCPRE-110 `local_regression` gate (`scripts/adr051_slo_gate.py`, a fresh run vs
  the committed dev-box anchor) and the MCPRE-123 `production_slo` gate
  (`scripts/slo_gate.py`, absolute per-hardware SLO) are unified in one
  `docs/bench/adr-051-slo-targets.json` (`local_regression` / `production_slo` /
  `absolute_gates`). `tls_load_harness_bench` (spawning the real async proxy at N
  cores) baselined on **real GKE hardware** (e2-standard-8 + c3-standard-8, 1 and 8
  cores) flips `production_slo` `pending → declared`: throughput floor 250 rps,
  p50/p99/p999 ceilings 250/600/900 ms, per-core linear factor ≥ 0.60, both classes'
  raw numbers recorded; the gate enforces them and passes for both.
- **Short-lived client cert for strict validation.** `DemoFixtures::short_lived_client_cert_pem`
  mints a ≤3600s leaf (URI-SAN == signer) so a `--strict` fleet — which refuses
  long-lived certs — can be driven live.
- **Release verification.** `cargo test --workspace` 1205/0; feature-gated backends
  649/0; `bazel test //...` 87/0; RFC 9421 + JOSE cross-verify (both directions);
  Python SDK 107/0; TypeScript SDK 106/0; JCS / port-registry / Bazel-drift / SLO gates
  green. Workspace version `0.10.1 → 0.11.0`.

---

_The detailed, chronological cycle entries follow (some superseded per the stdio note
above)._

### Added

- **`mcp-re-stdio-bridge` — the out-of-TCB stdio↔HTTP adapter (ADR-MCPRE-051,
  Phase B, MCPRE-118, part 1).** A new binary crate that fronts an unmodified,
  sandboxed local stdio MCP server behind a plain HTTP endpoint, so the proxy PEP
  can protect a stdio-only server via its stateless HTTP inner plane **without**
  the subprocess/sandbox/env/rlimit attack surface (~3k lines: subprocess
  lifecycle, environment allow-listing, Landlock fs rulesets, seccomp-bpf egress
  filters, `setrlimit`) entering the signing PEP's Trusted Computing Base. The
  bridge accepts a `POST` of an already-verified JSON-RPC body from the PEP,
  relays it to the sandboxed child over stdio (blocking subprocess I/O kept off
  the async workers), and returns the child's JSON-RPC response as the HTTP body;
  non-`POST` is `405`, over-cap bodies `400`, a panicked dispatch `502`. A
  compromise of the bridge cannot forge a signature or defeat replay — those
  guarantees live entirely in the PEP. Phase A reuses the proven hardened
  subprocess inner (`SubprocessInner` / `PersistentSubprocessInner` +
  `InnerLaunchConfig` + the Landlock/seccomp `SandboxProfile` + `RLimits`) from
  `mcp-re-proxy` with secure launch defaults; a later commit of this phase
  physically moves those modules into this crate and cuts the dependency so the
  PEP links none of them. Arg-parse unit tests + an end-to-end HTTP→stdio→HTTP
  relay smoke path.
- **Async authoritative replay tier — seam + L1-never-Fresh (ADR-MCPRE-051 §4,
  Phase 2, MCPRE-117, part 1).** The async data plane checks replay without blocking a
  runtime worker: a new `async_replay` module defines `AsyncAtomicReplayStore` — the
  async analogue of `shared_replay::AtomicReplayStore`, one server-side-atomic
  `atomic_insert_if_absent` awaited on the request path — with an in-memory reference
  impl (`InMemoryAsyncAtomicReplayStore`). The per-core `L1FastRejectStore` sits in
  front of the shared authoritative L2: it may fast-reject a key it already knows is
  present (returning `Replay` with no L2 round-trip) but **can never answer `Fresh` —
  `Fresh` is produced only by a winning L2 insert.** The property is enforced BY
  CONSTRUCTION (the L1 lookup returns `Some(Replay)` or a miss — a type that cannot
  express `Fresh`) and BY TEST. L1 is bounded per core with FIFO eviction that is
  always safe (an evicted known key costs an L2 round-trip, never a false `Fresh`); an
  L2 outage fails closed (`ReplayCacheUnavailable`) and recovers clean. A deterministic
  suite (`async_replay_test`) proves L1 fast-reject-without-L2, eviction safety, outage
  fail-closed + recovery, and **cross-core EXACTLY-ONE-`Fresh`** (many per-core tiers
  over one shared L2 under concurrency). Concrete async Redis (`SET NX PX`) / etcd
  (CAS) backends implement the same contract next; their live cross-replica proofs run
  in the skip-when-absent infra lane. Conformance target count 79 → 80.
- **Bounded graceful drain across cores — zero-abandoned (ADR-MCPRE-051 §6, Phase
  2, MCPRE-115).** On shutdown, each per-core `async_serve` loop stops accepting and
  then waits up to a bounded grace window (`ServerLimits::drain_grace`, default 30s)
  for its IN-FLIGHT requests to finish before the runtime is dropped — so a request
  already being served **completes rather than being abandoned**, while a stuck
  request cannot delay process exit past the grace (bounded exit). In-flight requests
  are tracked by a per-core RAII counter (`InFlightGuard`, incremented once a request
  is admitted, decremented on every return path); idle keep-alive connections carry no
  in-flight request and so do not extend the drain — an idle drain returns promptly.
  Because each request is also bounded by `request_deadline`, sizing
  `request_deadline <= drain_grace < terminationGracePeriodSeconds` guarantees a clean,
  zero-abandoned drain under a k8s rollout (documented on `drain_grace`). This replaces
  MCPS-88's single-process "≤1 inline request" guarantee with an explicit
  bounded-drain guarantee for the per-core fleet (each core drains before its worker
  thread joins). A deterministic suite (`async_drain_test`) proves an in-flight request
  drains cleanly (200, not abandoned), idle + saturated drains return within bound, and
  a request stalled in the body-read phase cannot delay exit past the grace. The
  SIGTERM/SIGINT → shutdown bridge is CLI wiring (a tracked follow-up); the mechanism
  is driven by the shared shutdown flag. Conformance target count 78 → 79.
- **Per-core bounded admission control + fail-closed backpressure (ADR-MCPRE-051
  §1, Phase 2, MCPRE-114).** The async serving path now enforces a **per-core
  in-flight-request ceiling** (`ServerLimits::max_in_flight_requests`): once a core is
  serving that many requests, the next request is rejected with `503 Service
  Unavailable` **before its body is read or the handler runs** — fail-closed
  backpressure that bounds tail latency under overload instead of queuing work without
  bound. The ceiling is a per-core `tokio::sync::Semaphore` acquired at the top of
  request handling and released on return (RAII, the same fail-closed permit idiom as
  `redis_store`'s `ConnectPermit`), so it stays lock-free ACROSS cores. Config surface
  is both per-core and fleet-global: `FleetConfig::max_in_flight_total` is divided
  evenly into per-core ceilings (`ceil(total / cores)`, at least 1; an explicit
  per-core ceiling wins) — no shared cross-core semaphore on the hot path. `None`
  leaves in-flight unbounded (the historical default). A deterministic suite
  (`async_admission_test`) drives `serve` on a multi-thread runtime with blocking
  handlers to prove over-cap requests get 503 (handler never reached), that the
  uncapped default admits all, and the global→per-core division. **Saturation latency
  bounded-at-cap is measured on the load harness (MCPRE-108) in the SLO lane.**
  Conformance target count 77 → 78.
- **Per-core async serving fleet — SO_REUSEPORT + thread pinning (ADR-MCPRE-051
  §1, Phase 2, MCPRE-113).** A new `mcp-re-proxy` module (`async_fleet`, behind the
  non-default `async_serve` feature) stands up the target data plane: **one worker
  thread per core, each a current-thread `tokio` runtime with its own `SO_REUSEPORT`
  listener and (on Linux) `sched_setaffinity` CPU pinning, running one
  `async_serve::serve` loop over one `Proxy` per core.** The kernel's `SO_REUSEPORT`
  group load-balances accepted connections across the per-core listeners, so there is
  no shared accept lock, no cross-core connection handoff, and no contended cross-core
  hot-path state — the only cross-core sharing is the coherent replay/trust store
  (server-side-atomic, ADR-MCPS-020) and the immutable `Arc<ServerConfig>` /
  `Arc<ServerOptions>` snapshots (a module-level cross-core-sharing audit documents
  this, satisfying the "no cross-core locks on the request path" criterion). Core
  count is configurable (`0` = `available_parallelism`); listeners share one port
  (`:0` resolves on the first bind and is reused). `SO_REUSEPORT` + `bind`/`listen`
  are done via `libc` directly (set before `bind`, which `std::net` cannot express) —
  no new crate, no crate-universe repin; the raw socket is wrapped in an `OwnedFd`
  for fail-closed RAII. This supersedes the MCPRE-112 single-shared-runtime
  scaffolding (never a release). An always-on suite (`async_fleet_test`) proves N
  independent per-core runtimes serve the full mTLS pipeline correctly, that a missing
  client cert fails closed on every core, configurable/auto core counts, and clean
  shutdown+join; on Linux it also asserts `SO_REUSEPORT` distributes connections
  across ≥2 cores. **Near-linear 1→N throughput scaling is measured on the load
  harness (MCPRE-108) in the SLO/CI lane (MCPRE-110/123), not this deterministic
  suite.** Bounded graceful drain across cores is MCPRE-115; per-core bounded
  admission control is MCPRE-114. Conformance target count 76 → 77.
- **In-process CRL hot-reload + versioned serving-config snapshots (ADR-MCPRE-051
  §6, MCPRE-116; subsumes MCPS-66).** The serve loop now reads the current rustls
  `ServerConfig` per connection from a `ServerConfigSnapshot` (a dependency-free
  `RwLock<Arc<ServerConfig>>` swap seam) instead of a fixed `Arc`. A new opt-in
  `--client-crl-reload-secs N` spawns a background task that every `N` seconds
  re-reads the `--client-crl` files and atomically swaps in a rebuilt verifier — so
  a **refreshed CRL is honored without a restart**, removing the old
  "restart-before-nextUpdate" requirement. A failed reload keeps the last-good
  config (which still fails closed once its CRL passes `nextUpdate`, via rustls'
  `enforce_revocation_expiration`), so a bad reload never widens what is accepted;
  every reload outcome is logged. The swap/keep-last-good decision (`reload_once`)
  is pure and deterministically tested (no wall clock), and an in-flight handshake
  keeps serving on the config it captured. **Default behavior is byte-identical**
  (no `--client-crl-reload-secs` → the snapshot is never swapped). Direct-TLS path
  in this increment; delegated-TLS reload is a tracked follow-up. The snapshot seam
  is also what the per-core async data plane (ADR-051 §1) reads from.
- **Opt-in async serving path (ADR-MCPRE-051 §1, Phase 2, MCPRE-112).** A new
  `mcp-re-proxy` module (`async_serve`, behind the non-default `async_serve`
  feature) serves over `tokio` + `tokio-rustls` + `hyper` with HTTP/1.1 keep-alive
  and HTTP/2 — killing the one-request-per-connection `Connection: close` wire. It
  is a THIN transport swap: the rustls `ServerConfig` (mTLS verifier + CRL), the
  verified-identity extraction, the per-connection cert-lifetime + routing-header
  rejections, and the request handler are the EXACT SAME ones the blocking
  `serve_once` uses (shared leaf-DER helper cores), so every mTLS fail-closed
  behavior is byte-identical — only the I/O framing is async. `ServerLimits` map
  onto the async stack: the aggregate read deadline bounds the handshake + body
  read (slow-loris), `hyper`'s header-read timeout bounds the header read,
  `max_body_bytes` caps the body (`http_body_util::Limited`), and
  `max_concurrent_connections` is a fail-closed `Semaphore`. A parity suite
  (`async_serve_parity_test`) proves mTLS rejection (missing/untrusted cert),
  identity extraction, keep-alive (N requests / one handshake), 32-way concurrency
  over one shared `Proxy` (`Send + Sync`, MCPRE-111), and the body-cap fail-closed.
  **The default/production closure is unchanged** — it links no `tokio`/`hyper` and
  stays the blocking `std::net` path (ADR-MCPS-018 lean-sync firewall); only the
  `:mcp_re_proxy_async` flavor + its test link the async stack. A shared runtime is
  dev scaffolding only (per-core `SO_REUSEPORT` is MCPRE-113); CLI wiring, an HTTP/2
  client test, load-harness (#313) integration, and online-OCSP-on-async are the
  tracked follow-ups. Conformance target count 73 → 74; 22 async crates enter the
  `async_serve`-only closure (validated by the CI `cargo-deny` gate).
- **Concurrent-TLS-client load harness driving the real listener (ADR-MCPRE-051
  §7, MCPRE-108).** A new harness (`tls_load_harness_bench`) spawns the real
  `mcp-re-proxy` binary and hammers its listener with many concurrent rustls
  **mTLS** clients — accept → TLS/mTLS → verify → inner → sign → respond — so
  every number includes the full serving path (unlike `fleet_throughput_bench`,
  which calls `Proxy::handle` on one thread). It reports aggregate throughput and
  p50/p99/p999 added latency, measures the cold-handshake and keep-alive
  connection modes SEPARATELY (keep-alive reports a realised-reuse fraction ≈ 0 on
  the current `Connection: close` wire), and records the per-core-scaling point.
  The **declared benchmark envelope** is committed alongside it
  (`docs/bench/adr-051-load-harness-envelope.md` + `adr-051-benchmark-envelope.json`):
  hardware class, core count, payload, TLS/signature suite, connection mode,
  replay backend, inner latency. The full run is `#[ignore]` (the §7
  manual/dispatch lane, scaled by `MCP_RE_LOADGEN_*`, optional JSON via
  `MCP_RE_LOADGEN_OUT`); an always-on smoke test self-verifies the harness at tiny
  scale on every battery run. Run against the current single-threaded proxy it
  produces the Phase-0 baseline for the SLO declaration (MCPRE-110). Conformance
  target count 72 → 73.
- **Replay race harness — the authoritative tier admits exactly one `Fresh`
  under concurrency (ADR-MCPRE-051 §4, MCPRE-109).** A new always-on test
  (`replay_race_harness_test`) fires N barrier-released threads at the SAME
  replay key on one shared `AtomicReplayStore` and asserts EXACTLY ONE `Fresh` +
  N−1 `Replay` — cross-core (many threads, one store) and cross-replica (per-
  replica store clones over one backend) — plus the fail-closed path (store
  unavailable ⇒ ZERO `Fresh`). Deterministic: a `Barrier` maximises contention
  and the assertion is an exact count, so there is no timing/sleep flake. The
  in-memory reference tier runs on every `bazel test //...`; the Redis and etcd
  lanes race the same harness on the live store (skip-when-absent; hard-fail
  under `MCP_RE_REQUIRE_LIVE_INFRA`). The full-stack serving-path variant arrives
  with the async data plane (ADR-051 Phase 2). Conformance target count 72 → 73.
- **HTTP standards profile — minimal proof path (ADR-MCPRE-050, seed Work
  Item 3)**: new pure crate `mcp-re-http-profile` implementing the RFC 9421
  HTTP Message Signatures + RFC 9530 `Content-Digest` carrier with the ratified
  covered-component sets, profile tag `mcp-re-http-v1`, labels `mcp-re` /
  `mcp-re-response`, split-form `request_evidence` handle, and fail-closed
  verification (body tamper, response splice, wrong digest, missing covered
  component, stale window, wrong keyid, foreign tag, `Content-Encoding`
  rejection). Wire-code verdicts reuse the frozen `mcp-re.*` taxonomy — no new
  tokens. Independent oracle: RFC 9421 Appendix B.2.6 known-answer test
  (byte-exact signature base; deterministic Ed25519 `sig-b26` byte-match).
- **HTTP-profile conformance corpus seed (Work Item 4)**:
  `mcp-re-conformance/tests/vectors/http-profile/` — 8 frozen fixtures with a
  static oracle (signature base, `Content-Digest`, Ed25519 signature bytes,
  evidence handle) plus a regenerating drift guard; draft-01/draft-02 corpora
  untouched.
- **Standards issue tracker (Work Item 5)**:
  `docs/spec/http-profile-open-questions.md` — grill-resolved questions vs.
  open items with named triggers (wire-code mapping ratification, third-party
  RFC 9421 CI cross-verification, artifact-binding/rejection/MRTR slices).
- **HTTP standards profile — full profile + parity gate green (ADR-MCPRE-050,
  MCPRE-92…103)**: the full profile is implemented and integrated — active
  `se.syncom/mcp-re.http.request` / `.response` body evidence blocks
  (audience + strict DPoP/mTLS/RAR artifact bindings, `server_signer` +
  `request_evidence` response binding), resolved-actor trust seam, the
  five-tuple replay key `(profile_id, signature_label, actor_id, audience_hash,
  nonce)` packed onto the existing replay-cache tiers, signed rejection
  receipts, and MRTR continuation rebased onto three standards-derived handles
  (previous-request / input-required-response signature-base digests + a
  `requestState` digest). A pure profile-level dispatcher seam
  (`mcp-re-http-profile::dispatch`) drives replay admission and continuation
  binding over verified evidence, failing closed and refusing a single-process
  reference replay cache under fleet-strict. ADR-MCPRE-050 is **Accepted**: the
  parity gate is declared green on the integrated-path battery
  (`full_profile_parity_test`, MCPRE-103) composed with the third-party RFC 9421
  cross-verification CI no-merge gate (MCPRE-99).
- **Fleet proof (c) — MRT continuation survives a mid-continuation replica
  switch (ADR-MCPS-049 W1, MCPS-82).** Completes the three ceiling-lifting
  proofs (alongside replay MCPS-80/81 and revocation MCPS-86): a new always-on
  e2e (`fleet_mrt_replica_switch_e2e_test`) drives an elicitation continuation
  across two independent serving-proxy replicas — leg 1 to replica A, the signed
  continuation leg to a fresh replica B — and B completes it without any shared
  server-side continuation state, because the `continuation` binding rides the
  signed draft-02 preimage (ADR-MCPS-047). Runs in the normal Bazel battery
  (not the Redis live lane): replica-independence of the continuation requires
  no shared cross-node store. No production code change.

### Changed

- **BREAKING — async/HTTP is the sole proxy serving path; sync serving + stdio
  inner are deleted/relocated (ADR-MCPRE-051, MCPRE-118).** The `mcp-re-proxy`
  binary now serves ONLY on the per-core async fleet (SO_REUSEPORT + one tokio
  runtime per core) forwarding to a stateless Streamable-HTTP inner backend; the
  blocking single-threaded serve loop and the synchronous in-memory `Proxy::handle`
  / `handle_with_transport` / `InnerServer` seam are removed. `Proxy::new` no longer
  takes an inner argument — wire the async inner via `.with_async_inner(...)`; the
  async replay tier defaults to in-memory and is swapped for a durable store via
  `.with_async_replay_tier(...)`. **The proxy no longer launches a subprocess:** the
  ~3k-line stdio subprocess/sandbox/rlimit/env surface (Landlock, seccomp-bpf,
  `setrlimit`, subprocess lifecycle) is REMOVED from the PEP's TCB and relocated to
  the out-of-TCB `mcp-re-stdio-bridge` crate. The `--inner-command` flag and all
  `--inner-*`/sandbox/rlimit stdio flags are gone; `--inner-http-url` is now required
  (front a local stdio server with `mcp-re-stdio-bridge` and point `--inner-http-url`
  at the bridge). The async serving path links tokio/hyper unconditionally,
  superseding the ADR-MCPS-018 §1 lean-sync firewall for the proxy serving path.
- **Durable/distributed replay is served by the async fleet (ADR-MCPRE-051 §4,
  MCPRE-118).** `--replay-cache shared` selects an AWAITED async authoritative
  store — `--replay-durability-tier linearizable` → a new async etcd backend (hyper
  over the etcd v3 JSON gateway), otherwise the async Redis backend (`SET NX PX` via
  the tokio client; its `ConnectionManager` reconnect task runs on a process-lifetime
  control runtime distinct from the per-core serving runtimes). `--replay-cache file`
  is not offered on the async fleet (a single file cache does not fit the per-core
  share-nothing data plane; use `shared` for durable cross-replica replay or `memory`
  for single-replica dev). *Follow-up: re-establish the persistent-inner / sandbox
  e2e coverage against the bridge topology (the bridge carries the unit coverage; the
  proxy's old proxy-wraps-subprocess e2e tests were removed with that topology).*
- **Thread-readiness: `Proxy` is now `Send + Sync` (ADR-MCPRE-051 §2, Phase 1,
  MCPRE-111).** Mechanical, no behavior change — the groundwork for the target
  per-core async data plane where a single `Proxy` serves concurrently across
  cores. `ReplayCache::check_and_insert` moved from `&mut self` to `&self`; the
  in-memory reference cache and the file-backed `DurableReplayCache` gained
  interior `Mutex` synchronization (each check-and-insert stays atomic — the
  lock spans check+insert, so a race still yields exactly one `Fresh`); the
  shared/atomic stores were already `&self`. The proxy now holds its replay
  cache directly (the `RefCell` on the serving path is gone), and the boxed
  custody/trust/inner/replay/policy trait-object seams carry `+ Send + Sync`. A
  compile-time assertion (`proxy_is_send_and_sync`) locks the property. The
  `ReplayCacheUnavailable` fail-closed taxonomy is unchanged; `mcp-re-core`
  stays pure (the interior lock is `std::sync`, not I/O/async).
- **Project renamed: MCP-S / MCPS → MCP Runtime Evidence (MCP-RE)** (#289,
  Stages 2–4). A full identity rename, including the wire format:
  - Crates and directories: `mcps-*` → `mcp-re-*`; Rust lib/module names
    `mcps_*` → `mcp_re_*`; types `Mcps*` → `McpRe*`.
  - **Wire format (BREAKING, pre-1.0):** envelope `_meta` namespaces
    `se.syncom/mcps.*` → `se.syncom/mcp-re.*`, error tokens `mcps.*` →
    `mcp-re.*`, canonicalization id `mcps-jcs-int53-json-v1` →
    `mcp-re-jcs-int53-json-v1`, and the response-preimage domain-separation
    tag. All conformance vectors and SDK oracle fixtures regenerated; peers
    speaking the old vocabulary do not interoperate.
  - Environment variables: `MCPS_*` → `MCP_RE_*`.
  - Bazel module `mcps` → `mcp-re`; crate-universe hub `crates_mcps` →
    `crates_mcp_re`; Helm chart `mcps-proxy` → `mcp-re-proxy`; SDK packages
    `@mcps/sdk` → `@mcp-re/sdk` (npm) and `mcps-sdk` → `mcp-re-sdk` (PyPI,
    Python module `mcp_re_sdk`).
  - Preserved as historical record: `ADR-MCPS-NNN` / `MCPS-NNN` work-item
    IDs and dated ADR filenames, grilling-seed docs, dated security scans,
    prior CHANGELOG entries, and the published demo-video sources under
    `demo/video/mcps-intro/`.

## [0.10.1] — 2026-07-05

Horizontally-scaled fleet deployment posture (ADR-MCPS-049) — lifting the
single-node ceiling over proven cross-replica coherence — plus a hermetic PKCS#11
test provider. No wire-envelope or public-API changes; the frozen v0.3 envelope is
unchanged.

### Added

- **Horizontally-scaled fleet posture (ADR-MCPS-049).** MCP-S may now run as N
  identical replicas behind a load balancer without weakening any security claim,
  gated behind an explicit `--fleet` flag (orthogonal to `--strict`):
  - `--fleet` rejects node-local replay caches — a replica must use a shared,
    cross-replica ReplayCache (Redis) so a nonce a second verifier could accept is
    never silently allowed (MCPS-79).
  - `--inner-session` self-declared statefulness field, so a stateful inner server
    is pinned/handled correctly under fan-out (MCPS-83).
  - Redis-backed trust-epoch invalidation source for the ADR-021 Push tier, so a
    revocation propagates across replicas (MCPS-84), with per-tier cross-replica
    revocation-lag bounds (MCPS-85).
  - Graceful `SIGTERM`/`SIGINT` shutdown for rolling fleet deploys (MCPS-88).
  - Cross-replica replay- and trust-revocation-coherence e2e proofs
    (MCPS-80/81/86) and a fleet PEP throughput / added-latency benchmark harness
    (MCPS-89).
  - Kubernetes/Helm fleet deployment reference + guide (MCPS-87).

### Changed

- **PKCS#11 e2e now runs against a hermetic in-tree mock provider.** The
  `pkcs11_keysource` sign+verify and delegated-TLS end-to-end tests
  (`tests/pkcs11_keysource_e2e_test.rs`) previously exercised the token path only
  in a nightly lane backed by an external SoftHSM2 software token; under plain
  `cargo test` they self-skipped. They now build and load a small test-only
  Cryptoki `cdylib` (`tests/mock-pkcs11/`, deterministic in-memory Ed25519 keys)
  that implements exactly the surface the client calls, so the full FFI /
  `C_Sign` (`CKM_EDDSA`) / delegated-mTLS-handshake path runs for real in the
  blocking `cargo` job — no external token or tooling. The mock is a test double,
  not a shipped key store; the vendor-neutral PKCS#11 client interface is
  unchanged. Removed the SoftHSM2 provisioning from the live-infra CI lane.

## [0.10.0] — 2026-07-04

**Mode C — attested ingress.** v0.10 adds the second strict-mode ingress posture:
a controlled ingress attestor terminates or receives validated client mTLS, checks
certificate revocation, and Ed25519-signs a request-bound assertion the
`mcps-proxy` node verifies over a pinned attestor→node channel. Mode C is
*attested delegation*, an explicit opt-in — **not** end-to-end client↔node mTLS
(the load balancer witnesses proof-of-possession and stays in the trusted computing
base). It never widens the wire: **zero draft-02 preimage change** — every Mode-C
fact rides the assertion, never the request. Built on top of v0.9.0
(ADR-023 §C, epic #245).

### Added in v0.10

- **`mcps/lb-ingress-assertion/v2` assertion format + node verifier**
  (`mcps-proxy`). A new frozen, domain-separated, length-prefixed assertion
  (the Tier-3 v1 preimage is untouched). v2 binds a distinct ingress identity,
  the audience/route, the attestor's opaque certificate-verification and revocation
  verdicts (explicit enums — a stale attestor CRL is an explicit `StaleCrl` verdict,
  never a sentinel), a recorded-only CRL `nextUpdate`, and an optional `expires_at`.
  The verifier is **bind-not-interpret** (§C3): it checks signature, freshness,
  `request_hash`, audience, and ingress identity, and admits the attestor's opaque
  verdicts by fail-closed policy — performing no certificate-path validation and no
  CRL-freshness computation of its own. No nonce, no assertion-replay cache.
- **`--transport-binding attested-ingress`** (`mcps-proxy`,
  `BindingKind::AttestedIngress`). Wires Mode C through proxy dispatch with
  fail-closed configuration guards: missing attestor keys, trusted ingress
  identity, audience, or the explicit `--ingress-pinned-mtls` acknowledgement each
  refuse to start (§C2 — the pinned attestor→node channel is load-bearing). Mode C
  is strict-**admitted** (explicit opt-in), unlike Mode B (`lb-assertion`, Tier-2
  header) which remains strict-**rejected**. The node records the three §C2 audit
  trust facts (`delegated_client_identity`, `ingress_internal_hop`,
  `backend_channel_binding = pinned_mtls`) and `revocation_mode = delegated_attestor_crl`.
- **Offline conformance spine** (`mcps-proxy` / `mcps-conformance`). Serve-level
  node-side rejection of a v2 assertion carrying `revocation_result = revoked`, a
  stale-CRL verdict, a bad signature, a cross-request `request_hash`, an untrusted
  ingress identity, a mismatched audience, or a missing header — plus a
  **preimage-invariance** proof that the forwarded draft-02 request is byte-identical
  to Mode A. Eight GREEN-OFFLINE entries added to the traceability manifest.
- **Non-normative Google Cloud cookbook** (§C4,
  [`docs/mode-c-attested-ingress-gcp-cookbook.md`](docs/mode-c-attested-ingress-gcp-cookbook.md)).
  The operator guide for building the attestor on GCP: the Envoy signing filter, GCLB
  `client_cert_*` headers with public-side stripping, CAS CRL lookup keyed on the cert
  serial, and the side-door-closing topology (internal ALB + Private Service Connect;
  Cloud Run `internal-and-cloud-load-balancing`).
- ADR-023 §C (attested ingress) is promoted to Accepted for v0.10; the
  `security-boundary.md` §11 two-posture (Mode A / Mode C) statement is added.

### Not in v0.10 (gaps / deferred)

- **Optional v0.10 tail** — live revocation, an OCSP response cache, cross-cloud
  attestors, and FIPS-140-2 L3 via PKCS#11 — stays deferred / HITL (MCPS-63, #243).
- **Live-cloud attestor QA is supporting-only.** Presenting a genuinely revoked
  client certificate and watching the GCP attestor reject it is operator QA of your
  build, outside the offline MCP-S evidence spine.
- Carried over from v0.9: the live-GCP HSM Ed25519 fact-check (MCPS-59, #239) and the
  in-process CRL hot-reloader (MCPS-66, #246) remain open.

## [0.9.0] — 2026-07-04

**Enterprise hardening — KMS key custody + Mode-A revocation honesty — on a
generated-first build graph.** v0.9 hardens the strict-mode operational envelope
(short-lived-cert Mode-A revocation, offline KMS-lifecycle-vs-trust-policy
custody semantics) with offline-provable evidence, and rebuilds the dual
Cargo/Bazel build so the Bazel graph is generated from the Cargo manifests and
CI-gated against drift. Built on top of v0.8.0.

### Added in v0.9

- **Mode-A strict cert-lifetime ceiling** (`mcps-proxy`). Strict mode now rejects
  a `max_client_cert_lifetime` above 3600s (previously strict only rejected
  none/0), tightening the short-lived-cert revocation posture (ADR-023 §A1).
- **Static CRL fail-closed-on-stale** (`mcps-proxy`). `--client-crl` enforces
  revocation-list expiration (rustls `enforce_revocation_expiration()`; the prior
  default was fail-open `Ignore`), plus a pure `crl_freshness()` startup gate
  (strict = refuse-start on a stale CRL; otherwise warn) and explicit
  OCSP-no-AIA → Unknown honesty. This is the restart-before-nextUpdate path; the
  in-process hot-reloader is deferred (MCPS-66).
- **Offline KMS-lifecycle custody negatives** (`mcps-proxy`, gcp/aws features). A
  fault-injecting FakeGcp backend + offline negatives proving the ADR-028/021
  custody sentence: KMS disable → sign-fail; destroy → construct-fail; a disabled
  KMS key is NOT verifier revocation (trust-policy-driven, no live KMS at verify);
  trust revocation rejects an otherwise-valid signature; rotation overlap.
- **Honest KMS protection-level labeling** (`mcps-proxy`, gcp feature). The native
  GCP Cloud KMS adapter documents software-vs-HSM protection precisely; FIPS-140-2
  L3 routes via PKCS#11 (CKM_EDDSA); Ed25519-only. (The live-GCP HSM protection
  fact-check remains HITL / open, #239.)
- ADR-021 / ADR-023 / ADR-028 gain v0.9 delta addendums recording these decisions;
  ADR-028 §C (KMS key custody) is promoted to Accepted for v0.9.

### Tooling

- **Generated-first build graph (ADR-048).** The Cargo/pyproject/package.json
  manifests are the sole human-authored dependency truth; first-party Bazel BUILD
  targets/edges are generated (gazelle_rust) and a **semantic drift gate**
  (`scripts/bazel_gazelle_gate.py`) fails CI on divergence — killing the #220
  Bazel/cargo parity-rot class. gazelle is the drift detector, not the byte-owner.
- **Blocking Bazel CI parity job.** `bazel test //...` + the drift gate now run on
  every push/PR (Bazel was previously ungated — the root cause of #220). The zig
  hermetic toolchain is scoped to darwin cross-compiles so the Linux runner builds
  every target with the native cc toolchain.
- **Downloader-artifact CI** (no Bazel). The maturin wheel (Python SDK) and napi
  package (TypeScript SDK) are built and smoke-installed in clean environments,
  proving the cargo/pip/npm downloader path.

### Not in v0.9 (gaps / deferred)

- **Mode C attested ingress** (`mcps/lb-ingress-assertion/v2` + attestor +
  `BindingKind::AttestedIngress` + offline rejection conformance) is v0.10
  (epic #245).
- **Live-cloud KMS fact-checks stay HITL** — the GCP HSM Ed25519 protection-level
  verification (MCPS-59, #239) and live revocation lanes are not part of the
  offline-provable v0.9 gate.
- **In-process CRL hot-reloader** deferred to MCPS-66 (#246).

## [0.8.0] — 2026-07-02

**Stateless multi-round-trip continuation + the TypeScript SDK.** v0.8 folds
request-associated elicitation into strict MCP-S as signed multi-round-trip (MRT)
continuation evidence (ADR [047](https://github.com/matssun/mcp-re/discussions/395)), and ships a second
client SDK — TypeScript — bound to the SAME audited `mcps-client-core` as the Python
SDK and the proxy. Built on top of the released v0.7.0.

### Added in v0.8

- **Stateless MRT continuation evidence** (`mcps-core` / `mcps-client-core` /
  `mcps-client-proxy`). A signed `InputRequiredResult` is verified as an ordinary
  server response and classified non-terminal; the client answers with a fresh signed
  continuation request bound to it (`previous_request_hash` +
  `input_required_response_hash`), verified server-side by the ordinary draft-02
  request path (the continuation object rides inside the signed preimage — no bespoke
  proxy code). Non-terminal correlation is associate-without-consume; the client proxy
  drives the elicitation → continuation round trip transparently. Shared conformance
  vectors **d12–d15**.
- **TypeScript SDK** (`sdk/typescript`, NEW). A `napi-rs` binding to the audited
  `mcps-client-core` — the exact analog of the Python PyO3 binding, so the canonical
  signed preimage is byte-identical across every SDK and the proxy by construction.
  Transport adapters (stdio + one-POST-per-request mTLS), authorization-binding
  providers, non-exporting (KMS/HSM) custody, and MRT continuation. Verified against
  the same independent oracle vectors as the Python SDK.
- **Python SDK** conformance driver gains MRT continuation support (parity with
  TypeScript), so the interchangeable-driver matrix stays a true parity harness.
- **Cross-SDK MRT parity matrix.** A safe, deterministic `delete_files` elicitation
  tool on `mcps-demo-fileserver` (a dry-run that carries its pending state in the
  opaque `requestState`) drives the elicitation → continuation SECURITY SHAPE end to
  end through the real four-hop across the **Rust reference, Python, and TypeScript**
  drivers.
- **`McpsHttpTransport` MRT coverage in both SDKs.** The continuation path through the
  request/response transport (record on the `InputRequiredResult` leg, bind on the
  answer leg) is covered three ways: always-run hermetic transport tests, the
  primitives-level four-hop matrix, and a **live** `delete_files` elicit → answer round
  trip driving the transport against the real `mcps-proxy` + fileserver — added for both
  the Python and TypeScript SDKs.
- **Transport hardening (message-boundary correctness).** `serverName` is validated
  against CR/LF before it reaches the HTTP `Host` header (header-injection guard); the
  stdio reader fails closed per message so one malformed line can't tear down the
  transport; the request/response transport delivers exactly one outcome per request id
  (no contradictory success-then-failure on interleaved server messages); and empty-vs-
  malformed inbound-payload handling is byte-for-byte matched across the two SDKs.

### Tooling

- **Two-tier security scanning.** CodeQL moved from default setup to an advanced-setup
  workflow that runs off the per-push inner loop (`push: main` / merge queue / weekly)
  and excludes the test-fixture `hard-coded-cryptographic-value` false positives; a
  `.pre-commit-config.yaml` adds a fast local hygiene + Semgrep tier.
- **Draft-02 corpus pinned by content.** The v0.8.0 draft-02 conformance corpus is
  pinned by digest, not only by Git tag: `scripts/corpus_digest.py` deterministically
  recomputes a `manifest.json` SHA-256 and a whole-directory file-hash-list digest from
  the checked-in bytes, so a reviewer can confirm they are recomputing against the same
  corpus object. The script's output is the normative pin; the scope and values live in
  the [Conformance Guide](docs/conformance-guide.md#v080-draft-02-conformance-corpus-pinning).

### Not in v0.8 (gaps / deferred)

- **Arbitrary server push stays out of strict MCP-S** and fails closed under
  `require_mcps` (ADR-047 / D9); `allow_unverified_server_initiated` remains a
  degraded migration opt-out only, audited as no-evidence.
- **ADR-MCPS-044 (Client-Side Integration Model) stays Proposed.** Both SDKs realize
  it, but its full scope is not yet claimed complete — not overclaiming.
- **ADR-MCPS-046 (Signed Rejection Receipts) stays deferred / design-only.**
- **The TypeScript conformance driver's Cloud KMS path signs via a synchronous
  `curl`** (Node has no native synchronous HTTP, and the napi non-exporting sign
  callback is synchronous); the offline/software path is fully in-process.

## [0.7.0] — 2026-07-02

**End-to-end walkthrough — the v0.7 persona ladder.** v0.7 closes the
"prove v0.7 end-to-end" gap with a real, multi-process MCP-S path: an ordinary
plain-MCP client → `mcps-client-proxy-cli` (signs draft-02, dials mTLS) →
`mcps-proxy` server PEP (verifies draft-02, strips, injects verified context,
serves) → an unmodified inner MCP server, organized as a persona ladder of
runnable tiers (ADR [045](https://github.com/matssun/mcp-re/discussions/393)).

### Proven in v0.7

- **The real four-hop MCP-S path, offline.** T0/T1/T3 run the full topology as
  separate OS processes over mTLS-on-loopback (`mcps-walkthrough`); the server PEP
  now verifies AND serves draft-02 end to end (version-branched forward +
  protected response; draft-01 path untouched).
- **Scoped authorization, deny-before-dispatch.** A reader's `write_file` is
  refused with `authorization_scope_denied` before the inner server is ever
  reached (T2; the inner's own received-log confirms it across processes at T3).
- **Transport-identity binding (T3).** `--transport-binding exact` ties the
  verified mTLS client identity to the request signer; a mismatched identity is
  denied before dispatch (proven by the inner's own append-only log + zero inner
  spawns), while the same cert passes with binding off — isolating the binding as
  the cause.
- **Client Cloud KMS signer (offline + ignored live lane).** A non-exporting
  `KmsClientSigner` (feature `gcp_kms`) signs through GCP Cloud KMS
  (`EC_SIGN_ED25519`, no algorithm substitution); proven OFFLINE against the
  unmodified `mcps-core` verifier via a no-network fake backend, plus an
  `#[ignore]` live lane.
- **Server Cloud KMS support (existing live lane).** `mcps-proxy --key-source
  GcpKms` continues to sign responses from a non-exporting Cloud KMS key
  (feature `gcp_kms_keysource`, live lanes).
- **Integrated Cloud KMS four-hop — Tier T4 (live, #218).** A single live run
  with the client request signer AND the server response signer BOTH non-exporting
  in Cloud KMS (two distinct keys), over the real mTLS socket. The walkthrough
  harness (`FourHop::launch_kms`, feature `gcp_kms`) fetches both KMS public keys
  to wire trust and drives a signed round-trip end to end; `#[ignore]`d, run from
  the cloud script (command 5). PROVEN against a real Cloud KMS project.
- **Secret-hygiene guard.** A tracked-file leak guard
  (`mcps-walkthrough` `no_tracked_secrets`) asserts no real account/project
  identifier is committed; the live-cloud script stays gitignored behind a
  sanitized committed placeholder.
- **Python SDK — request-side slice (#199).** `mcps-python-sdk` gains request
  signing + custody/signer-policy binding (request side only;
  ADR [044](https://github.com/matssun/mcp-re/discussions/392)).
- **Multi-SDK test architecture — pluggable client leg.** The four-hop harness's
  client leg is a `ClientDriver` seam: every MCP-S SDK is an interchangeable client
  behind one stdio + CLI contract (`mcps-client-proxy-cli` is the reference), and
  the `sdk_driver_matrix` runs the tiers against each configured driver (skip-not-
  fail). Ready for the upcoming TypeScript/Rust SDKs (`MCPS_DRIVER_*`).
- **Python SDK — live four-hop interop, software AND Cloud KMS.** `mcps_sdk.driver`
  makes the Python SDK a live client leg: it signs via the SDK's audited core, mTLS-
  POSTs to the real `mcps-proxy`, and verifies the server-signed response. Proven
  green in the matrix; and with `--key-source gcp-kms` the Python client signs every
  request with a NON-EXPORTING Cloud KMS key (`Signer.non_exporting` → `asymmetric
  Sign`) across the integrated four-hop (`t4_python_kms_custody`, live, #[ignore]).
  Both the happy path AND the untrusted-server negative are proven cross-language
  through the four-hop: every driver must fail closed when it cannot verify the
  server's response. Surfaced (and fixed) a real cross-language cert defect: the demo
  TLS leaves lacked an Authority Key Identifier — tolerated by rustls, rejected by
  OpenSSL (Python).

### NOT yet claimed in v0.7

- **Signed rejection reasons across the wire.** A client that fails closed cannot
  yet surface the remote's specific reason (e.g. `transport_binding_failed`) — it
  rides an unsigned error body the client rightly distrusts. The fix (signed
  rejection receipts) is designed, not built: ADR
  [046](https://github.com/matssun/mcp-re/discussions/394).

### Build & test

The **Cargo** workspace is the authoritative, maintained test gate and is fully
green (1104 tests across the workspace, 0 failures). The Cloud KMS lanes and the
live cross-language KMS four-hop are intentionally `#[ignore]`/manual (they require
live cloud credentials). The **Bazel** build has
known, pre-existing **non-gating** `BUILD`-file parity rot — unrelated to this
release — e.g. `//mcps-proxy:mcps_proxy_cli` missing a `//mcps-core:mcps_core`
dep (present already before this epic) and `pkcs11` test-dep gaps; tracked
separately and NOT mixed into this line.

## [0.6.0] — 2026-06-30

**Runtime-evidence preimages — a `draft-02` wire-envelope change.** v0.6
introduces the `draft-02` profile alongside the released `draft-01`/v0.5.1
baseline: two protected envelope identifiers (`version: "draft-02"` and a
self-describing `canonicalization_id`), an explicit canonical-preimage exclusion
predicate, a typed `authorization_binding` object (both `opaque-bytes` and
`authz-system-reference` base forms), nine new fail-closed wire codes, a dual
verifier with strict version dispatch and a required expected-version policy, and
a separate frozen conformance corpus with a static interop oracle.
`draft-01`/v0.5.1 stays byte-for-byte and verdict-for-verdict unchanged.
Resolved in the v0.6 grill (2026-06-29);
ADRs [037](https://github.com/matssun/mcp-re/discussions/385)–[042](https://github.com/matssun/mcp-re/discussions/390).

**Scope.** v0.6 ships the draft-02 profile, verifier, authorization-binding
policy wiring, and conformance corpus (including a live Cloud KMS draft-02
envelope lane). The `mcps-host`/`mcps-proxy` production paths still emit and
serve `draft-01`; adopting the draft-02 signing/serving path end-to-end is a
follow-up. The dual verifier exists so both profiles coexist at the verification
boundary during that migration.

### Documented limitation — integer-only canonicalization (`mcps-jcs-int53-json-v1`)

The first `draft-02` canonicalization scheme keeps the integer-only JSON number
domain (±(2^53 − 1)), named `mcps-jcs-int53-json-v1`. **MCP-S v0.6 does NOT
protect a signed payload that contains JSON fractional numbers** —
`{"temperature":0.7}`, `{"price":19.99}`, a latitude — such messages fail closed
with `mcps.canonicalization_failed` unless the value is carried as a string. This
is an intentional, named, machine-checked scope boundary (a required honesty
conformance vector proves `0.7`/`19.99` are rejected), not a defect: full
RFC 8785 fractional-number serialization is the highest-risk cross-implementation
interop surface and is **deferred to a future, separately-named, separately-
vector-hardened `mcps-jcs-…-v2` scheme** admitted through the canonicalization
allowlist — never by widening v1 ([ADR-MCPS-037](https://github.com/matssun/mcp-re/discussions/385)).

## [0.5.1] — 2026-06-24

**Live Google Cloud KMS validation release.** No wire-envelope changes: this
release proves the already-shipped GCP Cloud KMS adapter against **real** Cloud
KMS and adds a one-command reproduction harness. It is evidence and test surface,
not new protocol mechanism (see
[`docs/security/google-validation-plan.md`](docs/security/google-validation-plan.md)).
The `draft-01` request/response envelopes are unchanged.

### Added

- **Live GCP delegated-TLS test lane**
  (`mcps-proxy/tests/gcp_kms_delegated_tls_live_test.rs`). Proves the proxy's TLS
  *server* private key can live entirely in Cloud KMS and never leave it: the
  server leaf is minted over the KMS **public** key (rcgen `RemoteKeyPair`, no
  private key), and a fully-validating rustls mTLS handshake completes only
  because a live `asymmetricSign` produced the `CertificateVerify`. Negative
  lanes: a leaf not bound to the KMS key is rejected at config construction
  (`DelegatedKeyMismatch`), and an untrusted client certificate is rejected at the
  handshake (fail closed).
- **Object-signing negative lanes** in `gcp_kms_live_test.rs`: wrong-identity (a
  signature must not verify under a foreign key), bad-token fail-closed (an
  invalid access token must fail backend construction), and non-Ed25519 rejection
  (a provisioned RSA key version is rejected at construction, variant-matched).
- **One-command reproduction harness**
  (`docs/security/gcloud-kms-validation.sh`): sanitized, no secrets, `PROJECT_ID`
  placeholder-guarded; enables the KMS API, idempotently provisions the keys, and
  runs both live lanes.
- **First-time Google Cloud onboarding** in the validation plan ("Reproducing
  Stage 1 locally"): the account, billing, project, and `gcloud auth` steps a
  brand-new user needs before running the harness.

## [0.5.0] — 2026-06-23

**Proposal-readiness release over the frozen `draft-01` wire envelope.** 0.5 adds
**zero** wire-envelope fields; request and response envelopes are unchanged. The
work is documentation, conformance, and claim hardening — making every security
claim reviewable and traceable to a green test — not new protocol mechanism. Any
claim `draft-01` cannot support is ejected to a future `draft-02` ADR rather than
smuggled in as a field addition (ADR-MCPS-031, [`docs/spec/proposal-scope.md`](docs/spec/proposal-scope.md)).
Proposal-readiness is gated twice: mechanical CI **and** owner HITL sign-off over
one evidence spine (ADR-MCPS-036; [`security-boundary.md`](docs/spec/security-boundary.md) §10).

### Added — proposal-readiness artifacts

- **ADR-MCPS-031..036 (Accepted).** 031 frames 0.5 as proposal-readiness over a
  frozen `draft-01`; 032 consolidates docs to one canonical boundary + docs root;
  033 defines the two-section v0.5 claim matrix (NSA/threat-coverage matrix
  derived from §A, one evidence spine); 034 makes method-transparency
  CI-enforced; 035 derives the audit-evidence vocabulary from the frozen error
  taxonomy; 036 defines the dual proposal-readiness gate (mechanical CI + owner
  HITL).
- **v0.5 claim matrix** ([`docs/spec/v0.5-claim-matrix.md`](docs/spec/v0.5-claim-matrix.md),
  supersedes the v0.3 matrix): §A per-capability reviewer-facing claims, §B the
  four-axis deployment-tier composition (AND of declared tiers, bounded by the
  weakest).
- **New spec briefs:** [`proposal-scope.md`](docs/spec/proposal-scope.md) (draft-01
  freeze + bind-not-interpret authorization), [`composability.md`](docs/spec/composability.md),
  [`threat-coverage-matrix.md`](docs/spec/threat-coverage-matrix.md); glossary and
  v0.5 grilling seed.
- **Method-transparency is CI-enforced (ADR-MCPS-034):** a behavioral-equivalence
  test plus a static drift guard in `mcps-conformance` (`method_transparency_test`,
  `method_name_drift_guard_test`, `security_traceability_guard_test`,
  `forbidden_claim_guard_test`, `audit_vocabulary_guard_test`).

### Security

- **OCSP DNS-rebinding fix (#128).** The OCSP fetch is pinned to the vetted
  resolved IPs, closing a rebinding window between resolution and connection.
- **OCSP freshness when `nextUpdate` is absent (#136).** Acceptance age is bounded
  by `thisUpdate` + a `max_age` cap instead of being accepted unbounded.
- **Verify-before-return at the remote-signer seams (#137, #138).** PKCS#11 and
  KMS response signing now verify the produced signature before returning it,
  centralized at the response-signer seam.
- **Per-method key-reference scope (#133).** A key reference scopes its target
  per-method; empty-tool grants are rejected.
- **LB-assertion fails closed without a transport binding (#135).** A wired
  load-balancer ingress assertion with no transport binding now fails closed
  rather than admitting.
- **Replay-cache growth bounded (#140).** The file and in-memory replay paths are
  growth-bounded, and durable inline-prune is anchored on a real clock rather than
  request expiry.
- **Non-positive-TTL replay rejected pre-store (MCPS-08, #142).** Requests with a
  non-positive TTL are rejected before the store write, on the etcd backend too.

### Note

Internal version (`VERSION`, workspace `Cargo.toml`) advances from 0.3.1 to 0.5.0.
0.4.0 (below) was tagged retroactively from the hardening-epic history; it carried
no separate release commit, so the source tree at the v0.4.0 tag still declares
0.3.1.

## [0.4.0] — 2026-06-22

**Hardening-epic release (#68).** 0.4 wires the v0.3 tiered multi-node profile from
declared tiers into enforced backends, lands the full audit-remediation cluster
from the v0.4 Stage 1–2 audit round, and purifies MCP-S Core. *Tagged
retroactively* at the first-parent tip of the epic (`09f3250`, just before the 0.5
proposal-readiness work) — the tag was created after the fact, so no release commit
bumps `VERSION`/`Cargo.toml` at this point in history.

### Added — four-axis multi-node profile, wired

- **Axis 1 — LINEARIZABLE CP replay backend (#69).** An etcd-backed CPStore
  replay backend, the concrete realization of the v0.3 `LINEARIZABLE` tier.
- **Axis 2 — near-zero revocation tiers (#70).** Live + push revocation tiers
  wired into the trust resolver, with an injective trust-cache key.
- **Axis 4 — Tier-3 LB-signed ingress assertion (#71).** A request-bound,
  load-balancer-signed ingress assertion, wired into the serve path with
  serve-level acceptance.

### Security & hardening — v0.4 audit remediation

- **Seccomp egress (#98).** `io_uring` egress is denied in the `DenyAll` seccomp
  posture.
- **Production-surface sealing (#81, #83).** Test nonce/clock fixtures are
  feature-gated off the production surface; `VerifiedResult`/`VerifiedResponse`
  are sealed against out-of-band construction.
- **Strict-mode replay durability (#78, #90).** Replay caches self-declare a
  type-level durability class; strict mode rejects a non-durable in-memory cache
  and forbids `inherit-env` together with an env key source.
- **Reference-authz acknowledge gate + epoch-clock diagnosis (#94).**
- **Signed-manifest canonicalization & identity (#85, #87).** Duplicate keys in
  signed manifest bytes are rejected, `key_id` is cross-checked, the validity
  window is skew-tolerant, and inverted windows / unknown wire members are
  rejected.
- **Server read-path deadline (#100).** An aggregate wall-clock deadline on the
  server read path closes a slow-loris exposure.
- **Redis handshake watchdog (#97).** Abandoned Redis connect-handshake watchdog
  threads are bounded.
- **Working-dir TOCTOU (#93).** An explicit `--inner-working-dir` is hardened
  against symlink/TOCTOU with an explicit `O_RDONLY` no-follow open.
- **Key custody (#76).** The unused `Clone` on `SigningKey` is dropped and the
  custody boundary documented.
- **OCSP SSRF guards (#130).** Redirect-follow and empty-label-host SSRF bypasses
  on the OCSP fetch path are closed.
- **Centralized Ed25519 alg gate (#131).** The Ed25519 envelope algorithm gate is
  centralized in Core.

### Changed — Core purification (ADR-MCPS-030)

- The tool-catalog **signed-manifest subsystem is removed from MCP-S Core**; the
  manifest-enforcement design (formerly ADR-MCPS-029) is relocated to MTCI. Core
  is once again pure verification.

### Added — security process

- **Cross-round finding ledger** ([`docs/archive/security/finding-ledger.jsonl`](docs/archive/security/finding-ledger.jsonl)):
  durable per-finding disposition memory so a later audit round verifies only what
  is genuinely new and flags regressions loudly.

## [0.3.1] — 2026-06-21

Security-hardening patch release. No API or wire-format change relative to
0.3.0 — every change is a defensive fix or documentation correction surfaced by
the **Stage 1–2 security-audit funnel** (deterministic pre-scan + 3-lens review,
without the verify gate). Findings were triaged file-by-file: 10 fixed with
regression tests, 3 closed as false positives, and the remaining cluster
deferred to the v0.4 hardening epic (#68) as intentional ADR-MCPS-017
single-node-ceiling posture. The full verified (3-skeptic) scan is scheduled for
v0.4.

### Security

- **OCSP delegated-responder validity window (#95, RFC 6960).** A delegated
  responder certificate presented outside its `notBefore`/`notAfter` window is
  now rejected instead of trusted.
- **Authorization-grant timestamp taxonomy (#88).** An unparseable RFC 3339
  expiry on a delegated grant now fails as `AuthorizationMalformed` rather than
  being misclassified as `AuthorizationExpired`.
- **JCS duplicate-key invariant (#74).** A hand-built `JcsValue::Object`
  containing duplicate keys now fails closed (`CanonicalizationFailed`) rather
  than producing an ambiguous canonical form.
- **Injective trust-resolver composite key (#79).** `InMemoryTrustResolver`
  composes its lookup key with a length-prefixed encoding, removing a
  delimiter-collision class across `(signer, key_id)` pairs.
- **Bounded KMS response reads (#89, #92).** The AWS-KMS response body is read
  under an explicit byte cap (reject only when the length exceeds the cap), and
  GCP-KMS token-expiry arithmetic saturates on overflow instead of panicking.

### Fixed

- **Freshness-window overflow (#82).** Freshness-window expiry uses
  `checked_add`, failing closed instead of panicking on `i64` overflow.
- **Replay prune boundary (#91).** Durable-replay pruning is now inclusive at
  `retain_until` (`>=`), matching the in-memory store and removing a one-tick
  off-by-one retention gap.
- **Response taxonomy precision (#77).** `verify_response` rejects batch and
  notification shapes *before* canonicalization, restoring symmetry with
  `verify_request`.

### Documentation

- Corrected a stale `shared_replay` module doc and documented the
  `sandbox_linux` `try_clone` async-signal-safety caveat (#99, #98).

## [0.3.0] — 2026-06-16

This release adds the **tiered multi-node profile within one trust domain**
(epic #7). v0.2 was production-hardened for single-node deployments; v0.3
makes a *bounded, honest* multi-node claim: each of four security axes declares
a tier, and the composed claim is the **conjunction of the four declared tiers,
bounded by the weakest**. The proxy can never surface a claim stronger than its
configured tier. The enforcement artifacts are
[`docs/spec/v0.3-claim-matrix.md`](docs/spec/v0.3-claim-matrix.md),
[`docs/spec/v0.3-claim-boundary.md`](docs/spec/v0.3-claim-boundary.md), and
[`docs/spec/security-boundary.md`](docs/spec/security-boundary.md), backed by
the conformance manifest and `mcps-conformance` drift guard.

### Added — tiered multi-node claim matrix (the four axes)

- **Axis 1 — replay-store durability (ADR-MCPS-020).** Tiers `REDIS_ASYNC`,
  `REDIS_WAIT_QUORUM`, `LINEARIZABLE` (named; CP backend deferred), and
  `SINGLE_STORE_FAIL_CLOSED`, each surfacing its own honest guarantee.
  Strict-production deployments must declare `REDIS_WAIT_QUORUM` or stronger.
- **Axis 2 — trust propagation / revocation window `T` (ADR-MCPS-021).**
  Bounded-cache eventual trust: revocation enforced fleet-wide within `T`
  (default 60s), fail-closed on store outage past `T`. Zero-window revocation
  is a forbidden claim in v0.3.
- **Axis 3 — signing-key custody (ADR-MCPS-022 / ADR-MCPS-028).**
  `per_node_keyset` (default; tight blast radius) or `shared_remote_signer`
  (one non-exporting KMS/HSM identity). Copying a private key across nodes is
  normatively forbidden in every mode.
- **Axis 4 — ingress / transport binding (ADR-MCPS-023).** `end_to_end_mtls`
  (peer bound to the request signer end-to-end) or `trusted_ingress_asserted`
  (explicitly weakened; ingress in the TCB, authenticated LB↔node hop).

### Added — native cloud-KMS + delegated TLS key custody (ADR-MCPS-028 §B–§G)

- **Native cloud-KMS Ed25519 response signers** — AWS KMS
  (`ECC_NIST_EDWARDS25519`, `ED25519_SHA_512`, `MessageType=RAW`) and GCP Cloud
  KMS (`EC_SIGN_ED25519`), each over a blocking, hand-audited transport
  (SigV4 / OAuth2 + `ureq`), **not** the async vendor SDKs — the ADR-MCPS-018
  lean-sync firewall is preserved. The private key never leaves the KMS.
- **Delegated TLS-server-key custody (§G)** — the TLS server key can also stay
  non-exporting, via the `RawEd25519TlsSigner` seam and a delegated rustls
  certificate resolver, wired across PKCS#11, AWS KMS, and GCP KMS backends.
  Cross-cutting invariants enforced fail-closed: Ed25519-only, cert↔signer
  public-key match at config construction, a TLS credential distinct from the
  object-signing key, and delegated-XOR-exported mutual exclusion.
- **Cloud-KMS live CI lanes** — nightly-real-only (no faithful Ed25519 KMS
  emulator exists), secret-gated and non-blocking, with an anti-gaming hard
  fail; the load-bearing proof is `mcps-core` verifying the signature over the
  exact canonical preimage, never the provider's own `Verify`.

### Added — MCP SEP composition and trust hygiene

- **Replay safety under MCP multi round-trip requests (ADR-MCPS-024, SEP-2322).**
- **Untrusted transport routing headers (ADR-MCPS-025, SEP-2243)** — `Mcp-Method`
  / `Mcp-Name` never assert identity and never influence a security decision, in
  every ingress mode.
- **Signing scope vs. stateless per-request `_meta` (ADR-MCPS-026, SEP-2575).**
- **Extension-identifier reassignment to `se.syncom/mcps` (ADR-MCPS-027).**

### Known limitations — forbidden claims (tracked for v0.4, epic #68)

The composed claim licenses none of the following; each is a deferred tier
named in its ADR and tracked as v0.4 axis-hardening:

- Linearizable / unconditional replay safety (Axis 1 — needs the `CPStore`
  backend).
- Zero-window / instantaneous revocation (Axis 2 — needs live or push tiers).
- Smaller-than-per-node blast radius for a shared signer (Axis 3).
- End-to-end binding under `trusted_ingress_asserted` (Axis 4 — needs the
  LB-signed, request-bound Tier 3 assertion).
- Multi-tenant isolation between distrusting operators, and a hostile-shared-store
  threat model, both remain explicitly excluded from v0.3.

### Build

- Workspace version bumped to `0.3.0` across all crates. Cargo + Bazel still
  coexist; every crate carries both a `Cargo.toml` and a `BUILD.bazel`.

## [0.2.0] — 2026-06-05

This is the **initial public release** of MCP-S. v0.1 existed only inside the
authoring monorepo and was never published as source; it is captured here for
historical accuracy because both the architecture and the security review
process span it.

### Public-release scope

- Apache-2.0 licensed Rust workspace, ten crates:
  `mcps-core` (pure verification), `mcps-host` (client-side ambassador),
  `mcps-transport` (verifying mTLS client), `mcps-proxy` (server-side sidecar
  with TLS termination, OCSP, sandbox, Redis replay, PKCS#11 key sources),
  `mcps-policy` (delegated-authorization profiles, Phase 5),
  `mcps-conformance` (black-box conformance harness), three demo crates
  (`mcps-demo`, `mcps-demo-server`, `mcps-demo-fileserver`), and the test-only
  `mcps-test-paths` helper that lets the same integration tests run under
  Bazel runfiles OR a plain Cargo build.
- 19 architecture-decision records under [`docs/adr/`](docs/adr/) covering the
  trust model, core invariants, transport layering, authorization profile
  abstraction, and Phase 7 external backends.
- Specification briefs under [`docs/spec/`](docs/spec/) including the core
  spec, security boundary, and the upstream-proposal brief intended for an
  eventual MCP SEP submission.
- Two multi-agent Claude Opus 4.8 security audits and a per-finding
  remediation log under [`docs/security/`](docs/security/).

### Added — Phase 6 transport hardening

- **mTLS transport (`mcps-transport`)** — a blocking rustls client that
  presents a client certificate AND verifies the proxy's server certificate +
  identity against a configured server CA, including
  per-socket DoS hardening (read/write timeouts) and an aggregate
  response-read deadline that bounds slow-trickle peers
  (ADR-MCPS-015, [`mcps-transport/src/lib.rs`](mcps-transport/src/lib.rs)).
- **Server-side mTLS termination + identity verification** in `mcps-proxy`
  with configurable identity policies (SAN URI / SAN DNS / CN-legacy),
  exact transport-binding enforcement, and short-lived-cert posture
  (ADR-MCPS-014).

### Added — Phase 5 delegated authorization

- **`AuthorizationProfile` abstraction** with the Reference Signed
  Authorization Profile as the first implementation; policy evaluator runs
  AFTER core verification and BEFORE dispatch
  (ADR-MCPS-013, [`mcps-policy/src/`](mcps-policy/src/)).
- **Per-profile conformance vectors** under
  [`mcps-policy/tests/vectors/`](mcps-policy/tests/vectors/) covering every
  documented allow / deny code (12-token coverage).

### Added — Phase 7 external backends (feature-gated, off by default)

- **`pkcs11_keysource`** — vendor-neutral PKCS#11 backend for the
  response-signing key; key material never leaves the token.
- **`redis_replay`** — Redis-backed shared atomic replay cache for
  horizontally-scaled deployments, with bounded connection/read/write timeouts
  and TTL aligned to clock skew.
- **`online_ocsp`** — RFC 6960 §3.2 OCSP client-cert revocation, including
  full responder-signature trust chain
  (signature + responder identity + CertID binding + freshness + nonce).
- **Linux sandbox enforcement** (Landlock fs allowlists + seccomp egress
  filter), fail-closed on platforms without a kernel backend
  (ADR-MCPS-016 / ADR-MCPS-017).

### Security

This release is the product of two independent multi-agent Claude Opus 4.8
audits, totalling **282 agents and ~14.55M tokens** of review across both
rounds. The full audit reports are committed under
[`docs/security/`](docs/security/), alongside a per-finding remediation log.

- **v0.1 audit (2026-06-01)** — 3 High / 14 Medium / 36 Low / 53 Info,
  0 Critical. Overall residual-risk rating at audit time: **MODERATE**.
- **v0.2 audit (2026-06-02)** — 4 Critical / 15 High / 30 Medium / 59 Low /
  254 Info on the hardening branch. Overall residual-risk rating at audit
  time: **HIGH**.
- **Remediation in this release**: all 4 Critical, all 15 High, and 28 of 30
  Medium findings are **Addressed** with regression tests. The remaining 2
  Mediums (M01/M02 in [`docs/archive/security/remediation-v0.2.md`](docs/archive/security/remediation-v0.2.md))
  are **Deferred to v0.3**; their fail-mode is fail-closed and does NOT admit
  unauthorized requests.

Notable cross-cutting fixes folded in:

- OCSP responder verification rebuilt to enforce signature + identity +
  CertID + freshness + nonce per RFC 6960 §3.2; the single OCSP defect
  surfaced by four audit lenses is closed
  ([`mcps-proxy/src/ocsp.rs`](mcps-proxy/src/ocsp.rs)).
- Manifest pin atomicity (audit H-1) — repository now writes the pin file
  atomically via rename
  ([`mcps-policy/src/manifest_verifier.rs`](mcps-policy/src/manifest_verifier.rs)).
- Redis replay backend (audit H-8 / H-9 / H-10) — bounded connect, read, and
  write timeouts so the single-threaded serve loop cannot hang
  ([`mcps-proxy/src/redis_store.rs`](mcps-proxy/src/redis_store.rs)).
- `--strict` / `--production` postures now reject group/world-readable key
  files and disabled client-cert lifetime enforcement
  ([`mcps-proxy/src/main.rs`](mcps-proxy/src/main.rs),
  [`mcps-proxy/src/cli.rs`](mcps-proxy/src/cli.rs)).

### Build

- Cargo and Bazel coexist by design: every crate carries both a `Cargo.toml`
  and a `BUILD.bazel`, and the workspace is buildable with **either**
  toolchain. Cargo is the public-facing default for OSS contributors;
  Bazel remains the hermetic build path the maintainer uses internally.
- A small `mcps-test-paths` dev-dependency lets the same integration tests
  resolve child-process binaries and data fixtures under Bazel runfiles OR
  a plain Cargo build — see
  [`mcps-test-paths/src/lib.rs`](mcps-test-paths/src/lib.rs).

### Known limitations

- Two Medium findings (`M-01`, `M-02`) remain deferred to v0.3; both relate
  to fail-closed correctness gaps that do NOT admit unauthorized requests.
- Sandbox kernel enforcement (Landlock + seccomp) is Linux-only; on
  macOS / Windows / older Linux the proxy fails closed if
  `--inner-sandbox enforce` is requested (ADR-MCPS-017).
- The crate names and wire formats are explicitly unstable until 1.0; the
  ADR set names the surfaces most likely to evolve.

---

## [0.1.0] — 2026-06-01 (unpublished)

v0.1 is the internal pre-public baseline. It is NOT released as a public
crate or source archive; this entry is recorded so the v0.2 changelog,
audit, and remediation documents have an unambiguous predecessor to refer
to. The v0.1 audit report at
[`docs/archive/security/audit-v0.1.md`](docs/archive/security/audit-v0.1.md) captures the
state of the codebase at this point.

### Highlights

- Pure `mcps-core` verification crate with canonicalization, signature
  verification, replay detection, and the verified-context contract.
- `mcps-proxy` server-side sidecar with stdio transport, response signing,
  and verified-context propagation to an unmodified inner MCP server.
- `mcps-host` client-side ambassador for request signing and bound
  response verification.
- Black-box `mcps-conformance` harness (object + stdio targets).
- 18 ADRs covering the trust model, core invariants, and Phase 1-5 design
  decisions.

### Audit summary

- 3 High / 14 Medium / 36 Low / 53 Info, 0 Critical.
- Residual-risk rating at audit time: **MODERATE**.
- Four findings were partial carry-overs into the v0.2 hardening branch;
  all are closed in v0.2.0 per the
  [v0.2 remediation log](docs/archive/security/remediation-v0.2.md).

[0.3.1]: https://github.com/matssun/mcps/releases/tag/v0.3.1
[0.3.0]: https://github.com/matssun/mcps/releases/tag/v0.3.0
[0.2.0]: https://github.com/matssun/mcps/releases/tag/v0.2.0
[0.1.0]: https://github.com/matssun/mcps/releases/tag/v0.1.0
