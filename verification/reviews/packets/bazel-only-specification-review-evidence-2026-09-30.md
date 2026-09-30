# Specification-review evidence — five theorems awaiting the owner (#1074)

Prepared 2026-09-30 for the owner's specification review of THM-0082, THM-0119, THM-0123,
THM-0126 and THM-0127. **Nothing here is an approval. No review record and no claim
correction was written.** A fingerprint identifies what was reviewed; it does not establish
that the specification is correct, and this packet is the material for deciding that.

Tree: branch `build/bazel-only-execution` with `origin/main` (`ab5af549`) merged. Fingerprints
cover `statement + security_consequence + scope`, each premise's claim digest, the theorem id
and its review requirement (`tools/verification/_fingerprint.py`), so they do not depend on the
crate lock, the tests or this packet, and were regenerated on this tree.

## 1. Fingerprints

| theorem | reviewed fingerprint (recovered, reproduced) | current fingerprint |
|---|---|---|
| THM-0082 | `sha256:f85bc41b1ad4178e4842d196a2429e15e7147289f1cdedfd44054ea460e223be` | `sha256:807d622eec73915f60ab7dd4663f8babbb53d197413ce2fdcdf739f8859d8fca` |
| THM-0119 | `sha256:e1b6ece8eebddbe10e1ab34b0394910a7438ce11c0c917c4fa0f0a25818a26eb` | `sha256:99320e222d165e33ab41be091e81262175c7e8c02ed7e535059e26bd8d31e675` |
| THM-0123 | `sha256:d49622174412a7122cc6758effe64e8862e9cbe47e733382415d6c2b5bf244ce` | `sha256:1c134a5776c22b04caa0ecd8fe53f9907427a6c8efa273be8187677812690f05` |
| THM-0126 | `sha256:732c25f445a1c6fc07cb516f1d6a4e96e4ca39acb66eb4dc939a65a8eadcddf9` | `sha256:18e4a265ba7b324faeb00842b4432c23d723cc1a368064f1053e5c09a9e452b6` |
| THM-0127 | `sha256:420a9a9c8f06ea71d6c8638f10ed64d1e5088a433227cfa17b921c6854ecd3e8` | `sha256:41d895d991ca84466ae5b3bacc78405d98a2a18d5602e24046d2117b64d4763b` |

"Reproduced": recomputing `fingerprint_theorem` over `theorems.toml` at a historical commit
gives exactly the recorded fingerprint. The approved text below is therefore recovered from
git, not inferred. The newest reproducing commit is `1a86f331` for THM-0082 and `17dab8a0`
for the other four.

## 2. Corrections to the record

1. **THM-0082's recorded premise digests are reproducible.** The migration packet said they
   are digests "no text in the tree at its review reproduces". That is wrong, and the
   objection is withdrawn (section 3).
2. **THM-0127 is a scope correction, not a rename.** `client.config_lattice` appears in no
   version of `verification.toml`; the approved sentence cited an authority that was never
   registered (commit `28394a14`, which says so). Section 7.
3. **A reload-cadence test already existed.** An earlier draft of this packet said no test of
   the `trust.reload_secs` bound was found. `config::tests::a_disabled_or_unbounded_reload_cadence_is_refused`
   exists. It is claimed by `client.deployment_config`, not by the unit the theorem points
   at, and it checks only 0 and 86400 plus the maximum, so a bound moved by one survives it.
4. **Only one commit on `origin/main` moved these scopes after approval: `28394a14`.** The
   Cargo-to-Bazel wording is this branch's own commit (`77be06f2`).

## 3. THM-0082 — the serving path signs under the credential source materialization produced

### Why the digests looked unreproducible, and what actually changed

The recorded closure has seven premises (THM-0025, 0026, 0027, 0049 transitive; THM-0062,
0064, 0073 direct). All seven have identical digests today. THM-0082's own statement,
consequence and scope are byte-identical across approved, `origin/main` and this branch. The
digest algorithm still produces the recorded value from the review-time tree.

What changed is the premise SET. Commit `b6186813` (#990, 2026-09-18) added THM-0116 as a
direct premise, which pulls THM-0108 and THM-0089 in transitively: the closure grew from 7 to
10. That commit recorded a correction for THM-0075 (the root the edge moves) but none for
THM-0082, and THM-0082's review record was not touched. So a non-root theorem gained a
premise with no review or correction carrying it. This branch then moved THM-0108 and
THM-0116 again, by lane wording only:

```diff
THM-0108 scope
-Executable, class V0, measured in the default cargo lane. Outside every root's closure: no
+Executable, class V0, measured in the default Bazel lane (`bazel test //...`). Outside every root's closure: no
THM-0116 scope
-a plain `cargo test --workspace` compiles all three to zero tests, so each is its own unit
+the crate's default-feature test targets compile all three to zero tests, so each is its own unit
```

THM-0116, THM-0108 and THM-0089 are each `REVIEWED` at their own current fingerprints
(`e2b64a11…`, `709bb3a5…`, `e72c8e86…`). What has not been reviewed is the **connection**.

### Why THM-0116 is the premise the claim needs

The stated reason, from the theorem's own comment: for a non-exporting source, "signs under
the materialized source" means something only if that source established the key it
advertises before signing anything. The argument, with what each step rests on:

1. **Which sources can the materializer return?** Production `KeySource` implementors are
   `FileKeySource` (exporting; THM-0062 and THM-0073), `KmsKeySource`
   (`kms_keysource/mod.rs`, AWS and GCP backends beneath it) and `Pkcs11KeySource`.
   `RolesFixture`, `Absent` and `SwitchableRoot` are test-only. So the non-exporting
   production sources are exactly the seam (THM-0108) over the AWS and GCP adapters, and the
   PKCS#11 adapter: the three units THM-0116 names.
2. **The advertised key and the signing source are one object.** `app.rs:308` builds the
   source once (`build_key_source(...).into_key_source()`); `app.rs:403` reads
   `key_source.response_public_key()`; `app.rs:625` moves that same `key_source` into
   `SigningPlane::materialize`. Its comment says it "was only borrowed above".
3. **That source established the key it advertises (THM-0116).** The provider is asked for
   algorithm and public key at construction; non-Ed25519 refuses; the key is accepted only
   as a well-formed RFC 8410 encoding; a destroyed GCP key version refuses.
4. **No signature is emitted that the advertised key cannot verify (THM-0116, THM-0108).**
   Each adapter self-verifies; independently the seam re-verifies every signature under
   `response_public_key()` for any backend (`kms_keysource/mod.rs:83-112`), and its typed
   values make a pre-hash, a wrong-length or DER-wrapped signature unconstructible.
5. **Composition.** From 2, 3 and 4: what the root advertises and what its source signs are
   the same key, and that key verifies what the source emits. That is the property the
   THM-0082 consequence needs ("every signature would still verify and every startup line
   would still be true; the two facts would simply be about different keys").

Separately, `delegated_wiring.rs` (about lines 105-120) re-verifies the root's signature a
second time on the credential-issuance path, because responses are signed by a delegated key
whose credential the root issues. **No theorem claims that control**; it is an extra
production check outside THM-0108, THM-0116 and THM-0082.

### Where THM-0089 enters, and what the composition does not establish

- **THM-0089 is in the closure only through THM-0116's third sentence** (an endpoint is
  refused at construction). THM-0082's conclusion is about key identity, not about where a
  credential is sent, so its argument does not use the endpoint rule. The closure is
  conservative: any edit to THM-0089 re-stales THM-0082. Options: accept that, or split
  THM-0116 so the key-establishment half (used here) and the endpoint half are separate.
- **Not established:** key custody or non-exportability (THM-0116 and THM-0108 both disclaim
  it: "NOT A CUSTODY CLAIM"); FIPS or HSM protection; that any adapter speaks its provider's
  protocol correctly against a live provider; the TLS delegated signer, which is a second
  KMS key outside this claim. THM-0082's "custody" means the validated selection
  (THM-0064), not a protection level.

### Evidence run on this tree

All registered tests of the units involved ran and passed: `proxy.signing_credential_provenance`
4/4, `proxy.aws_kms_adapter` 16/16, `proxy.gcp_kms_adapter` 14/14, `proxy.pkcs11_adapter`
11/11, `proxy.kms_ed25519_seam` 10/10, `proxy.kms_endpoint_authority` 16/16 (one log line was
interleaved with stderr; the suite reports 1797 passed, 0 failed). THM-0082's own unit
evidence is over the composition root's source shape, not unconstructibility, as its scope
says.

**Owner question:** do you accept THM-0082 as now resting on THM-0116, and through it on
THM-0108 and THM-0089? Approving the three premises individually does not answer that.

## 4. THM-0119 — a trust binding that does not exist and a resolver that cannot answer are different refusals

Owner `core.trust_resolver_seam`, severity medium, depends_on `[]`. Statement and
security_consequence are byte-identical to the approved text. Current text in full:

> **statement.** The trust-resolver seam maps `(signer, key_id)` to a verification key. A
> binding that is unknown, or that has been revoked, is refused as an ACTOR-BINDING failure;
> a resolver that could not answer is refused as an OUTAGE. The mapping between the two
> outcomes and the two frozen tokens is exact in both directions, and neither is an allow.
> The composite key the reference resolver indexes by is injective across pairs whose members
> contain the delimiter, so no `(signer, key_id)` pair resolves under another pair's entry.
>
> **security_consequence.** An outage reported as an actor-binding failure tells an operator
> that a caller presented an unknown key when the truth is that the trust store was
> unreachable, and the two send an investigation to opposite places. The reverse reading is
> worse: a revoked binding reported as an outage invites a retry against a store that will
> keep saying the same thing. The injectivity conjunct is the one an ordinary happy-path
> battery does not reach: a signer name containing the delimiter could, under a naive join,
> resolve using a different signer's key id, a key confusion at the point the whole pipeline
> decides who signed.
>
> **scope.** THE SEAM AND THE REFERENCE IMPLEMENTATION. Nothing here is about the runtime
> trust plane's tiers, its caching windows, or its revocation channel — those are THM-0097
> through THM-0100's, over `proxy.trust_resolution_window` and `proxy.trust_reload_cadence`.
> NOT A CLAIM ABOUT WHICH KEYS A DEPLOYMENT TRUSTS. The resolver answers from what it was
> given; where the bindings came from and whether they were authorized is the trust
> document's authority. Executable, class V0, measured in the default Bazel lane
> (`bazel test //...`).

The complete difference from the approved text, in two separate parts:

```diff
# pre-branch, origin/main 28394a14 (ADR-MCPRE-068 Phase 1, after #996 split the unit)
-over `proxy.trust_plane_runtime`.
+over `proxy.trust_resolution_window` and `proxy.trust_reload_cadence`.
# this branch, 77be06f2 (Cargo to Bazel wording)
-Executable, class V0, measured in the default cargo lane.
+Executable, class V0, measured in the default Bazel lane (`bazel test //...`).
```

**Evidence.** The claim is about the seam, which is unchanged: `core.trust_resolver_seam`'s
seven registered tests (binding and outage mapping, exact error mapping, injectivity) ran and
passed. The renamed sentence is an exclusion, so it adds nothing the claim depends on.

**One imprecision in the pointer.** THM-0097 through THM-0100 have four theorems, but the
sentence names two units. THM-0097's owner is `proxy.trust_resolution_window`; THM-0100's is
`proxy.trust_reload_cadence`. THM-0098's owner is `proxy.trust_document_interpretation`, and
THM-0099's only unit is `proxy.serving_trust_seam`, neither named. It does not widen THM-0119,
because it only says what the claim excludes. **No other gap found.**

## 5. THM-0123 — an admitted local request cannot leak its slot, be guessed onto a route, or render a pause as a finished call

Owner `client.local_serving_pipeline`, severity medium, **depends_on `[]`**. Statement and
consequence byte-identical to approved.

```diff
# pre-branch, 28394a14
-accepted authority and the head fields are `client.local_ingress_authority`'s under THM-0091.
+accepted authority and the head fields are `client.bind_scope`'s,
+`client.accepted_authority`'s and `client.caller_shape_admission`'s under THM-0091.
# this branch, 77be06f2
-Executable, class V0, measured in the default cargo lane.
+Executable, class V0, measured in the default Bazel lane (`bazel test //...`).
```

**THM-0091 is outside this approval's requirements.** THM-0123 has no premise edge, so its
fingerprint has no dependency component and its review is not conditioned on THM-0091's
state. The citation is an exclusion ("WHAT HAPPENS TO AN ADMITTED REQUEST, NOT WHOSE REQUESTS
ARE ADMITTED"). What does matter is that the pointer is accurate, and it is: THM-0091's
`supported_by` contains `client.bind_scope`, `client.accepted_authority` and
`client.caller_shape_admission`, and its text names them. THM-0091 is `STALE_CLAIM` (statement
rewritten on main, never re-reviewed) and was not moved by this branch, so the claim-surface
gate does not enforce it here; it stays a separate debt (migration packet §4). The old unit
`client.local_ingress_authority` was removed by `1a86f331` (THM-0091 decomposed).

**Evidence run:** `client.local_serving_pipeline` 16/16 (including the e2e target),
`client.bind_scope` 4/4, `client.accepted_authority` 4/4, `client.caller_shape_admission`
8/8, `client.proxy_request_correspondence` 4/4, all passed.

## 6. THM-0126 — a verified reply is not a completed call

Owner `client.verified_outcome`, severity high, depends_on `[THM-0061]` (unchanged,
`REVIEWED`). Statement and consequence byte-identical to approved.

```diff
# pre-branch, 28394a14
-request is `client.response_acceptance`'s under THM-0076. What is established here is that
+request is `client.response_signer_authorization`'s and
+`client.response_binding_disposition`'s under THM-0076. What is established here is that
-chain is `client.response_acceptance`'s question, not this claim's.
+chain is `client.response_signer_authorization`'s question, not this claim's.
# this branch, 77be06f2
-Executable, class V0, measured in the default cargo lane. Every control performs a real
+Executable, class V0, measured in the default Bazel lane (`bazel test //...`). Every control performs a real
```

**THM-0076 is outside this approval's requirements, and the edge points the other way.**
THM-0076 `depends_on` THM-0126 and THM-0127; THM-0126 does not depend on THM-0076. Its
staleness is a consequence of these theorems moving. A review record does not change claim
text, so approving THM-0126 and THM-0127 does not cascade again. The first replaced sentence
is accurate: THM-0076's `supported_by` is exactly `client.response_signer_authorization` and
`client.response_binding_disposition`.

**The second replaced sentence is not supported by evidence.** It says sealing the
verified-response chain is `client.response_signer_authorization`'s question. That unit's
description and 15 tests cover which signer a client may accept (chain to a root, pin,
revocation, expiry). No unit description and no theorem other than THM-0126 mentions
`VerifiedDelegatedResponse`, and the struct still has `pub` fields (`response.rs:90`). The
replaced unit's sealing question therefore has no owner today. `28394a14` did not choose this
replacement by controls, as it did for THM-0130. A wording such as "Sealing that chain has no
owning unit today and is not this claim's" would be accurate, but it would change the claim
and therefore the fingerprint, so it must be decided **before** approval, not after.

**Evidence run:** `client.verified_outcome` 5/5, `client.execution_contract` 8/8,
`client.response_signer_authorization` 15/15, `client.response_binding_disposition` 5/5.

## 7. THM-0127 — the deployable's serving path always runs an anchor refresher

Owner `client.serving_lifetime`, severity high, depends_on `[THM-0120]` (closure THM-0057,
THM-0120, THM-0121). Statement and consequence byte-identical to approved.

```diff
# pre-branch, 28394a14
-that bound is `client.config_lattice`'s.
+that bound is `client.local_leg_declaration`'s.
# this branch, 77be06f2
-Executable, class V0, measured in the default cargo lane over the shipped
+Executable, class V0, measured in the default Bazel lane (`bazel test //...`) over the shipped
```

**This is a scope correction, not a rename.** `28394a14` records that `client.config_lattice`
appears in no version of `verification.toml`, so the approved sentence named an authority that
never existed; the bound it attributes is real and is at `config/validation.rs:67`.

**Premises moved only by this branch's wording:** THM-0120 and THM-0121 each changed by
"default cargo lane" to "default Bazel lane" (`fab37abf`→`e8a77509`, `ee4b3ea0`→`1cd97005`).
Both are `REVIEWED` at their current fingerprints, so THM-0127's own review is the one that
predates them.

### Every bound the claim makes or points at, mapped to its evidence

| claimed | kind | evidence | result on this tree |
|---|---|---|---|
| refresher started before the listener is served and held while serving | claim | `client.serving_lifetime`: `startup::tests::the_serving_path_starts_the_anchor_refresher_and_anchors_are_withdrawn_on_expiry` drives `serve_until_shutdown` | ran ok (1/1) |
| anchors re-read on the configured cadence, withdrawn past `expires_at` with no newer document | consequence, via THM-0120 | `client.anchor_refresh` | ran ok (8/8) |
| over the shipped `serve_until_shutdown` itself | scope | same test calls `serve_until_shutdown` directly | ran ok |
| no freshness number is asserted; no availability claim | disclaimers | none needed | n/a |
| "the configuration boundary bounds `trust.reload_secs`, and that bound is `client.local_leg_declaration`'s" | pointer the claim does not rely on | `validation.rs:67` (`1..=MAX_MANIFEST_RELOAD_SECS`, 3600) | see below |

The test for the first row shows the refresher runs while serving (anchors are withdrawn after
expiry). It does not separately assert the ordering "before the listener is served".

### The reload_secs bound: test added and run

The code is in `client.local_leg_declaration`'s file, but its only test was in
`config/mod.rs` under `client.deployment_config`, and it checks 0 and 86400 plus the maximum.
`config::validation::tests` (in the owning unit's own path, registered to it) now pins the
bound at both edges: 0 and 3601 refused with a message naming the field and `1..=3600`; 1 and
3600 admitted; and the constant itself equals 3600. Mutation check, each mutant applied to
`validation.rs:67` and run under Bazel:

| mutant | new test | existing test |
|---|---|---|
| lower edge 1 → 0 (zero admitted) | red | red |
| lower edge 1 → 2 (one refused) | red | **survives** |
| inclusive → exclusive (maximum refused) | red | red |
| upper edge plus one (3601 admitted) | red | **survives** |
| bound check deleted | red | red |

The new test is red on all five; the old one misses two. All 56 tests in
`//mcp-re-client:mcp_re_client_test` pass with the original code restored. A formal mutation
probe in `mutation-probes.toml` was not added; the table above is a manual check.

## 8. What each decision would and would not attest

| theorem | approval attests | still open |
|---|---|---|
| THM-0082 | the claim as written, resting on THM-0116 and its closure | whether to accept the conservative THM-0089 inclusion or split THM-0116; the issuance-path re-verification is claimed by nothing |
| THM-0119 | the seam claim and an exclusion pointer | pointer names two of the units behind THM-0097..0100 (optional tightening) |
| THM-0123 | the claim, independent of THM-0091 | none specific to the claim |
| THM-0126 | the claim and its THM-0061 premise | wording of the "sealing" sentence, to be decided before approving |
| THM-0127 | the claim, its premises as they now read | none specific; the bound it points at is now test-backed |

## 9. Noted, not changed, not in scope

- `client.deployment_config`'s comment in `verification.toml` still names the removed unit
  `client.local_ingress_authority`.
- The two SLO gates (`adr051_slo_gate.py`, `slo_gate.py`) require `--report`, and
  `check-generated` needs the extraction environment; both stay unresolved in the pinned
  sweep report.
