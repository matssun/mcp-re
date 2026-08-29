<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-067 — the semantic-altitude sweep, and what each phase did to it

The Phase-1 census record for the ontology-neutral-spine campaign
([ADR-MCPRE-067](https://github.com/matssun/mcp-re/discussions/668), tracker
[#669](https://github.com/matssun/mcp-re/issues/669)). Measured on `main` @ `7fbfe8f`.

Every finding is classified by the ADR §5 **replacement test**:

> If the current implementation mechanism were replaced tomorrow by a different mechanism
> that establishes the same proposition, would this type and its public semantic contract
> remain unchanged?

**Yes** → semantic; mechanism vocabulary there is a violation. **No** → a mechanism leaf,
and specificity is correct.

This is not a rename list, and the register below is deliberately dominated by its third
column. A sweep that found violations everywhere would be evidence that the test was being
applied as vocabulary censorship rather than as a question about altitude.

## What was searched

The semantic, request, state and composition layers:

```text
mcp-re-proxy/src/config_state/          the configuration state machines
mcp-re-proxy/src/deployment_request/    the CLI-neutral request model
mcp-re-proxy/src/communication_assurance/
mcp-re-proxy/src/authorization/
mcp-re-proxy/src/refusal/  startup_posture/  runtime_state.rs  startup_plan.rs
mcp-re-proxy/src/exchange_state.rs  request_stages.rs  signing_plane.rs
mcp-re-proxy/src/materialized_runtime.rs  materializing_runtime.rs  serving_capabilities.rs
mcp-re-core/  mcp-re-http-profile/  mcp-re-policy/  mcp-re-client-core/
```

for the families ADR §23 names: TLS/mTLS/rustls, X.509, OCSP/CRL, AWS/KMS/IRSA/STS,
GCP/metadata, PKCS#11, SPIFFE/SPIRE, Redis/etcd, HTTP/RFC 9421/RFC 9530, JOSE/JWS,
SCITT/COSE, Ed25519 — over type names, method names, field names, and imports.

## The one measurement that is not about names

**Dependency direction is already correct** (ADR §20). No module under `config_state/`,
`deployment_request/`, `communication_assurance/` or `authorization/` imports a provider
client or a protocol library. `config_state/` imports `deployment_request`, two tier
enums, and `transport::IdentityPolicy`, and nothing else from the crate.

That is the property a name is a proxy for, and it holds independently of the findings
below.

---

## Register

### A — semantic spine violations, FIXED in this campaign

| # | unit | the proposition it should have represented | disposition |
|---|---|---|---|
| A1 | `DeploymentRequest.key_source` + **16** provider-qualified sibling fields | *which key signs responses, and which key establishes the channel* | replaced by `response_signing: ResponseSigningRequest` and `channel_credential: ChannelCredentialRequest`, each a tagged mechanism selection carrying its own payload |
| A2 | `CustodyState::is_non_exporting_device()` | *whether private signing-key material can enter this process* | replaced by `exposure() -> PrivateKeyExposure { ProcessReadable, NonExporting }`. The old name asked about a class of devices; the new one asks what downstream policy actually needs |
| A3 | `KeySourceKind` | — | **deleted.** A mechanism discriminator that could disagree with its own payload is the flat shape ADR §7 forbids; the variant of `SigningSourceRequest` *is* the selection |

A1's structural consequence is the point rather than the field count: an AWS selection has
nowhere to put a GCP or PKCS#11 value, so the nine-entry "belongs to a different custody
source" table at the configuration boundary has no configuration left to refuse.

### B — semantic spine violations, DEFERRED to their own phase

Named here so the sweep is a measurement rather than a work list that quietly grew. Each
is a genuine violation by the replacement test; none is Phase 2's.

| unit | the durable proposition | phase |
|---|---|---|
| ~~`config_state::tls_custody::TlsCustodyState`, `DelegatedTlsKey`~~ | whether the channel-establishment key may leave the device | **3 — done** |
| ~~`tls::IdentityStrategy::DirectTls`, `startup_plan::identity_strategy`~~ | how the peer's identity reaches this node | **3 — done** |
| ~~`startup_plan::TlsPlan`~~ | what must hold to establish authenticated channels | **3 — done** |
| `materializing_runtime::install_tls` / `tls` | ruled a mechanism leaf: it installs a `TlsPlane`, and a rustls plane is entitled to say so | **3 — ruled** |
| ~~`DeploymentRequest`'s `ingress_pinned_mtls` and its five ingress siblings~~ | which evidence carries the peer's identity | **6 — done** |
| ~~`DeploymentRequest`'s 5 Redis/etcd locator fields~~ | where shared replay, continuation, admission and trust-epoch state live | **4 — done** |
| ~~`config_state::transport::CrlRevocationState`, `crl_posture`, `crl_plan`~~ | the credential-currency posture and its latency bound | **5 — done**, and the posture is now its own type; the CRL state stays CRL-named below it |
| ~~`deployment_request::OcspKind`, `config_state::validation::residue::ocsp_*`~~ | whether online revocation evidence is required | **5 — done** |
| `key_source::KeySource`'s `tls_server_cert_chain` / `tls_server_key` / `client_ca_roots` | ruled a mechanism leaf in Phase 3: the trait returns rustls types to a rustls listener, so its proposition genuinely IS "a rustls signing key used by a TLS listener". Only its LOCATION moves | 8 |

`scripts/semantic_altitude_gate.py` carries the same list as its `NOT_YET_MIGRATED`
registry, so the boundary states which families it is not yet checking instead of
reporting a clean "OK" over them. Phase 3 moved `tls` out of that registry and into
`MIGRATED`, joined by `x509`; `mtls` entered `NOT_YET_MIGRATED` when the gate measured
`ingress_pinned_mtls`, a field no phase before 6 reaches.

### B.3 — what Phase 3 produced

| before | after |
|---|---|
| `TlsCustodyState` with `is_delegated()` + four mechanism-named `Option` getters | `ChannelCredentialCustodyState` with `exposure() -> PrivateKeyExposure` and one `material() -> ChannelKeyMaterial` payload projection |
| `DeploymentRequest.tls_key` + `channel_credential.delegated: Option<..>` | `channel_credential.key: ChannelKeyRequest` — `ExportedFile` XOR `Delegated` |
| `DeploymentRequest.tls_cert` | `channel_credential.credential_chain` |
| `DeploymentRequest.client_ca` | `peer_trust_anchors` |
| `IdentityStrategy { DirectTls, LbAssertion }` in `tls.rs` | `PeerIdentityProvenance { ChannelCredential, IngressAssertion }` in `communication_assurance/` |
| `TlsPlan` | `ChannelEstablishmentPlan` |
| relation X2b + `validate_tls_signing_exclusivity` | **deleted** — the pair is unconstructible; the argv form is refused by `cli::signing_source_flags::channel_role` |

The custody fact is REUSED, not duplicated: both roles project the Phase-2
`PrivateKeyExposure`, and a test asserts they answer the same question with different
values for one fixture — which is what keeps the roles separate owners that share a
projection rather than one owner with two names.

### B.4 — what Phase 4 produced

Four semantic roles, four owners, one shared mechanism payload. That three of them are
usually served by the same Redis is a deployment choice, not evidence that they are one
fact — so the sharing is at the mechanism layer and nowhere above it.

| before | after |
|---|---|
| `replay_redis_url` + `cpstore_etcd_endpoint` + `replay_durability_tier` | `replay: ReplayStorageRequest { durability, store: Option<ReplayStoreRequest> }` — one store slot |
| `continuation_control_redis_url` | `continuation_control: ContinuationStoreRequest { shared: Option<SharedStoreRequest> }` |
| `admission_redis_url` | `admission_store: AdmissionStoreRequest` |
| `trust_epoch_redis_url` + `trust_epoch_key` | `trust_epoch: TrustEpochStoreRequest`, the key INSIDE `TrustEpochSource` |
| `ReplayDurabilityTier::RedisWaitQuorum` / `RedisAsyncBounded` | `QuorumAcknowledged` / `AsyncReplicatedBounded` — the `wire_name()` and `guarantee()` strings are unchanged, because those are an ADR-MCPS-020 published vocabulary and not a type name |
| the replay `SharedRedis`/`SharedLinearizable` forbidden columns (2 refusals) | **deleted** — one store slot, so naming one backend is how the other stops being named. What is left is one relation: a store that cannot deliver the declared tier |
| CF-04, the trust-epoch key with no store | **deleted** — the coordinate travels inside the source |

Both deleted clauses had an argv form that survives, and `cli::storage_flags` answers both
with the sentences the boundary used to.

`SharedStoreRequest` is a one-variant enum on purpose: it is the seam a second backend
arrives at, and its three consumers already read a selection rather than a Redis URL.

### B.5 — what Phase 5 produced

CRL and OCSP are two mechanisms, and they stay two. Nothing here merges an implementation
to look generic; what was added is the layer above them that consumers actually read.

| before | after |
|---|---|
| `client_crl_paths` + `client_crl_reload_secs` + `client_ocsp` + `ocsp_responder_url` | `peer_revocation: PeerRevocationRequest { lists, online }` |
| `OcspKind { Off, Require }` | `OnlineRevocationEvidenceRequest { NotRequired, Required(OcspResponderRequest) }` — the semantic selection, with the protocol payload inside it |
| `fleet_crl_bound`'s three inline arms | `CredentialCurrencyBound { CredentialLifetime, PublicationRefresh, PublicationValidity }`, projected by `credential_currency_bound`; `fleet_crl_bound` renders it |
| the "responder has no effect without `--client-ocsp require`" clause | **deleted** — the responder travels inside `Required`; the argv form is `cli::revocation_flags`' |

**`PeerRevocationRequest` is a struct, not a tagged union**, and that is a decision rather
than an omission: holding a revocation list does not make an online check meaningless, or
the reverse. Forcing a union would have encoded a mutual exclusion the domain does not have.

**Online OCSP remains unselectable.** `online_ocsp_refusal` is unchanged and still refuses
`Required` unconditionally, because the production data plane performs no responder round
trip. The variant exists so the request can state what is being refused.

**`TrustedRevocationAnswer` was not renamed and needs no new projection.** The generic fact
its consumer needs — whether the credential is admissible on revocation grounds — is
already `OcspChecker::allows`, over a `RevocationEvidence` that ALREADY separates
*a verified responder said `unknown`* (`Answered(TrustedRevocationAnswer)` carrying
`CertRevocationStatus::Unknown`) from *no trusted answer was established*
(`NotEstablished`). Adding a second generic type above it would have duplicated an
authority the tree already has. The RFC 6960 leaf keeps its EX-006 disposition and was not
touched.

### B.5.1 — the dormant trust findings, classified

Classified, not wired. None is a security control a deployment currently believes is active.

| unit | classification | why |
|---|---|---|
| `LiveTrustResolver::revocation` (the secondary `RevocationSource`) | **intentionally dormant** | no production path installs one, and no deployment can believe otherwise: relation X6 refuses `--revocation-list` paths unconditionally, so a configured deny-list is a startup refusal rather than a silent no-op. The seam is the ADR-MCPS-021 elaboration a networked revocation feed would use |
| `t_exceeds_recommended_max` | **intentionally dormant; wiring is a behaviour change** | an ADVISORY with no caller. The operator is told the actual window on the tier's `startup_audit_line`; what is missing is the annotation that it exceeds five minutes. Nothing claims the advisory fires, so no false belief exists. Connecting it adds a startup warning, which is a behaviour change this phase was told not to make on its own |
| `strictest_applicable_t` | **Phase-6 input needed** | it has no INPUT, not merely no caller: the deployment surface carries no per-sensitivity-class window, so `class_windows` is always empty and the function is the identity. The semantic requirement is clear and the request model cannot express it, so it is carried forward rather than given an input invented here |

No item met the "required live security control that current deployments falsely claim to
enforce" condition, so this phase did not stop.

### B.6 — what Phases 6-8 produced

**Phase 6 rebuilt the request.** 72 fields at the start of the campaign, 46 after Phase 5,
**32** now — and every one names a durable proposition rather than a CLI flag or a
state-machine input. (This section said 31 until the Phase-9 re-measurement counted the
declarations rather than the migration table's rows.)

| before | after | clauses deleted |
|---|---|---|
| `binding` + `identity_source` + five `ingress_*` | `peer_identity: PeerIdentityEvidenceRequest` | 5 dangling + the pinned-channel requirement |
| `admission` + five `admission_*` | `admission: AdmissionRequest` | 5 dangling + the 2 illegal degraded cells |
| `revocation_tier` + `trust_reload_secs` + `trust_epoch` | `request_signer_currency: RequestSignerCurrencyRequest` | X8 + 2 cadence-requiredness |
| five `delegated_*` | `delegated_signing: DelegatedSigningRequest` | — (all four were value guards) |

`PinnedChannelAcknowledgement` is the sharpest case: the §C2 channel guarantee is not a
flag beside the attested form, it is what the form is BUILT from — no `Default`, no public
field — so a Mode-C request cannot come into existence beside a silence.

**`strictest_applicable_t` got the input it was missing NAMED rather than fabricated.**
Its rule needs two things this tree has neither of: a producer that classifies a request
into a sensitivity class, and a deployment input stating a window per class.
`ApplicableClassWindows` has one production constructor and it is empty, so the rule is the
identity BY TYPE — the compiler records which input is missing, and no class-name-to-number
map was invented to activate dormant code.

**Phase 7 decomposed the CLI.** `parse_args` **537 → 22** production lines; `cli.rs`
**1170 → 331**. Fourteen flag families, each owning one semantic question's spelling.

**Phase 8 moved materialization to its owners.** `build_key_source` (210 lines, one arm per
mechanism) became `capability_materialization::key_source` with a module per mechanism;
`read_pkcs11_pin`, `build_ocsp_checker` and `build_attested_ingress_binding` went with it,
and `key_file_mode_is_insecure` went to the policy that owns it. EX-008's last duplication —
`quota_verdict`, written twice and already drifted in shape — is one rule over per-provider
DATA.

### B.7 — what Phase 9 closed

A regression pass over the corrected tree, not a new design exercise.

**The gate's registry is still empty and its scope still states itself.** `NOT_YET_MIGRATED`
holds nothing; `MIGRATED` holds 21 families; the dependency-direction half checks 20
mechanism adapters against four semantic directories. No new provider-qualified sibling
appeared on `DeploymentRequest`, and no semantic module acquired an adapter import.

**One altitude finding, fixed.** `config_state::admission` destructured the Phase-4
`SharedStoreRequest` into a bare `redis_url: String` on both enforcing states and projected
it as `EnforcedAdmission::redis_url()`. Its own doc comment already stated the durable
proposition — *the shared authoritative record currency is compared against* — so only the
identifier disagreed with it, and the identifier is what a consumer reads. Its sibling
`ContinuationControlState` had already migrated the same shape to `shared_store()`. The
field and its projection are now `record_store`; the `--admission-redis-url` spelling inside
the refusal text is unchanged, because a flag name in a diagnostic is a diagnostic
(section C).

**Everything else above the boundary carries a justification.** Re-checked by hand, since a
name-based gate cannot: `CrlRevocationState` and `classify_and_validate_crl` (ruled in B,
Phase 5 — the posture is its own type and the CRL state stays CRL-named below it),
`AwsCredentialMode` and `kms_endpoint` (C and E), `residue::ocsp_*` (each carries its own
"why no narrower owner" clause), `channel_key_material`'s per-mechanism locator projections
(the ruled `CustodyMaterial` shape, consumed only by the materializer), and the typed
mechanism payloads under `deployment_request::signing_source`, `::storage` and
`::revocation`. The leaves in section D are unchanged and still specific.

**The completion question, answered per family.** *Can a new mechanism be added as a typed
leaf without changing the semantic consumers that care only about the durable proposition?*

| family | a new mechanism adds | what a semantic consumer reads, unchanged |
|---|---|---|
| signing source / channel key | one `SigningSourceRequest` / `ChannelKeyRequest` variant, one payload, one materializer arm | `PrivateKeyExposure`, `ChannelCredentialCustodyState` |
| shared storage | one `SharedStoreRequest` variant | `shared_store()`, `record_store()`, `materialization_plan()` |
| peer revocation | one arm under `PeerRevocationRequest` | `CredentialCurrencyBound` |
| peer identity | one `PeerIdentityEvidenceRequest` variant | `PeerIdentityProvenance` |

**Yes across all four**, so Phase 9 closes. What a new mechanism still touches is its own
adapter and the materializer that selects backends — which is the selection boundary's job,
not a semantic consumer's.

### C — mechanism-selection boundary (legitimate; a provider name is correct here)

These sit *at* the boundary. They name mechanisms because their consumer is the thing that
must pick one.

| unit | why the name is correct |
|---|---|
| `config_state::custody::CustodyMaterial` | the mechanism payload projection, borrowed and matchable, whose one consumer is `build_key_source`. Selecting a backend is materialization's own job |
| `config_state::custody::AwsCredentialMode` | a sub-posture of the AWS state. Credentials to reach KMS mean nothing without a KMS key to reach |
| `config_state::kms_endpoint` | its proposition genuinely is *"a KMS/STS endpoint override is held to the endpoint-authority rule"*. A mechanism with no endpoint has no question to answer here |
| `cross_machine::x2a` | a cross-ROLE compatibility relation, expressed by matching two tagged unions. The flag names in its refusals are diagnostics, not semantics |
| `cli::signing_source_flags` | the CLI is an adapter (ADR §16). It says `--aws-kms-region` because an operator reads a flat command line, and assembles the typed payload immediately |
| `app::run`'s env-seed startup warning | the warning is about that mechanism and that build feature, not about a custody class. `ProcessReadable` covers files too, and files are production-legal |
| `serving_capabilities::online_ocsp` | a BUILD fact about a protocol |

### D — legitimate mechanism leaves

Left specific, deliberately. Renaming any of these to appear generic would be the failure
mode ADR §3 names.

```text
ocsp.rs                       RFC 6960 request construction and §3.2 response verification
outbound_fetch/               scheme allowlist, private-address classification, DNS rebinding
aws_kms_keysource.rs  aws_sigv4.rs  aws_sts.rs
gcp_kms_keysource.rs
pkcs11_keysource.rs  pkcs11_native.rs
kms_keysource.rs              the provider-agnostic Ed25519 KMS protocol mapping
tls.rs  tls_listener_state/  delegated_tls/     rustls construction and handshake signing
redis_store.rs  etcd_store.rs  async_redis_store.rs  async_etcd_store.rs
mcp-re-http-profile/src/scitt/     COSE / SCITT wire vocabulary
communication_assurance/ed25519_public_key.rs   an Ed25519 key's canonical encoding
```

`mcp-re-http-profile/src/custody.rs` is worth naming separately: it is a **semantic**
authority that already passes the replacement test. Its root issuer and key factory are
injected, so a KMS is a swap of the injected issuer rather than a code fork, and the type
names say nothing about who signs.

### E — ambiguous, ruled

| unit | ruling |
|---|---|
| `config_state::kms_endpoint` | **mechanism-selection boundary** (C), not a violation. The alternative reading — "an outbound authority a deployment names" — would be a genuinely different proposition, and the existing `outbound_fetch` authority already owns it. Creating a second one would be the duplicate-authority mistake ADR-MCPRE-059 rev1 made |
| `app::run`'s env-seed warning | **boundary** (C). It matches `CustodyMaterial::EnvSeed` to warn about a dev-only build, which is a statement about that mechanism. Reading it through `PrivateKeyExposure` would make it fire for file custody too, which is production-legal |
| `deployment_request::kinds::OcspKind` | **violation** (B, Phase 5). It is a request-level selector named for the protocol that happens to implement it; the durable proposition is whether online revocation evidence is required |

---

## Counts

```text
semantic spine violation          3 fixed in Phase 2 (A)
                                + 7 deferred (B), of which 6 are now done
                                  (Phases 3-5) and 1 was ruled a mechanism leaf
mechanism-selection boundary      7 (C)
legitimate mechanism leaf        ~20 modules (D)
ambiguous, ruled                  3 (E)
dependency-direction violation    0
dormant control, classified       3 (B.5.1) — 2 intentionally dormant,
                                  1 needing a Phase-6 input; 0 falsely claimed
Phase-9 regression pass           1 finding (config_state::admission), fixed
```

After Phase 6 the semantic-altitude gate's `NOT_YET_MIGRATED` registry is **empty**, and
Phase 9's regression pass confirmed it stayed so: every
family the sweep named has a typed mechanism payload. The registry stays in the file because
the shape it enforces — a family must be listed with the phase that owns it, or be refused —
is what keeps a future un-migrated family from passing silently, and its selftest now
supplies its own registry rather than asserting over nothing.

Per the tracker's one rule, no issue was opened per finding. Section B is the phase list
the ADR already carries; section A is the work this campaign did.
