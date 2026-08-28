<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPRE-067 Phase 1 — the semantic-altitude sweep

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
| `config_state::tls_custody::TlsCustodyState`, `DelegatedTlsKey` | whether the channel-establishment key may leave the device | 3 |
| `tls::IdentityStrategy::DirectTls`, `startup_plan::identity_strategy` | how the peer's identity reaches this node | 3 |
| `startup_plan::TlsPlan`, `materializing_runtime::install_tls` / `tls` | the listener's credential material | 3 |
| `DeploymentRequest`'s 5 Redis/etcd locator fields | where shared replay, continuation and admission state live | 4 |
| `config_state::transport::CrlRevocationState`, `crl_posture`, `crl_plan` | the credential-currency posture and its latency bound | 5 |
| `deployment_request::OcspKind`, `config_state::validation::residue::ocsp_*` | whether online revocation evidence is required | 5 |
| `key_source::KeySource`'s `tls_server_cert_chain` / `tls_server_key` / `client_ca_roots` | the material a listener is built from | 3, with the Phase-8 materialization move |

`scripts/semantic_altitude_gate.py` carries the same list as its `NOT_YET_MIGRATED`
registry, so the boundary states which families it is not yet checking instead of
reporting a clean "OK" over them.

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
semantic spine violation          3 fixed (A) + 7 deferred (B)
mechanism-selection boundary      7 (C)
legitimate mechanism leaf        ~20 modules (D)
ambiguous, ruled                  3 (E)
dependency-direction violation    0
```

Per the tracker's one rule, no issue was opened per finding. Section B is the phase list
the ADR already carries; section A is the work this campaign did.
