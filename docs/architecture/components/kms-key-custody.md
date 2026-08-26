<!-- SPDX-License-Identifier: Apache-2.0 -->

# Component Blueprint: KMS Key Custody (AWS + GCP)

**Status:** Authority census (ADR-MCPRE-061 §8), MCPRE-143 / issue #579. **One conceptual census over both backends.** Investigation only — no code changed.

**Scope split:** target design for the key-custody axis. Current sealed state: [`docs/dev/sealed-owners.md`](../../dev/sealed-owners.md). §9 is the diff.

**Measured on `main` @ `7ec8f92`** with `scripts/module_size_gate.py::production_lines`:

| unit | prod | registry |
|---|---:|---|
| `gcp_kms_keysource.rs` | 1149 | 1149, `unreviewed` |
| `aws_kms_keysource.rs` | 694 | 694, `unreviewed` |
| `key_source.rs` | 362 | 362, `unreviewed` |
| `kms_keysource.rs` | 230 | 230, `unreviewed` |
| **census scope** | **2435** | |

The issue names two files; the authority spans four. The shared vocabulary the backends already consume (`remote_signer_call.rs` 191, `handshake_quota.rs` 178) is read but not censused here.

**Two providers is not two authorities**, and the census does not treat it as such.

## 1. Purpose

Establish that this deployment's response-signing key is held by a non-exporting custodian, and produce signatures with it without the private key ever entering the process.

## 2. Authority

### Owns

- the `KeySource` / `ResponseSigner` seam — what a custodian must be able to do;
- the **provider-agnostic KMS protocol mapping**: RAW-only PureEdDSA, raw 64-byte signature, RFC 8410 public key, fail-closed on every deviation (`kms_keysource.rs`);
- per backend, the **cloud transport**: request/response wire format, authentication (SigV4 / OAuth bearer), credential refresh, and failure classification.

### Does not own

- what a legal Ed25519 public key is — ADR-MCPRE-063 Slice 2's `Ed25519PublicKeyValue`; `kms_keysource.rs` says so and calls it a compatibility facade;
- which custody a deployment is in (`config_state::custody`);
- **which key serves which role** — that is decided in `cli.rs::build_key_source`. See Q7.

## 3. What proposition does a `KeySource` establish?

> *This process can produce Ed25519 signatures under a named key, and — for the KMS implementations — the private key is not in this process's address space.*

The second clause is the whole point of the axis and **the type does not say it.** `KeySource` is implemented by `FileKeySource` (seed on disk, key in memory), `EnvKeySource` (seed in an env var, key in memory) and `KmsKeySource` (key in a KMS). All three satisfy one trait, so a consumer holding a `Box<dyn KeySource>` cannot tell a non-exporting custodian from a seed file — the distinction that the entire ADR-MCPS-028 §B/§C work exists to deliver.

Today the distinction is carried by `CustodyState`, one layer up, and by the startup posture line. That is a real answer; it is also a *fact about configuration* standing in for a *property of the value*.

## 4. The twelve questions (ADR-061 §8)

### 1. What single fact does this unit own?

Per file, cleanly. Across the axis, the honest sentence is §3's, and its second clause is unrepresented.

### 2. How many independently describable authorities?

**Three**, not four and emphatically not "two, one per cloud":

| # | authority | where | lines |
|---|---|---|---:|
| A | **custody seam + local custodians** | `key_source.rs` | 362 |
| B | **KMS protocol mapping** (provider-agnostic) | `kms_keysource.rs` | 230 |
| C | **cloud transport + failure classification** | `aws_*` + `gcp_*` | 1843 |

**B already is the common owner** the census brief predicted would be the answer, and its module doc states the principle exactly: *"the protocol mapping is IDENTICAL across providers … a provider differs ONLY in the `KmsEd25519Backend` network client."* The top of this architecture is right.

The finding is that **C did not stay inside that boundary.**

### 3. Do AWS and GCP independently reimplement the same semantics?

**Yes — five times, and the sharpest one is a security classifier.**

| rule | AWS | GCP | genuinely provider-specific? |
|---|---|---|---|
| `ED25519_SIGNATURE_LEN = 64` | own const | own const | **no** — and `kms_keysource.rs` defines it a third time |
| `NETWORK_TIMEOUT = 5s` | own const | own const | **no** |
| `MAX_ERROR_BODY_BYTES = 8 KiB` + `read_error_body` | own | own | **no** |
| `quota_verdict` | own | own | **the rule: no. the data: yes** |
| local-key test transport | `LocalKeyKmsTransport` | `LocalKeyGcpTransport` | **no** — one pattern, two copies |
| request/response wire format | own | own | **yes** — legitimately |
| authentication + credential refresh | SigV4 + IRSA | OAuth + metadata server | **yes** — legitimately |

`quota_verdict` is worth stating in full, because it is the case the brief anticipated. The two functions have the same structure, consume the same shared types (`RemoteSignerFailure`, `QuotaVerdict`), call the same shared helpers (`is_load_shedding_status`, `json_string_field`), and **carry near-identical doc comments describing the same historical defect** — *"It used to be `format!(\"{error:?}\")` and `contains`, because the transport rendered the status and the body into a `KeyError` string before anything could ask."*

They differ in exactly two data points: the JSON path (`["__type"]` vs `["error","status"]`) and the token list — plus AWS's namespace-suffix rule.

**That is one semantic rule with two data tables, written twice.** The answer here is a common private owner taking `(path, tokens)` as backend-supplied data — not two smaller copies. A future third provider would otherwise arrive with a third copy, and a correction to the rule would have to be made in three places, which is exactly how the `format!`+`contains` defect survived as long as it did.

### 4. Does either backend reconstruct facts already decided elsewhere?

**No — and this is the axis's strength.** Both consume `CustodyState` decisions rather than re-reading the request; both delegate Ed25519 key interpretation to `Ed25519PublicKeyValue` through B's facade rather than parsing SPKI locally; both consume `RemoteSignerFailure`/`QuotaVerdict` rather than re-deriving failure semantics from prose. The census looked for the classic drift and found none.

### 5. Can backend-specific values be constructed in combinations the provider could never return?

`AwsKmsConfig { region, key_id, endpoint }` and `GcpKmsConfig` have public fields — but they are *requests*, not products: an implausible config yields a failed call, not a false claim. That is the right side of the line.

The products are better sealed than elsewhere in this campaign: `KmsResponseSigner` and `KmsKeySource` hold private backends, and `AwsKmsEd25519Backend`/`GcpKmsEd25519Backend` fetch and **validate the public key as Ed25519 at construction**, storing `spki_der` privately. Possession of a backend means the KMS answered and the key was a legal Ed25519 key.

**One gap.** `KmsEd25519Backend::sign_raw_ed25519` returns `Vec<u8>`, and `public_key_spki_der` returns `Vec<u8>` — untyped bytes at the seam. B re-checks length and parses, so nothing unsafe passes; but the seam's contract ("raw 64-byte PureEdDSA signature", "RFC 8410 SPKI") is prose over `Vec<u8>` in both directions, and a backend author's only guide is the doc comment.

### 6. Do root and delegated signing consume the same semantic product?

**No — and the separation is held by a construction site, not by a type.**

Both `AwsKmsEd25519Backend` and `GcpKmsEd25519Backend` implement **two traits**: `KmsEd25519Backend` (response-evidence signing) and `RawEd25519TlsSigner` (TLS handshake signing). Those are different propositions over different preimages — an RFC 9421 signature base versus a TLS 1.3 CertificateVerify transcript — and one type answers both.

In production they are **two different keys**: `--aws-kms-tls-key-id` / `--gcp-kms-tls-key-version` are separate selectors, relation X2a refuses a selector without its matching source, and `cli.rs::build_key_source` constructs a **second backend instance** for the TLS role. The separation is real and it is enforced *there*.

It is enforced nowhere in these files. Nothing stops one instance being used for both roles, and the code that guarantees otherwise is `build_key_source` — precisely the function EX-007 ruled should move out of `cli.rs`. **The two remediations touch the same 200 lines**, and the KMS one has an interest in what happens to it: whichever owner ends up holding `build_key_source` inherits the role-separation guarantee.

### 7. What relationship exists only through call ordering or a construction site?

The role separation above. Also: both backends validate the public key **at construction** and cache `spki_der`, so "the advertised key is Ed25519" holds for the object's lifetime by ordering rather than by a validated-key type. This is the mild form — construction is the only entry — and it is noted rather than charged.

### 8. What public interface exists only because tests need it?

`LocalKeyKmsTransport` and `LocalKeyGcpTransport` are both `#[cfg(test)]`-adjacent local-key fakes, correctly scoped. `KmsHttpClient`/`GcpKmsTransport` are `pub(crate)` traits whose stated purpose is to make the parsing and verify-before-return logic testable without network — a legitimate seam with a production implementor each.

Nothing here is test-shaped public API.

### 9. What is unreachable under the current legality model?

Nothing. Unlike EX-005 and EX-006, both backends are selectable (`--key-source aws-kms` / `gcp-kms`), and both are exercised by live lanes. This axis is **live**.

### 10. What facts are represented more than once?

Q3's table. **This is the question that decides this census**, as the brief anticipated: five duplications, of which four are pure copies and one — `quota_verdict` — is one rule with two data tables.

Plus `ED25519_SIGNATURE_LEN` in **three** files.

### 11. What inconsistent values can callers construct?

Less than anywhere else in this campaign. The products are sealed; the configs are requests. The residual is Q5's untyped `Vec<u8>` seam.

### 12. Which tests are emulator/unit and which are genuine live-cloud evidence?

**This axis already has the artefact the OCSP census wished for:** [`docs/security/cloud-kms-claims-map.md`](../../security/cloud-kms-claims-map.md) states, per runner, the trigger, whether it blocks, and what it contains.

| evidence | tests | lane | kind |
|---|---:|---|---|
| GCP protocol mapping, token lifetime, metadata cooldown, quota verdict | 39 unit tests in `gcp_kms_keysource.rs` | `--features gcp_kms_keysource`; CI feature-gated job (**blocking**) | offline, local-key fake |
| AWS protocol mapping, SigV4 wiring, quota verdict | 14 unit tests in `aws_kms_keysource.rs` | `--features aws_kms_keysource`; same job | offline, local-key fake |
| Provider-agnostic mapping against the real `mcp-re-core` verifier | 6 unit tests in `kms_keysource.rs` | default + feature lanes | offline, no network |
| IRSA credential exchange | 12 tests in `tests/aws_irsa_web_identity_test.rs` | CI feature-gated job (**blocking**) | **offline twin** — fake STS over loopback; its own doc says it "never earns the cloud-validation claim on its own" |
| **Real Cloud KMS signs; `mcp-re-core` verifies** | 2 tests in `tests/gcp_kms_live_test.rs` | `cloud-kms-live.yml`, **nightly 04:00 + dispatch, non-blocking**, and only when that backend's secrets are present | **genuine live-cloud** |
| Real AWS KMS equivalents | `aws_kms_live_test.rs` | same workflow | **genuine live-cloud** |

**`key_source.rs` has zero tests** — 362 production lines defining the seam and both local custodians, with no `#[cfg(test)] mod tests`, against the repository's own rule that every file has one.

**A contrast worth recording.** `gcp_kms_live_test.rs` is `#[ignore]` and its doc says it *"FAILS LOUDLY if its required configuration is absent — never a silent pass."* That is the correct shape, and it is the exact opposite of the OCSP e2e test EX-006 flagged for self-skipping to green. The repository contains both patterns; this is the one to copy.

## 5. Theorem inventory

**Measured: 0 of 33 registry entries concern this axis.**

| proposition | scope | evidence | status |
|---|---|---|---|
| A KMS-backed signature verifies under the unmodified `mcp-re-core` verifier with the key that KMS advertises | system | `gcp_kms_live_test`, `aws_kms_live_test` | **gap** — the axis's headline claim, evidenced only in a nightly non-blocking lane |
| The response-signing private key never enters this process | local | true of `KmsKeySource`; **not expressible** on `KeySource` (§3) | **gap, blocked on the representation** |
| A KMS backend signs PureEdDSA over the raw preimage, never Ed25519ph | local | `kms_keysource.rs` + local-key fake | structural, no entry |
| A quota verdict is read from the wire fact, never from rendered prose | local | both `quota_verdict`s | structural, no entry — **and stated twice** |
| Response signing and TLS handshake signing use different KMS keys | relation | `cli.rs::build_key_source` + X2a | **structural, and held by a construction site** (Q6) |

## 6. Implementation map

| lines | unit | authority |
|---:|---|---|
| 362 | `key_source.rs` — `KeyError`, `ResponseSigner`, `KeySource`, `FileKeySource`, `EnvKeySource` | A (**no tests**) |
| 230 | `kms_keysource.rs` — `KmsEd25519Backend`, `KmsResponseSigner`, `KmsKeySource`, SPKI facade | B |
| 694 | `aws_kms_keysource.rs` — SigV4 transport, IRSA, wire codec, `quota_verdict` | C |
| 1149 | `gcp_kms_keysource.rs` — OAuth/metadata token source, wire codec, `quota_verdict` | C |

GCP is 455 lines larger than AWS, and most of the difference is the access-token source: metadata-server fetch, expiry inference, refresh margin, unknown-expiry reuse, failure cooldown, refusal cooldown. That is genuine provider-specific mechanism, not duplication.

## 7. Outcome — one common owner for the duplicated rule; no per-provider split

**Do not split either backend, and do not merge them.** Q2 found three authorities and the top two are already correct. The disposition is narrower and follows Q10.

**1. Give `quota_verdict` a common private owner.** One function taking the backend's `(json path, token set, name-suffix rule)` as data. One rule, one implementation, per-provider tables — the shape the brief predicted and the shape the shared `RemoteSignerFailure`/`QuotaVerdict` vocabulary was already reaching for.

**2. Lift the four pure duplications** — `ED25519_SIGNATURE_LEN` (three copies), `NETWORK_TIMEOUT`, `MAX_ERROR_BODY_BYTES` + `read_error_body`, and the local-key test-transport pattern — into B or the shared transport vocabulary.

**3. Give the KMS seam typed operands.** `sign_raw_ed25519 -> Vec<u8>` and `public_key_spki_der -> Vec<u8>` state their contracts in prose. A `RawEd25519Signature` and an SPKI type would make a backend author's obligation checkable rather than readable. B re-checks today, so this is hardening, not a hole.

**4. Record — do not act on — the two representation questions**, because each belongs to another owner:
   - **`KeySource` cannot express non-exporting custody** (§3). Changing that is an ADR-MCPS-028 question about the seam, not a KMS refactor.
   - **Role separation lives in `build_key_source`** (Q6), the function EX-007 is moving. Whoever receives it inherits the guarantee, and this census asks that the move preserve it explicitly rather than by accident.

**5. `key_source.rs` needs a test module.** 362 lines, zero tests, and it is the seam every custodian implements.

**After 1–3, re-measure.** `gcp_kms_keysource.rs` will remain over the threshold and is then a band-3 unit whose remaining bulk is one provider's genuine token mechanism — a candidate for its own §14 discussion, not for this census to pre-empt.

## 8. Known deviations

| deviation | status |
|---|---|
| One quota-classification rule implemented twice, with near-identical doc comments | **finding**; common owner proposed |
| `ED25519_SIGNATURE_LEN` in three files; timeout/error-cap constants in two | **finding**; lift proposed |
| The KMS seam passes `Vec<u8>` in both directions with prose contracts | **finding**; typed operands proposed |
| `KeySource` cannot express non-exporting custody | **recorded, not acted on** — ADR-MCPS-028 seam question |
| Role separation (response vs TLS key) held by `build_key_source` | **recorded** — EX-007 is moving that function; the move must preserve it |
| `key_source.rs` has no test module | **finding** |
| The headline live claim rests on a nightly, non-blocking lane | recorded — and the lane **fails loudly** when unconfigured, which is the correct shape |
| No theorem entry for any proposition on this axis | recorded; §5 is the drafting list |

## 9. Completion criteria

- [x] All twelve questions answered, **as one census over both backends**
- [x] The `KeySource` proposition stated, and its unrepresented clause identified
- [x] Common custody/materialization semantics separated from cloud transport mechanics
- [x] Independent reimplementation measured item by item, with provider-specific mechanism distinguished from duplication
- [x] Reconstruction of facts owned elsewhere: looked for, **none found**, said so
- [x] Constructible-invalid-state review: products sealed; the residual `Vec<u8>` seam named
- [x] Root vs delegated signing: **different propositions, one type, separation held by a construction site**
- [x] Emulator/unit vs genuine live-cloud evidence separated per row, with blocking status
- [x] Outcome: **common owner for the duplicated rule; no per-provider split**
- [x] No code changed
