# Medium-finding census — 2026-10-05

Read-only classification of every actionable medium in `docs/security/finding-ledger.jsonl`,
**pinned at `aa9ed8fd`** (104 mediums: 63 `open`, 41 `provisional`). High-remediation commits
after that head are not reflected; no medium changed status between `aa9ed8fd` and the census.
Machine-readable table: [`medium-census-2026-10-05.jsonl`](medium-census-2026-10-05.jsonl), one
row per finding, with class, booleans, verification ids, dependency, families, shared fix,
proposed batch and the `file:line` evidence read at `aa9ed8fd`.

The census closes nothing. An M6 row is a **closure candidate**: it carries evidence, and it
still goes through the reconciliation protocol (pinned evidence, adversarial second review for
every medium closure) before any status changes.

## The headline answer

| question | rows | distinct defects |
|---|---:|---:|
| need production coding (M1, M2, M5, M7) | 42 | 34 |
| verification / theorem / registry maintenance only (M4) | 6 | 5 |
| test / evidence repair only (M3) | 4 | 4 |
| probable closures (M6) | 52 | — |
| **total** | **104** | |

*Distinct defects* folds same-round duplicates still open side by side (three r10 triplicates,
two pairs, one r12 pair). Of the 42 production rows, 14 change a public API and 3 are blocked on
the Python SDK test lane.

**Where the closures come from.** All 52 M6 rows are r10 rows from the five reconciliation
batches not yet run (R1, R5, R7, R8, R9); none is an r11/r12 row and none is a row a completed
reconciliation minted. Of the 74 open r10 mediums in those batches, 52 look closable and 22 still
present:

| batch | M6 candidates | still present |
|---|---:|---:|
| R1 config_state | 10 | 7 |
| R5 transport, app | 9 | 2 |
| R7 tls_plane, kms_keysource, tls_listener_state | 16 | 3 |
| R8 serving_capabilities, audit_sink, retained_evidence | 11 | 7 |
| R9 trust_plane, push_trust, revocation_resolver | 6 | 3 |

What the M6 evidence rests on: 31 duplicate an older or later row (whose status is cited), 6
were fixed since the round, 2 are superseded by ADR-MCPRE-064, and the rest are absent on the
current tree (`file:line` cited). 15 of the 52 are medium confidence.

## A. Classes

| class | rows |
|---|---:|
| M1 production-code security defect | 14 |
| M2 structural / type / API hardening | 22 |
| M3 test / evidence defect | 4 |
| M4 theorem / verification / registry | 6 |
| M5 mixed code + verification | 3 |
| M6 reconciliation / closure candidate | 52 |
| M7 infrastructure blocked | 3 |

Secondary classes are recorded where a row is genuinely two things (28 rows).

## C. Defect families — counted, not assumed

| family | rows | note |
|---|---:|---|
| duplicate of an older round | 31 | all inside the 52 M6 |
| caller convention carries a guarantee | 11 | |
| unchecked public construction | 10 | |
| fail-open / incomplete lifecycle or error semantics | 9 | |
| stale proof or registry wording | 9 | |
| same-round duplicate | 6 | |
| fixed since the round | 6 | |
| test does not prove its stated scope | 5 | |
| raw identifier where a domain type should constrain | 5 | |
| config coordinate checked trimmed, stored untrimmed | 4 | one rule fixes all four |
| timeout / liveness | 4 | |
| shared mutable handle bypasses validation | 2 | |
| feature / configuration lane omits the code | 1 | |
| assumption now implementation-enforced | 1 | |
| theorem / unit path-set mismatch | 0 | none open among the mediums |

## D. Concentrations

- **Crate.** `mcp-re-proxy` 82, `mcp-re-http-profile` 16, Python SDK 3, the Verus reproducer 3.
- **Module.**
  - `config_state` 19
  - `serving_capabilities` 10
  - `trust_plane` 9
  - `tls_plane` 8
  - `app` 7
  - `audit_sink` 7
  - `kms_keysource` 7
  - `custody` 5
  - `mcp_transport` 5
- **File.**
  - `config_state/server_identity.rs` 17: 9 are closure candidates.
  - `app.rs` 12
  - `serving_capabilities.rs` 10
  - `kms_keysource/mod.rs` 7
  - `tls_plane/mod.rs` 7
  - `custody/mod.rs` 5
  - `audit_sink/mod.rs` 5
- **Theorem.**
  - THM-0077 13
  - THM-0066 9
  - THM-0015 8
  - THM-0070 8
  - THM-0048 8
  - THM-0108 7
  - THM-0063, THM-0073, THM-0094 6 each
- **Unit.**
  - `proxy.server_identity_facts` 16
  - `proxy.serving_capability_posture` 10
  - `proxy.listener_state_assembly` 9
  - `http_profile.request_full_result` 8
  - `proxy.audit_delivery` 8
  - `proxy.trust_composition_root` 7
  - `proxy.kms_ed25519_seam` 7
- **Probe.** M310 is cited by 16 rows, M90 by 10 and M129 by 7. These are the probes a fix in
  those files must keep red.

## Shared fixes — one change, several findings (each still closes on its own evidence)

| shared fix | findings | one change |
|---|---|---|
| refuse a config coordinate that differs from its trimmed form | 1ab5a311, 4340a695, d296a6a5, 094e44dd | the rule `delegated_signing.rs:181-189` already applies |
| audit seam returns an `Established` capability | 272bc4d1, 6a377079, 7f124529 | one type change in `serving_capabilities.rs` |
| posture lines state what the installed sink does | 2575eeb9, fea031d8, bc1ce233 | constants + the test that checks them |
| custody: bound the issued window (exp ≤ requested, exp > now) | 0d3f59f5, 630acbf3 | `ActiveDelegatedKey::issued` / `adopt` |
| `--trust` reloader liveness deadline | 0dd5128c, bbfa4027 | one deadline registration |
| narrow `McpTransportPolicy` API | b4648cd2, cd5dd994 | one owner |
| evidence-handle role types (F1, ratified) | b86c0b8d, e49adade (+ 0f0dc26c) | one seal |
| SDK pinned root honours `now` | 31419f23, 83208e90, 9cf9662b | one resolver, behind the SDK lane |
| Verus ICE ceiling registered as a ceiling | 218bdb7d, 90cdf796, ddbee9c2 | one registry entry + reproducer label |
| TLS plane drop / snapshot contract | 6297cdd7, b70e342b | one contract statement + code |

## E. Coding versus maintenance

| work family | rows | production code | verification authority | batching |
|---|---:|---|---|---|
| pure code (M1) | 14 | yes | fingerprints move with the files | B5, B7, B8, B9, B13, B14 |
| type / API hardening (M2) | 22 | yes; 8 change a public API | sometimes | B4, B5, B6, B8, B10, B13, B14 |
| test / evidence (M3) | 4 | no | the cited control moves | B7, B8, B12 |
| theorem / registry (M4) | 6 | no | yes | B2 (F2), B10, B11 |
| mixed (M5) | 3 | yes | yes, ratified | B1 (F1) |
| closure candidates (M6) | 52 | no | adjudication only | RECON-R1/R5/R7/R8/R9 |
| blocked (M7) | 3 | yes, once validatable | THM-0094 | B15 behind the SDK lane |
| **total** | **104** | | | |

## F. Proposed medium campaign — derived from the rows

Order: the reconciliation batches first, because they are the cheapest. They are adjudication only, and 52 of their 74
mediums are closure candidates. Then the code batches, by shared owner.

| batch | findings | files | common invariant | authority changes | semantic risk | one fix, several closures? | gate / test set |
|---|---|---|---|---|---|---|---|
| RECON-R1/R5/R7/R8/R9 | 52 M6 + 22 still-present r10 (and the batches' low/info) | per batch | — | none; still-present rows get fresh ids | low | n/a | `recon/apply.py` validation + adversarial second review of every medium closure |
| B1 F1 evidence seal | b86c0b8d, e49adade, 0f0dc26c | `evidence.rs`, `block.rs`, `sign/request.rs` | a role is a type; a block is validated before it is signed | ratified (F1); THM-0014..0021 move | medium (public API) | yes | http-profile + every crate test depending on it; mutation probes of the evidence units |
| B2 F2 THM-0041 scope | 2ca90cad | `theorems.toml` | scope matches the selectable posture | THM-0041 re-review (ratified) | low | — | verification suites, check-views |
| B3 F4 | 9c5a6680 | `replay.rs`, `dispatch.rs` | no sync admission door | THM-0079 (F4) | medium | absorbed by F4 | F4's gate |
| B4 seal public values | d4966e39 (`HttpReplayKey`), 64981b1b (`ActorIdentity`), 04683c6a (raw skew), 51bb21a2 (signer write side), 11bd6924 (`consume` verdict) | http-profile `replay.rs`, `app.rs`, core `replay.rs`, `delegated_server_signer`, `continuation_store` | possession is the proof: no public field, no raw constructor | 5 public API changes; THM-0062/0066/0079/0087 fingerprints | medium-high (cross-crate callers) | no — five owners, one pattern; split by crate | lint + full closure tests; `ActorIdentity` touches ~10 struct-literal sites |
| B5 MCP transport contract | 1cce4612, 46bf0c30, aee88e1f, b4648cd2, cd5dd994 | `mcp_transport/{mod,agreement}.rs` | the contract is enforced from the protocol table, after verification only | THM-0015 | medium | partly (b4648cd2+cd5dd994) | http-profile tests + `mcp_transport_headers_test`, `bodyless_202_test` |
| B6 config coordinate canonical form | 1ab5a311, 4340a695, d296a6a5, 094e44dd | `server_identity.rs`, `mcp_transport_contract.rs` | a coordinate that differs from its trim is refused | `proxy.server_identity_facts` (M310 stays red) | low | **yes, one rule** | proxy unit tests |
| B7 custody issuance and lifecycle | 0d3f59f5, 630acbf3, d46ed638, 4519b138, 86743e76 | `custody/{mod,active_key}.rs` | an adopted credential's window is inside the request; lifecycle audit is bounded | THM-0063 | medium | 2 of 5 | http-profile + proxy signing-plane tests |
| B8 serving capabilities | 2575eeb9, fea031d8, bc1ce233, 272bc4d1, 6a377079, 7f124529 | `serving_capabilities.rs`, `app.rs` | a posture line is derived from the installed capability | THM-0070, THM-0077; M90 | low-medium | **yes, two fixes for six** | proxy unit tests |
| B9 liveness and budgets | 0dd5128c, bbfa4027, 6d6125f2, 2942e46a | `trust_plane/reload`, `tls_listener_state`, continuation stores | every worker and shared budget has a stated bound | THM-0097, THM-0048, THM-0087 | medium; 2942e46a may need a policy ruling | 2 of 4 | proxy unit + async drain lane where relevant |
| B10 TLS plane retirement | 6297cdd7, b70e342b | `tls_plane/mod.rs` | drop/snapshot contract stated for every posture | THM-0048/0054 | low | yes | proxy unit |
| B11 verification registry | 218bdb7d, 90cdf796, ddbee9c2, fb29f893 | registry, reproducer | an undischarged `ensures` is labelled as one; store-write premise registered | ASM additions | low | yes (ICE trio) | verification suites |
| B12 test evidence | f0015b94, 322a3674 | `replay_plane/backends.rs`, `server_identity.rs` | the cited branch executes in a merge-path test | unit `tested_symbols` | low | no | proxy unit |
| B13 owner-question candidates | f3e6d4f0, 5520c9f5, 6bba984c, fe0ebe9f | `delegated_signing.rs`, `server_identity.rs` | — | — | — | — | tested against the escalation four-field test before anything reaches the queue |
| B14 singletons | 28fe5fcc, a2fe0986, 5f5b9f93 | `audit_sink`, `transport`, `invalidation_channel` | — | THM-0034/0070/0097 | low | no | proxy unit |
| B15 SDK | 31419f23, 83208e90, 9cf9662b | `sdk/python/src/trust.rs` | the pinned root honours `now` | THM-0094 | medium (published Python API) | yes | the SDK `py_test` lane, then this |

**Owner-question candidates are not queue items yet.** The shards flagged these rows as possibly
needing a ruling: f3e6d4f0, the example.com placeholder trio, 2942e46a, fb29f893, and among the
closure candidates ad9fa383, f5f76b63, 39440a50 and 98dd488e. Each will be tested against the
escalation rule when its batch runs, and only a genuine two-admissible-remedies decision goes to
the queue, by name.

**One observation outside the medium set.** `cd5dbac0` is `fixed`, yet `publish`, `retire`
and `retire_permanently` are still `pub` at `delegated_server_signer/mod.rs:190,202,218`.
That fix narrowed the reader only. The open twin is 51bb21a2, in B4, so nothing is lost. But
the `fixed` row's note should be checked when B4 runs.
