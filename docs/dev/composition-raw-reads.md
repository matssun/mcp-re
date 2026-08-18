# Post-validation raw reads of `DeploymentRequest`

The rule this inventory serves:

> **R-INGRESS.** `DeploymentRequest` SHALL NOT cross the Layer-A validation boundary as a
> runtime or composition input. It may be retained privately for diagnostics; `app.rs`,
> startup composition, materialization and the serving path must not ask for it again.

`ValidatedDeployment::config()` is the escape hatch. Its own doc comment already says each
forward is "countable as work remaining" — this is the count. Five call sites bind it, and
through those bindings **39 raw field reads over 26 distinct fields** reach composition:
29 reads / 20 fields in `app.rs`, 10 reads / 10 fields in `startup_plan.rs`.

Measured at `438abc2`.

## The taxonomy

| bucket | test | remedy |
|---|---|---|
| **1 SEMANTIC FACT** | an existing owner already decided its meaning | consume the owner's projection |
| **2 ORDINARY VALIDATED PARAMETER** | no further semantic interpretation is attached | carry explicitly as validated operational data |
| **3 NO OWNER YET** | composition derives a security-relevant fact no prior authority established | **FINDING** — assign ownership before carrying it |

The discriminating question between 2 and 3:

> If this value changes while every existing owner state stays unchanged, can a
> security-sensitive decision or effect change?

If yes it is not an ordinary parameter: either an owner is missing, or a cross-owner
relation has not been represented.

## Bucket 3 — NO OWNER YET (6 fields, all security-relevant)

| field | reads | why it is a finding |
|---|---|---|
| `max_clock_skew` | 5 (`app.rs`) | validated by a residue clause; **no owner carries it**. It is only *mentioned* in `config_state/admission.rs` prose. It sets the verifier's freshness window and the replay plane's tolerance — change it with every owner state fixed and admission changes |
| `allow_group_readable_key_files` | 1 | no owner. An explicit opt-in that widens who may read a signing key; composition applies it directly to the key-file floor |
| `max_client_cert_lifetime` | 2 | no owner. When no CRL is enforced this ceiling *is* the client-certificate revocation bound (`tls_plane::fleet_crl_bound` reasons about exactly that pairing) |
| `trust_path` | 1 (`startup_plan.rs:276`) | no owner, and `TrustPlan` pairs it with a sealed `TrustRevocationState` in a struct of `pub` fields — any module can pair a validated revocation posture with an arbitrary authority key. This is the defect `sealed-owners.md` records for `AdmissionState`, one layer up |
| `delegated_ttl_secs`, `delegated_overlap_secs` | 2 (`startup_plan.rs:359-360`) | `config_state/delegated_signing.rs` **validates** `0 < overlap < ttl` and then says in its own header that both are "checked here and kept in `DeploymentRequest`". The guard is a statement about one construction site; the pairing is re-created from raw fields at the plan |

## Bucket 1 — SEMANTIC FACT (an owner already answered)

| field | owner that already decided | evidence |
|---|---|---|
| `client_crl_paths` (`.len()`) | `CrlRevocationState::is_enforced()` | `app.rs:415` re-answers "is offline revocation enforced" from the raw list |
| `key_source` (`== Env`) | `CustodyState` / `CustodyMaterial::EnvSeed` | `app.rs:435` |
| `identity_source` | `ChannelBindingState` | `app.rs:456`, `startup_plan.rs:145` — derived in both places |
| `binding` | `ChannelBindingState` | `startup_plan.rs:135` |
~~`fleet`~~ and ~~`cores`~~ were listed here on first pass and are **wrong**: four owners
*classify on* `fleet` and `InFlightLimitBasis` resolves a per-core ceiling, but no owner
owns "this is a fleet deployment" or "this many cores". Swapping them would have meant
inventing a projection so composition could keep asking — which is the failure this
campaign exists to stop. They move to bucket 3.

## Dead, not a bucket — the reverse-proxy warning

`app.rs:447-458` is an eleven-line `WARNING:` block guarded by
`if let Some(header) = &values.reverse_proxy_identity_header`, and it reads three further
raw fields (`reverse_proxy_header_format`, `identity_source`, `bind`) to compose its text.

`cross_machine::x7` refuses `--reverse-proxy-identity-header` **outright**. Every
`ValidatedDeployment` therefore has `None` there, so the warning **cannot print**. It is the
orphan of an unconditional refusal, exactly like `cli::build_ocsp_checker` — with the
difference that the OCSP orphan is deliberate and documented, and this one is not.

Removing it retires 4 of the 39 raw reads on its own.

## Bucket 2 — ORDINARY VALIDATED PARAMETER

`tls_cert`, `client_ca`, `inner_http_urls`, `bind` (as the listen address), `route`,
`target_uri`, `audience`, `trust_domain`, `limits`, `workers_per_shard`.

`tls_cert` and `client_ca` are the argued case: `build_key_source`'s own documentation
states they belong to no custody machine — all five states consume them, and shared use is
not semantic ownership. They are strings whose *interpretation* the custody state decides.

## Corrections from executing the swaps

Re-measured after the mechanical head: `app.rs` is down from 29 reads / 20 fields to
**23 reads / 15 fields**, and `crate::deployment_request::KeySourceKind` is no longer
imported by the composition root at all.

Two entries above were misclassified on the first pass (`fleet`, `cores`) — see the strike
in bucket 1. That is the third bucket doing its job in the other direction: the test is
whether an owner ALREADY owns the fact, not whether one plausibly could.

`identity_source` and `binding` remain in `startup_plan::identity_strategy`, which is
blocked on a ruling — see below.

## A second orphan, needing the OCSP ruling rather than a deletion

`startup_plan::identity_strategy` matches on the same `reverse_proxy_identity_header` that
X7 refuses outright, and its `Some(header)` arm builds a `ReverseProxyMtlsProvider`. That
arm is unreachable for the same reason the deleted warning was — but the provider behind it
is **45 references across `transport.rs` (34) and `tls.rs` (11)**, with its own tests, and
no declared seam.

So this is the `build_ocsp_checker` question, not the dead-warning question: retained
capability or dead code? A 45-reference deletion is an owner ruling. Until it is made,
`identity_strategy` keeps two of the remaining raw reads.

## Order of work

1. Delete the dead reverse-proxy warning (−4 reads, no design decision).
2. Bucket 1 — replace each re-derivation with the owner's projection (−7 reads).
3. Bucket 3 — six fields needing an owner or a represented relation. `trust_path` and the
   delegated TTL/overlap pair are the two that also re-widen what an owner had sealed, so
   they belong with the plan-sealing half of the campaign.
4. Then narrow or remove `ValidatedDeployment::config()`, and the grep becomes a regression
   guard rather than the argument.
