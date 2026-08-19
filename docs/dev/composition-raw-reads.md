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
imported by the composition root at all. After the owner work above it is **18**, and
`startup_plan.rs` is down from 10 to **3**.

Two entries above were misclassified on the first pass (`fleet`, `cores`) — see the strike
in bucket 1. That is the third bucket doing its job in the other direction: the test is
whether an owner ALREADY owns the fact, not whether one plausibly could.

`identity_source` and `binding` remain in `startup_plan::identity_strategy`, which is
blocked on a ruling — see below.

## A second orphan — RULED, and deleted

`startup_plan::identity_strategy` matched on the same `reverse_proxy_identity_header` that
X7 refused outright, and its `Some(header)` arm built a `ReverseProxyMtlsProvider`. The arm
was unreachable for the same reason the deleted warning was, so the question was the
`build_ocsp_checker` one: retained capability or dead code?

The measurement that settled it. The 45 references were **12 production and 30 test**;
there were no consumers outside this crate; `docs/AGENT_INSTRUCTIONS.md` §9 lists the
retained-but-refused capabilities and the forwarded-identity header is **not** among them;
and the one document that claimed the capability was supported — `README.md`, "available
via the forwarded-identity path" — was false, contradicted by `SECURITY.md` in two places.
With that claim corrected there was no declared contract on either side.

Owner ruling: delete. The flag, the `DeploymentRequest` fields, relation X7, the provider,
the XFCC/RFC2253 parsers and the `IdentityStrategy::ReverseProxyHeader` variant are gone.
The strongest evidence that the seam really was header-shaped is that
`tls::resolve_identity` and `resolve_identity_from_leaf` no longer take `&RequestHeaders` at
all: no strategy can derive a transport identity from a request header, and the signature
now says so. Direct locally-terminated mTLS is unchanged and remains the production posture.

This is the `--replay-cache` precedent, not a precedent for the other four §9 entries: the
answer here was "the input should not exist", which is what raising a refusal looks like
when the refusal turns out to be all the capability still did.

## Order of work

1. ~~Delete the dead reverse-proxy warning~~ (−4 reads, no design decision). **Done.**
2. ~~Bucket 1 — replace each re-derivation with the owner's projection~~ (−7 reads). **Done.**
3. ~~Delete the forwarded-identity provider~~ (owner ruling above). **Done.**
4. ~~Eliminate plan re-widening, starting with `TrustPlan`~~. **Done** — see below.
5. ~~`max_client_cert_lifetime`~~ — **done**, as `ClientCredentialWindow`, and it found a
   live defect: see below.
6. Bucket 3 — the remaining fields needing an owner or a represented relation:
   `allow_group_readable_key_files` and the `fleet`/`cores` topology pair.
7. Then narrow or remove `ValidatedDeployment::config()`, and the grep becomes a regression
   guard rather than the argument.

## Plan re-widening — `TrustPlan`, and what sealing found

`TrustPlan` paired a sealed `TrustRevocationState` with a public `trust_path: String` and a
public `reload: TrustReloadPlan`. Both halves were defects, and only one was the expected
one.

The locator now has an owner. `TrustDocumentSource` claims exactly that the string names
something — not that the file exists, parses, or holds a trusted key, which are
observations belonging to materialization. Its guard left the residue's required-locator
group, which is down to three.

The reload cadence turned out not to be a fact the plan should hold at all. The revocation
state already decides it (`reload_cadence()`), so a stored copy was a second value free to
disagree — and it did: `trust_plane`'s fixture named a 30s reload beside a state carrying
5s, and asserted the wording of an operator-facing line no deployment prints. `reload()` is
derived now. The same seal showed that `ReadOnceAtStartup` is reachable only under
bounded-cache, so a second test was asserting the frozen-store wording for three postures
layer A refuses.

That is the argument for sealing a composition, stated concretely: a public bag of owned
facts had already drifted into a combination no configuration reaches, and nothing failed.

## A validated relation, split back into its terms — `max_client_cert_lifetime`

The third bucket's test is *"if this value changes while every existing owner state stays
unchanged, can a security-sensitive decision or effect change?"* For the certificate
lifetime the answer was yes, and asking it found a defect rather than a shape.

Relation X5 refused with the words *"a connection would outlive the credential that
authenticated it"*, and compared `max_connection_age` against the ceiling **constant** —
never against the configured lifetime. `--max-client-cert-lifetime 600
--max-connection-age-secs 3000` was therefore accepted: a connection served requests for
forty minutes past the expiry of the certificate that authenticated it, while the startup
transcript reported `exposure_window=600s`. `TlsPlan` then carried both values on as
`Option<Duration>` under a comment saying their relation "was settled at layer A".

`ClientCredentialWindow` owns both durations and enforces the relation at construction, so
`exposure_window()` is something the value can claim. X5 and the residue's lifetime clause
are gone — one owner, one refusal per defect.

**This tightens what the proxy accepts.** A deployment whose connection age exceeds its
certificate lifetime now fails to start. That is the rule the codebase already stated; it
was simply not the rule it checked.
