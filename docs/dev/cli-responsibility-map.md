<!-- SPDX-License-Identifier: Apache-2.0 -->

# What `cli.rs` owns: a responsibility measurement

**Measured at:** `mcp-re-proxy/src/cli.rs` on
`refactor/adr-056-phase0-startup-characterization` after `3f8eb7c`, 3,241 production lines
(tests begin at 3,242) of which `parse_args` is 727 (784–1510), 22%.

**Why re-measured rather than carried forward.** The parser-boundary audit
([`../security/parser-boundary-audit.md`](../security/parser-boundary-audit.md)) measured a
`parse_args` that still decided deployment legality. That audit succeeded well enough to
invalidate its own inventory: the responsibilities it named were relocated, so its
remaining-category counts describe an object that no longer exists. Every count below was
taken again from zero.

**The question is not "what can be extracted to make `parse_args` smaller".** It is: *for
every remaining block, why must this operation happen at the CLI-input boundary?* Each
operation lands in exactly one of four buckets, the last of which is the negative control:

- **Syntax** — token recognition, flag/value consumption, spelling, numeric parsing,
  structured token parsing.
- **Provenance** — facts that exist only while interpreting argv and that a
  `DeploymentRequest` cannot express.
- **CLI normalization** — translating CLI syntax into the request vocabulary without
  deciding deployment legality.
- **Not CLI** — anything that cannot justify itself under one of those three.

## Map A — `parse_args`, 727 lines

| Block | Lines | LOC | Bucket |
|---|---|---:|---|
| local bindings and their defaults | 785–909 | 125 | mixed — see the defaults inventory |
| five valueless boolean flags | 910–951 | 42 | syntax |
| value fetch (`flag requires a value`) | 952–954 | 3 | syntax |
| the flag `match`, ~80 arms | 955–1376 | 422 | mostly syntax — see below |
| `require` closure, `has_delegated_tls`, two delegated defaults | 1380–1394 | 15 | mixed |
| struct literal | 1396–1503 | 108 | normalization, two exceptions |
| handoff to `ValidatedDeployment::try_from` | 1505–1509 | 5 | — |

### The ~80 match arms

**Syntax — 73 arms.** 42 plain `Some(value.clone())` / `push` captures; 10 enum-spelling
arms (`--key-source`, `--client-ocsp`, `--admission`, `--audit-sink`,
`--verified-context-carrier`, `--admission-allow-degraded`, `--transport-binding`,
`--transport-identity-source`, `--reverse-proxy-header-format`, `--authz`); 2 arms
delegating to a domain type's own parser (`ReplayDurabilityTier::parse`,
`RevocationTier::parse`); 11 bare numeric parses; 4 via `parse_timeout`; 1 via
`parse_cert_lifetime`; 2 structured `<keyid>:<base64url>` pairs; the unknown-flag arm.

The two structured-pair arms (`--ingress-lb-key`, `--ingress-attestor-key`) split on `:`
and refuse an empty half. That is token recognition — the *shape* of one argument — and it
is distinct from `ingress_assertion_refusal`, which decides at the boundary whether the
resulting key set is coherent with the selected binding. Both exist and neither duplicates
the other.

**CLI normalization — 3 arms.** `--client-crl`, `--inner-http-url` and `--revocation-list`
split a comma-separated value and extend a list. Empty segments are preserved and reach the
owning machine as the empty paths they are, so the split decides nothing.

**Provenance — 3 arms.**

- `--pkcs11-pin` (1001–1010) is refused because the PIN is in *this process's argv*. No
  `DeploymentRequest` can express that and no boundary can observe it. This is the clearest
  member of the bucket.
- `--max-in-flight` and `--max-in-flight-total` each call `second_admission_limit`, which
  refuses an argument list naming both. `InFlightLimitRequest` holds one limit, so a request
  naming two is unrepresentable — "already set" is a fact about the input.

Those same two arms also refuse `n == 0`. That is not a duplicated legality check: the
variants hold `NonZeroUsize`, so there is no request to construct. The refusal is forced by
the request vocabulary, which is what a parser is for.

**One arm under review — `--trust-reload-secs`** (1078–1083):

```rust
let secs: u64 = value.parse()...;
trust_reload_secs = (secs > 0).then_some(secs);
```

This is the only arm that turns a *number* into a *state*: an explicit `0` becomes the same
`None` an omitted flag produces. `TrustRevocation` treats the two identically today, so no
outcome differs — but the parser is deciding that zero means "no cadence" when the machine
already has a state for that. Classified normalization, flagged because it is the shape that
becomes a semantic decision the moment the machine grows a clause that distinguishes them.

### The struct literal — two operations that are Not CLI

Nine fields use `require(...)`, which refuses an *absent* flag. `DeploymentRequest` types
these as `String`, so absence is not representable and the report can only be made here;
the boundary independently refuses all nine when empty
(`config_legality_characterization_test.rs`). Provenance, correctly placed — with one cost
noted below.

Two fields do something else:

```rust
signing_key_seed: match key_source {
    KeySourceKind::File | KeySourceKind::Env => require(signing_key_seed, "--signing-key-seed")?,
    KeySourceKind::Pkcs11 | KeySourceKind::AwsKms | KeySourceKind::GcpKms =>
        signing_key_seed.unwrap_or_default(),
},
tls_key: if has_delegated_tls { tls_key.unwrap_or_default() } else { require(tls_key, "--tls-key")? },
```

Both derive **which custody state the deployment is in** in order to decide whether a field
is required — and both machines derive it again from the same fields:
`config_state/custody.rs:131,134` requires a non-empty seed for `FileSeed`/`Env`, and
`config_state/tls_custody.rs:83–96` decides `Delegated` vs `Exported` from the three
selectors and `tls_key`. This is CF-10 in the shape the last pass removed twenty instances
of: one deployment fact, two derivations, free to disagree. It survived because it is
spelled as a field initializer rather than as a check.

The parser's derivation also wins the race — `--key-source file` with no seed reports
`missing required --signing-key-seed`, and `Custody`'s own "a custody state with no key"
never runs. Collapsing both to `unwrap_or_default()` would hand the question to the owning
machine; what it costs is the absent-vs-empty distinction for those two fields specifically,
which is a deliberate call rather than a free win.

### Cost of `require` that should be recorded

`require` uses `?`. A command line missing four required flags is answered about one — the
early-return cost the last pass removed everywhere else. Every remaining early return in
`parse_args` is syntactic (`?` on a parse failure), and for a *malformed token* stopping at
the first is right. `require` is the exception: nine independent presence facts, reported one
at a time, immediately before a boundary that reports all violations at once.

## The defaults inventory

Defaults are where provenance disappears, so each is listed with where its value comes from.

| Default | Source | Provenance |
|---|---|---|
| `max_clock_skew` | `VerifierPolicy::DEFAULT_MAX_CLOCK_SKEW` | owner-sourced |
| `limits` | `ServerLimits::default()` | owner-sourced |
| `revocation_tier` | `BoundedCache { trust_cache::DEFAULT_T_SECS }` | owner-sourced |
| `key_source`, `client_ocsp`, `admission`, `authz`, `verified_context`, `audit_sink`, `binding`, `identity_source`, `reverse_proxy_header_format` | enum variant | absence = the off/strict variant |
| four booleans (`--fleet`, `--gcp-kms-use-metadata`, `--aws-kms-use-web-identity`, `--ingress-pinned-mtls`, `--allow-group-readable-key-files`) | `false` | absence of a valueless flag |
| `cores`, `workers_per_shard` | `0` = auto | `0` is a real value, not a sentinel for absence |
| `admission_degraded_bound_secs` | `0` | boundary has clauses for both directions |
| `in_flight_limit` | `InFlightLimitRequest::Unspecified` | **representable**; fail-safe default applied at the boundary |
| `max_client_cert_lifetime` | `Some(Duration::from_secs(3600))` — literal | **second spelling of `MAX_CLIENT_CERT_LIFETIME`**, 766 lines below in this file |
| `delegated_ttl_secs` / `delegated_overlap_secs` | `unwrap_or(300)` / `unwrap_or(60)` — literals | **owner has the invariant and the ceiling but not the default** |

The honest verdict: the provenance loss is uniform and real — for every field but
`in_flight_limit`, "the operator wrote the default" is indistinguishable from "the operator
said nothing" — and it changes no outcome anywhere I can find. That is worth stating plainly
rather than dressing up, because the structural point stands on its own: `in_flight_limit`
got a representable type *because* its fail-safe default had to be applied at the boundary.
The rule that generalizes is

> a default belongs in the parser when the request type cannot be wrong about it, and at the
> boundary when the machine owning the field would refuse the absence differently than it
> refuses the default.

Three entries fail the weaker test of *where the number lives*: the client-cert lifetime
default duplicates the ceiling constant in the same file, and the two delegated-rotation
defaults are bare literals in `parse_args` while `config_state/delegated_signing.rs` holds
`0 < O < T` and `MAX_DELEGATED_TTL_SECS` and has no default constant at all.

## Map B — the other 2,514 production lines

| Region | Lines | LOC | What it is |
|---|---|---:|---|
| module doc + imports | 1–35 | 35 | **stale**: names "the subprocess inner server" and "the blocking serve loop" |
| `SecretString` | 37–71 | 35 | secret custody |
| seven domain enums | 73–197 | 125 | the request vocabulary |
| `DeploymentRequest` | 199–583 | 385 | the request type, 76 public fields |
| `validated_kms_endpoint`, `ingress_assertion_refusal` | 585–783 | 199 | boundary predicates, placed *before* the parser |
| **`parse_args`** | 784–1510 | **727** | map A |
| `ValidatedDeployment` + `TryFrom` | 1512–1597 | 86 | the boundary type |
| `validate_tls_signing_exclusivity`, `target_uri_violation` | 1598–1660 | 63 | boundary predicates |
| three ceiling constants | 1661–1710 | 50 | domain constants read by `config_state` |
| four refusal predicates | 1711–1851 | 141 | boundary predicates |
| admission messages, `AdmissionAuthority`, `validated_admission_authority` | 1852–2030 | 179 | boundary predicate + a parsed value type |
| `kms_endpoint_refusals`, `ingress_assertion_violation`, `second_admission_limit` | 2031–2117 | 87 | boundary adapters + one provenance guard |
| `unsafe_config_violations`, `validate_configuration`, `MachineViolations`, `legality_violations` | 2118–2548 | 431 | **the validation boundary itself** |
| `key_file_mode_is_insecure`, `key_file_posture_violation`, `read_pkcs11_pin` | 2549–2639 | 91 | filesystem custody |
| `parse_timeout`, `parse_cert_lifetime` + cap constant | 2640–2703 | 64 | CLI syntax helpers |
| six `build_*` / `load_*` functions and the TLS-custody accessors | 2704–3241 | 538 | **runtime establishment** |

Three things this makes visible.

**The validation boundary is the largest single occupant of the file** — roughly 1,100 lines
across `legality_violations`, the ten standalone refusal predicates, `ValidatedDeployment`,
and the two predicates parked ahead of `parse_args` — against `parse_args`'s 727. `cli.rs`
is not a parser with a boundary attached; it is a boundary with a parser attached.

**Six public functions have zero call sites outside `cli.rs`**, production or test — only
unit tests inside the file itself:

| Function | Why nothing reaches it |
|---|---|
| `load_revocation_list` | X6 refuses any non-empty `--revocation-list` |
| `build_ocsp_checker` | `online_ocsp_refusal` refuses `require`; `Off` returns `None` |
| `build_attested_ingress_binding` | `undeployable_transport_binding_refusal` refuses Mode C |
| `build_lb_assertion_binding` | `config_state/transport.rs:88` refuses `lb-assertion` |
| `build_shared_replay_cache` (both cfg variants) | `startup_plan::ReplayPlan::from_validated` is the production path |
| `build_cpstore_replay_cache` (both cfg variants) | same |

Four of the six are unreachable *because the boundary now refuses the posture they exist to
serve* — they are the machinery behind a capability the project has decided not to offer.
Two were superseded by `startup_plan`. Only `build_ocsp_checker` is documented as
deliberately retained (`serving_capabilities.rs:114`); the other five are retained by nothing
but their own unit tests, which is the same shape as a doc comment standing in for a call
graph. Whether they are deleted, feature-gated, or explicitly documented as retained is an
owner decision, but "a test is the only caller" must not be the reason they survive.

**Runtime establishment lives in the parser's file.** `build_key_source` (218 lines) reads
PIN files and constructs KMS clients; `read_pkcs11_pin` and the key-file permission
predicates are filesystem custody. These are ADR-MCPRE-056 §5.1 *materialization* — they
observe the environment — and `app.rs` is their only production caller.

## What the module should own

The target shape, stated as the pipeline rather than as a file list:

```
argv  ──▶  CLI parser  ──▶  DeploymentRequest  ──▶  boundary  ──▶  ValidatedDeployment
                                                                        │
                                          domain state, planning, establishment elsewhere
```

Against that, `cli.rs` currently owns four things beyond the parser: the request vocabulary,
the validation boundary, filesystem/secret custody, and runtime establishment. Splitting
`parse_args` into option-group modules while those stay in `cli/mod.rs` would organize the
smallest of the five occupants and call ADR-058 complete.

### Proposed order, and the seam test for a parser module

A typed option group earns existence when several CLI inputs **jointly produce one request
fragment while sharing syntax or provenance behaviour** — not because they share a domain
owner. Those two boundaries need not coincide, and on this evidence they mostly do not: the
42 plain-capture arms share no syntax with each other, and the arms that *do* share syntax
(the two `<keyid>:<b64>` pairs; the four `parse_timeout` arms; the three comma-split lists)
cut across `ChannelBinding`, `ServerLimits`, `CrlRevocation` and the inner plane.

That points away from `cli/custody.rs`-style domain modules and toward the two extractions
the evidence actually supports:

1. **Move the boundary out first** — the ~1,100 lines of `legality_violations`, the ten
   refusal predicates, `ValidatedDeployment` and the two predicates parked ahead of the
   parser. They belong beside `config_state`, whose machines they consult. This is the
   largest occupant and the one whose current placement most misleads a reader about what
   the file is.
2. **Move establishment out second** — `build_key_source`, the replay-cache and binding
   builders, `read_pkcs11_pin` and the key-file predicates. Materialization, called by
   `app.rs`, currently indistinguishable from validation by file position alone.

After both, what remains is `DeploymentRequest`, the seven enums, and a `parse_args` whose
727 lines are 73 syntax arms and a struct literal. **Whether that wants subdividing at all is
an open question this measurement does not answer** — it may well be one coherent unit, and
a 727-line parser of uniform arms is more reviewable than twelve modules that make a reader
chase trivial control flow to find where `--bind` is read.

The three edits the measurement does support, independent of any split:

- collapse the two custody-derived `require` branches so `Custody` and `TlsCustody` are the
  only derivations of their own required-field columns;
- give `delegated_signing` its default constants, and make the client-cert lifetime default
  read `MAX_CLIENT_CERT_LIFETIME` instead of re-typing 3600;
- rule on the six unreachable builders.

ADR-058 closes when the parser is reviewable by semantic unit. 727 is not a target, and a
smaller number is not automatically better.
