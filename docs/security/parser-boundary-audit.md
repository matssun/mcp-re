<!-- SPDX-License-Identifier: Apache-2.0 -->

# Parser-boundary audit: which security invariants depend solely on `parse_args`

**Audited at:** `mcp-re-proxy/src/cli.rs`, commit `126b093` plus the fix this document
records.
**Question:** does any runtime or security invariant hold *only* because `parse_args` ran?

That question matters because `Config` is a struct of public fields. Anything that builds
one in code — a test, an embedder, a future composition root — reaches the serving path
without meeting the parser. A rule enforced only there is not a rule; it is a rule about
argv.

## Why the criterion is "boundary", not "parser"

`parse_args` is a good place for a *diagnostic* and a bad place for an *invariant*. The
distinction this audit uses:

- **Boundary** — `cli::unsafe_config_violations`, consulted by `app::run` for every
  config however built. An invariant enforced here holds unconditionally.
- **Downstream fail-closed** — a later step that independently refuses the same state, for
  its own reasons (`startup_plan::ReplayPlan::from_config`, `delegated_wiring`,
  `trust_plane`). Also unconditional, and legitimate.
- **Parser-only** — enforced nowhere else. A bypass if the state it refuses is a security
  state.

A parse-time check that duplicates a boundary check is not redundancy to remove: it is what
keeps the diagnostic an operator meets first unchanged (ADR-MCPRE-058 §8.5). The rule lives
in one shared predicate; both sites consult it.

## Method

All 80 refusal sites inside `parse_args` (lines 619–1926) were enumerated and split at the
end of the flag loop:

- **Syntax tier (lines 809–1316)** — per-flag value parsing: unknown flag, missing value,
  unparsable number, empty string. Unreachable for a programmatic config, and not security
  invariants. Four are semantic and are covered below.
- **Semantic tier (lines 1331–1926)** — cross-flag consistency. This is where bypasses
  live, and every member was traced to its downstream enforcement or found to have none.

## Findings

### Confirmed bypass, now fixed — `--target-uri`

`async_serve` refuses to serve when the origin-form of the configured target differs from
the one the request arrived at. That comparison is answerable only for an **absolute**
target:

```rust
fn origin_form_of(absolute: &str) -> Option<String> {
    let authority_start = absolute.find("://")? + 3;   // None without a scheme
    ...
}

fn target_uri_mismatch(configured: &str, received: &hyper::Uri) -> Option<String> {
    if configured.is_empty() { return None; }          // None reads as "no mismatch"
    let configured_origin = origin_form_of(configured)?;
    ...
}
```

A `None` from either line propagates as *consistent*. So an empty or scheme-less
`--target-uri` does not weaken the request-target reconstruction check — it **disables it
for every request**, silently, while the deployment goes on reporting the binding as in
force. The verifier's own audience comparison cannot catch it either: both sides are the
same configured string, so it compares equal to itself.

Both functions documented the shape as something the parser had already guaranteed:

> `None` only for a target with no `://`, which `cli::parse_args` refuses — so on the
> served path this is always `Some`, and the mismatch check is always live.

True for argv, and only for argv. The impact is the one the parse-time diagnostic already
described: an ingress fanning several paths into one process would verify signatures over a
`@target-uri` no request arrived at.

**Fix.** The rule moved into `cli::target_uri_violation`, consulted by both `parse_args`
(at the position it always occupied, so the CLI diagnostic is unchanged) and
`unsafe_config_violations`. The two downstream comments now name the boundary rather than
the parser. Sixth member of this file's parser-only family, after
`validate_tls_signing_exclusivity`.

### Verified covered — no action

| Invariant | Enforced by |
|---|---|
| a replay state requires a durability tier | `startup_plan::ReplayPlan::from_config` — `ok_or` on the tier |
| `linearizable` requires `--cpstore-etcd-endpoint` | same, `ok_or` on the endpoint |
| non-linearizable shared requires `--replay-redis-url` | same, `ok_or` on the url |
| a sub-strict durability tier | same, refused outright |
| at least one `--inner-http-url` | `trust_plane.rs:264` |
| delegated trust epoch required; `0 < overlap < ttl` | `delegated_wiring.rs:84–88` |
| PKCS#11 / AWS / GCP required flags per key source | `build_key_source`, per source |
| online OCSP posture | `online_ocsp_refusal`, at the boundary |
| unenforceable revocation list | `unenforceable_revocation_list_refusal`, at the boundary |
| unaccepted authz profile | `unaccepted_authz_profile_refusal`, at the boundary |
| undeployable transport binding (Mode C) | `undeployable_transport_binding_refusal`, at the boundary |
| admission-gate coherence, incl. the degraded window | `unenforceable_admission_refusal`, at the boundary |
| contradictory TLS custody | `tls_signing_exclusivity_refusal`, at the boundary |

The boundary additionally enforces, with no parse-time counterpart: client-cert lifetime
ceiling, connection-age bound, revocation tier versus trust-reload cadence, slow-loris
timeouts, `cn_legacy` identity, non-durable replay, fleet replay locality,
reverse-proxy header ingress, and `--transport-binding none|lb-assertion`.

### Parser-only, and deliberately left there

These are refused only by `parse_args`. Each was checked and is **not** a security bypass;
the reasoning is recorded so a later reader does not have to redo it.

**Dangling-flag guards** — `--pkcs11-tls-key-label`, `--aws-kms-tls-key-id`,
`--gcp-kms-tls-key-version`, `--aws-kms-use-web-identity`, `--aws-sts-endpoint`,
`--gcp-kms-use-metadata`, `--cpstore-etcd-endpoint`, `--trust-epoch-redis-url`,
`--ingress-lb-key`, the Mode-C ingress flags, `--ocsp-responder-url`.

Each refuses a flag that would silently do nothing under the selected mode. The hazard is a
false operator belief, which is real — but the *resulting posture* is the one the other
flags describe, and that posture is itself assessed at the boundary. A dangling
`--ingress-lb-key` under `--transport-binding exact` leaves a **stronger** binding in force,
not a weaker one. Migrating these would add boundary noise without closing a hole.

The three delegated-TLS custody selectors are a partial exception: the *contradiction* they
can form with an exported `--tls-key` is the finding already migrated;
what remains parser-only is only the "wrong key source" dangling case.

**`--trust-domain` must not be empty.** The trust domain is one component of the
`role:trust_domain:subject:keyid` actor id, and each component is escaped before the join
(`block.rs:57–63`). An empty component therefore yields `role::subject:keyid`, which stays
distinct from every populated one — no collision and no tautology. The guard exists to stop
the historical `example.com` placeholder from being inherited by hand-rolled deployments,
which is deployment hygiene rather than an enforceable invariant. Recorded, not migrated.

**Bounded-value guards** — `--client-crl-reload-secs`, `--max-connections`,
`--max-in-flight`, `--drain-grace-secs` must each be `> 0`. A programmatic zero is
reachable. These are availability and resource bounds rather than authorization decisions,
and the drain-grace one is exercised by the ADR-MCPRE-057 teardown work. Candidates for a
later sweep; none of them admits an unauthorized request.

## Verdict against the release criterion

> No runtime or security invariant depends solely on `parse_args`.

**Satisfied**, for the class of invariant the criterion names — the ones that decide whether
a request is admitted, whom it is attributed to, and what it is bound to. One genuine
bypass was found and closed. What remains parser-only is dangling-flag hygiene, one
placeholder guard, and four resource bounds, each recorded above with its reasoning.

This is a statement about *enforcement placement*, not about `parse_args`'s size. The
function is still ~1300 lines and its structural decomposition into a configuration
compiler remains open engineering work — but it is now debt, not a security gap.

## Negative controls

Every claim of enforcement above was verified by removing the enforcement and observing a
test fail, then restoring it. For the migrated rule specifically:

| Broken | Observed |
|---|---|
| delete the `target_uri_violation` call from `unsafe_config_violations` | `a_programmatic_config_cannot_disable_the_request_target_reconstruction_check` fails |
| absolute target on the same fixture | not refused — the control that proves the boundary is not simply refusing everything |
