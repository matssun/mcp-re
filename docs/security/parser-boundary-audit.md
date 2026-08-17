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

A parse-time check that duplicates a boundary check is redundancy to remove. It was kept
for one migration, to hold the diagnostic an operator meets first unchanged while the rule
moved (ADR-MCPRE-058 §8.5); once the rule is at the boundary the second call site buys
nothing and costs an early return, which means a command line wrong in four ways is
answered about one. `parse_args` now decides no legality at all: it reads syntax, records
provenance, applies the CLI's own defaults, and hands the request to the same boundary
every other caller meets.

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

**Fix.** The rule moved into `cli::target_uri_violation`, consulted by
`unsafe_config_violations`. The two downstream comments now name the boundary rather than
the parser.

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

### Was parser-only, now closed at the boundary

This section recorded three families as parser-only-but-acceptable. Two of the three
arguments were wrong, and recording them is more useful than deleting them: each was a
defensible-sounding reason to leave an enforcement site where it did not belong.

**Dangling-flag guards.** The argument was that a dangling flag leaves the posture the
*other* flags describe, which the boundary assesses — so migrating would add noise without
closing a hole. That holds for the resulting posture and misses the hazard the guard is
about: an operator who believes a control is configured stops looking for one that is not.
All of them are boundary clauses now, in their owners — the delegated-TLS selectors under
relation X2a, the KMS credential-mode flags under `Custody`, `--cpstore-etcd-endpoint`
under `Replay`, `--trust-epoch-redis-url` under `TrustRevocation` (X8), the ingress flags
under `ChannelBinding`, and `--ocsp-responder-url` beside the OCSP mode clause it
parameterizes. It was the last of them, and the only one that had no owner to move to
until one was written.

**`--trust-domain` must not be empty.** The argument — that an empty component still yields
a distinct actor id, so there is no collision — was sound about collisions and answered the
wrong question. An identity coordinate that is empty in two deployments is one coordinate
fewer distinguishing them from each other, and the same reasoning applies to `--audience`,
`--server-signer` and `--server-key-id`, none of which had a guard at all. All four are
boundary clauses, stated one field at a time.

**Bounded-value guards.** The argument was that a resource bound is not an authorization
decision. `--max-connections 0`, `--drain-grace-secs 0` and a `--client-crl-reload-secs`
of zero are each a limit that disables the control it bounds, which is a security posture
whatever tier it sits in; they are boundary clauses now, beside the slow-loris timeouts
that were already there. `--max-in-flight` is the exception that stayed, and for a reason
that is not a judgement call: `InFlightLimitRequest` holds a `NonZeroUsize`, so a
programmatic zero is not reachable — the type closed it.

### What is left in the parser

Syntax, provenance, and the CLI's own normalization: unknown flag, missing value,
unparsable number, an enum spelling that names no variant, splitting a comma-separated
list, applying the default an omitted flag means, and the two rules that are about an
*argument list* rather than about a deployment —

- `--pkcs11-pin` is refused because the PIN is in this process's argv, which no
  `DeploymentRequest` can express and no boundary can observe;
- `second_admission_limit` refuses naming both admission-limit flags, because
  `InFlightLimitRequest` holds one limit and a request naming two is unrepresentable —
  "already set" is a fact about the input.

## Verdict against the release criterion

> No runtime or security invariant depends solely on `parse_args`.

**Satisfied**, and no longer only for the class of invariant the criterion names. Nothing
about deployment legality is decided in `parse_args`: every clause it used to hold is at
the validation boundary, in the machine or relation that owns it, and each is covered by a
control that builds the request programmatically so the parser cannot participate.

This is a statement about *enforcement placement*, not about `parse_args`'s size. The
structural question was measured separately and closed: see
[`../dev/cli-responsibility-map.md`](../dev/cli-responsibility-map.md). The remaining
function is a shallow 79-arm dispatch table with a median arm of one line, so ADR-MCPRE-058
closes it as a reviewed R-3 exception rather than decomposing a lookup table across files.

## Negative controls

Every claim of enforcement above was verified by removing the enforcement and observing a
test fail, then restoring it. For the migrated rule specifically:

| Broken | Observed |
|---|---|
| delete the `target_uri_violation` call from `unsafe_config_violations` | `a_programmatic_config_cannot_disable_the_request_target_reconstruction_check` fails |
| absolute target on the same fixture | not refused — the control that proves the boundary is not simply refusing everything |
