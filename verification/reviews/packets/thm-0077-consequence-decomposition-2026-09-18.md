<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-MCPRE-068 Phase 1 — THM-0077 "No deployment serves a posture nobody selected", decomposed

`high` direct, 16 declared dependencies, a 22-theorem closure, 18 distinct semantic owners.

Decomposed with an extra obligation: one root earlier, THM-0074's decomposition named THM-0077
as the premise its antecedent quantifies over. So this root now carries a `critical` consumer,
and its effective severity is `critical` by N3 whatever its own direct label says.

## 1. The consequence

If THM-0077 is false, an operator obtains a weaker security posture than the one they
configured — or a serving component disagrees with the owner about what WAS configured — and
nothing says so. Two attacks, and they are different failures:

| # | the attack | proposition |
|---|---|---|
| A | a capability the runtime holds that no validated owner state produced | P1 |
| B | an illegal, unsupported or contradictory posture SILENTLY reinterpreted as a weaker one | P2 |

B's load-bearing word is *silently*. A posture that is refused loudly at layer A is inside the
claim, not a violation of it — the root's own scope says the same thing about availability:
"an unavailable tier failing closed is inside the claim, an unavailable tier being softened
into an allow is not".

## 2. The propositions

### P1 — PROVENANCE. Every security capability derives from validated semantic owner state.

The interesting half is the word **every**, because that is a universal claim over a set
nobody enumerates. What makes it total is THM-0067, and the mechanism is worth stating: the
composition root's raw reads are PINNED to an inventory, so a capability that did not come
through an owner must appear as a raw `values.<field>` read in `app.rs` and fail the
inventory. Completeness is enforced by exhaustiveness over reads rather than by listing
capabilities — which is why the list below is evidence of coverage and not the definition of
it.

The capabilities the closure names one by one: listener posture (THM-0048, THM-0054), replay
tier (THM-0086), continuation capability (THM-0096), custody (THM-0064), signing role
separation (THM-0073), the trust seam (THM-0066), trust epoch source (THM-0036), credential
window (THM-0102), outbound destination (THM-0090), KMS endpoint authority (THM-0089), online
OCSP (THM-0013), admission degradation (THM-0005).

### P2 — NO SILENT WEAKENING.
* owners: `proxy.cross_machine_legality` (THM-0049, illegal cross-owner combinations refused
  at layer A), `proxy.tls_listener_state` (THM-0054, unknown revocation status denied),
  `proxy.replay_materialization` (THM-0086, the established tier is the selected one and
  never a weaker substitute), `proxy.continuation_materialization` (THM-0096, exactly the
  capability the plan names)

## 3. Falsifying the root statement

**Attempt 1 — is P1's totality real, given that the inventory reads only `app.rs`?** This is
the attack the mechanism above invites: a capability selected somewhere OTHER than the
composition root is invisible to an inventory over the composition root. Ambient process
state is the obvious route, so it was measured rather than reasoned about.

There ARE production reads of ambient environment outside `app.rs`:

```
mcp-re-proxy/src/aws_sts.rs           AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
                                      AWS_SESSION_TOKEN, AWS_ROLE_ARN,
                                      AWS_WEB_IDENTITY_TOKEN_FILE, AWS_ROLE_SESSION_NAME
mcp-re-proxy/src/key_source.rs:320    std::env::var(var)   -- var named by validated config
mcp-re-proxy/src/gcp_kms_keysource.rs:193  MCP_RE_GCP_ACCESS_TOKEN
```

Every one was read. Every one supplies credential MATERIAL for a capability the validated
state already selected, and every one fails closed when absent — `EnvAccessTokenSource`
returns `KeyError::NotFound("gcp-kms: MCP_RE_GCP_ACCESS_TOKEN not set")` rather than
falling back, and `key_source.rs` the same. None of them SELECTS a posture. **The attempt
fails, and the root holds.**

**But it fails by inspection, not by a control** — see §5. Nothing would stop the next such
read from selecting one.

**Attempt 2 — does "silently" let a loud weakening through?** No, and the distinction is
carried rather than assumed: THM-0086 says the established replay tier is the selected one
"and never a weaker substitute", and THM-0096 says the runtime installs "exactly the
continuation capability its plan names". Both are identity claims, not adequacy claims, which
is the correct shape for P2.

**Attempt 3 — does THM-0013 ("no validated deployment enables online OCSP") belong here at
all?** It is a claim that a capability is NOT available, which reads oddly under a root about
capabilities being derived. It belongs: an online-OCSP path that a deployment could enable
would be a capability whose posture (network reachability deciding revocation) no owner state
governs. Registered `medium`, falsified (`mutation` present). No correction.

## 4. Evidence, measured

Eighteen owners. **Twelve carry a registered falsifier; six do not**, and all six are already
registered N1 obligations:

```
proxy.trust_composition_root   DEBT=critical   <- P1's own carrier
proxy.cross_machine_legality   DEBT=critical   <- P2
proxy.custody_exposure         DEBT=critical
proxy.signing_role_separation  DEBT=critical
proxy.kms_endpoint_authority   DEBT=critical
proxy.replay_materialization   DEBT=critical   <- P2
```

`http_profile.admission_currency` is `proved` (Verus) and was not reclassified.

This is a markedly healthier root than THM-0076: two thirds of its owners have had something
try to break them. `proxy.trust_composition_root`'s obligation is discharged by M149 on the
source-text falsifier branch — the probe reintroduces a raw `max_clock_skew` read and turns
the inventory red, which is precisely P1's carrier being shown load-bearing.

## 5. Premises, boundaries and review obligations

* **REVIEW OBLIGATION (new, and the finding of this packet).** P1's totality rests on the
  composition root being the ONLY place a security capability is selected. That is true today
  — measured in attempt 1, at every ambient read in the proxy — and **no control enforces
  it**. There is no gate saying "no production module outside the composition root selects a
  security posture from ambient process state", where there IS one saying the authorization
  authority names no transport header (`authorization_provenance_gate.py` Law A-1) and one
  pinning the root's raw reads (`composition_raw_read_test`). The shape of the missing control
  is already in the tree twice over; what is missing is this instance of it.

  Recorded as a review obligation rather than fixed here: writing it is production work in a
  phase whose job is decomposition, and it is a gate with a `gate#` falsifier — which is now
  an available form, on the source-text falsifier branch. Sequenced after that lands.

* **EXTERNAL BOUNDARY** — the AWS and GCP provider credential chains (THM-0089, THM-0116).
  What the provider's own discovery does with `AWS_ACCESS_KEY_ID` is the provider's; the claim
  ends at the endpoint reaching the authority its text names.
* **ASSUMED** — none new.

## 6. What was NOT done here

Nothing discharged. No split: question 2 was asked of all eighteen owners and none answered
with a second independently describable authority its theorem layer had not already separated
— `proxy.trust_composition_root` carries THM-0067, THM-0038 and THM-0077, and those are one
authority stated at three altitudes (the general inventory, its trust specialization, the
system promise) rather than three authorities. The review obligation in §5 is recorded, not
discharged.
