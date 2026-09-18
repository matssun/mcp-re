<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-MCPRE-068 Phase 1 — THM-0076 "A client accepts only an answer to its own request", decomposed

`critical`, 8 declared dependencies, a 16-theorem closure, 11 distinct semantic owners — nine
of them client-side. Decomposed downward from the consequence. **The root survived
falsification; the finding here is about its evidence, not its statement.**

## 1. The consequence, stated precisely

If THM-0076 is false, an application is handed something as the answer to a call it made, and
acts on it. Five attacks:

| # | the attack | proposition |
|---|---|---|
| A | a response from another exchange | Q1 |
| B | from another signer | Q2 |
| C | from a signer whose authorization has been RETIRED | Q2 + currency |
| D | one that verified only in the unbound form | Q3 |
| E | led to repeat a side effect by reading silence as *it did not run* | Q4 |

E is the one that is not about cryptography at all, and it is the one with a side effect in
the world.

## 2. Falsifying the root statement

**Attempt 1 — is the shipped path's pairing established, or assumed?** Assumed once, and the
scope RECORDS that it was: the statement claimed the response resolved against "the request
this client sent" while the scope said the pairing was a caller obligation. That is a
contradiction, not a boundary, and THM-0084 removed it by establishing the pairing where the
shipped path owns it. Nothing to correct — a previous review already corrected it, and the
scope keeps the record.

**Attempt 2 — is the value returned to the caller the verified one, or a reconstruction?**
This is the client-side analogue of THM-0051, and on the serving side it needed a whole
source-text gate. It is owned: THM-0126 establishes that the shipped proxy "composes those
answers without adding a reading of its own", with the classification itself belonging to
THM-0061. In `depends_on` already.

**Attempt 3 — does verification consult CURRENT anchors, or a snapshot taken at
construction?** The sharpest question available, because the serving side has an entire
theorem family for exactly this defect (ADR-MCPS-021: a resolver chain constructed, its
guarantee printed, then dropped, while the enforcement point resolved from a map frozen at
process start). And the client's own registry says the request path is blind here —
`client.serving_lifetime`'s description: *"nothing on the request path consults that
expiry"*.

So currency rests entirely on the refresher. Measured: THM-0127 (the refresher is started
unconditionally and held for as long as the client serves) `depends_on` THM-0120 (a client
that cannot establish current anchors publishes NONE rather than serving on expired ones).
Both are in the closure. The graph is correct and the chain is complete.

**What that costs, and it is worth naming.** THM-0076's security property — attack C, a
retired authorization — rests on a LIVENESS property: a task that must keep running. THM-0074
disclaims liveness in terms ("It says nothing about liveness: that a valid request IS served
is not claimed"). THM-0076 cannot, and does not. The two roots are not in conflict; they are
different propositions. But a reader who carries THM-0074's habit across to the client side
will misread what THM-0076 needs, which is why it is recorded here rather than left implicit.

## 3. The propositions

| | proposition | owner | theorem |
|---|---|---|---|
| Q1 | verified against the request THAT PROXY SENT | `client.proxy_request_correspondence` | THM-0084 |
| Q2 | under a signer the CURRENT trust configuration authorizes in the Response slot | `client.response_acceptance`; currency from `client.trust_manifest_lifecycle`, `client.serving_lifetime`, `client.anchor_refresh` | THM-0058, THM-0057, THM-0127, THM-0120 |
| Q3 | a response that could not be bound is never a success | `client.response_acceptance` | THM-0059 |
| Q4 | what may be concluded is what the receipt STATES, never what its silence is read as | `client.execution_contract`, `client.verified_outcome` | THM-0061, THM-0126 |

Q2 and Q3 share an owner today. **They are two authorities and the split is already in
flight** — `client.response_acceptance` becomes `client.response_signer_authorization`
(THM-0058) and `client.response_binding_disposition` (THM-0059), with THM-0076 staying with
the binding half where `response.rs` composes the two. They fail independently and in opposite
directions: a perfectly bound answer under a revoked key, or a perfectly authorized signature
over somebody else's answer. Recorded in `residue-units-2026-09-18.md`; not re-derived here.

## 4. The finding: the client half of the estate is unfalsified

Eleven owners. Measured:

```
client.anchor_refresh                DEBT eff=critical   ['test']
client.delegation_policy_seal        DEBT eff=critical   ['test']
client.execution_contract            DEBT eff=critical   ['test']
client.manifest_floor                DEBT eff=critical   ['test']
client.proxy_request_correspondence  DEBT eff=critical   ['test']
client.response_acceptance           DEBT eff=critical   ['test']      <- the root's own owner
client.serving_lifetime              DEBT eff=critical   ['test']
client.trust_manifest_lifecycle      DEBT eff=critical   ['test']
client.verified_outcome              DEBT eff=critical   ['test']
http_profile.freshness_window        -                   ['test', 'verus']   (proved)
http_profile.verifier_results        -                   ['mutation', 'test']
```

**Every one of the nine client-side owners is `tested` with no falsifier, and every one is an
open N1 obligation at `critical`.** The only two owners in this root's closure that anything
has tried to break are the two it shares with the serving side.

This is not nine unrelated gaps, and the shape is sharper than "the client side is
unfalsified" — which is what a first pass of this packet said, and it was wrong. Measured
over the 186 registered probes:

```
http_profile  46      client   10
proxy        130

the 10 client probes, by unit:
  client.accepted_authority 1   client.bind_scope 1   client.caller_shape_admission 3
  client.local_leg_declaration 1   client.local_request_surface 1
  client.transport_message_hygiene 2   client.transport_server_identity 1

probed client units inside THM-0076's closure: NONE
```

The client side HAS falsifiers — ten of them. Every one attacks the client's local
INGRESS: which scope may bind, what caller shape is admitted, transport hygiene, server
identity. That is THM-0091's family, and it is well defended. Not one probe attacks any owner
in THM-0076's closure.

So the estate's client-side falsifier effort went entirely to the door and none of it to what
comes back through it. THM-0076 is a `critical` system root and nothing has demonstrated that
any check under it is load-bearing.

No debt was manufactured or uncovered — all nine were already registered. What the
decomposition adds is the shape: they are not scattered, they are the whole side.

**This is the measurement that should order Phase 2.** THM-0094 (Python SDK) and THM-0095
(TypeScript SDK) are the other two consumer-side roots, and the Phase-2 falsifier lane was
already scheduled for them. The client proxy belongs in that lane on the same argument, and
this packet is the evidence for saying so rather than an opinion about priority.

## 5. Premises, boundaries and review obligations

* **EXTERNAL BOUNDARY** — the FFI seam. `ResponseExpectation::new` stays public for bindings
  that rebuilt the request from scalars and hold no `SignedRequest`; sealing past that seam
  would be theatre. The root's scope already says raw FFI and low-level reconstruction are
  outside, and THM-0084's claim is precisely that the SHIPPED path does not use it.
* **EXTERNAL BOUNDARY** — whether the deployment was right to trust an anchor. Stated in the
  root's scope; unchanged.
* **ASSUMED** — attack E's guarantee ends at what the client REPORTS. That an application
  then declines to repeat the side effect is the application's. The scope does not say so and
  the consequence's wording ("cannot be led to") carries it; recorded here rather than
  proposed as a correction, because the client's obligation — not presenting silence as
  *it did not run* — is what THM-0061 establishes and is the whole of what production can
  offer.
* **REVIEW OBLIGATION** — none new.

## 6. What was NOT done here

Nothing discharged. No split performed — the one this root needs is in flight on another
branch and re-deriving it would manufacture a conflict for no gain. No claim correction: the
statement says what production establishes, and the one place it did not, a previous review
had already fixed.
