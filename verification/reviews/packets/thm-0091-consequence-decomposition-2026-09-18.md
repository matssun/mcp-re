<!-- SPDX-License-Identifier: Apache-2.0 -->
# Phase-1 decomposition packet — THM-0091, the sidecar's ingress root

**ADR-MCPRE-068 Phase 1**, consequence-first. The third of the three roots ADR-MCPRE-068 §2
measured as *undecomposed end to end*, and the one that record called **the sharpest
illustration of its own thesis**:

> THM-0091's own statement names a structural fact: *possession of the scope IS that
> permission — there is no other constructor.* That is a seal, stated in the theorem, and
> the registry records the whole claim as `test://`. Under §4 the seal's falsifier is a
> construction that must not compile, and no such control exists.

This packet is that correction, and it found one thing §2 could not have: the seal was not
only unmeasured, it was **not load-bearing at the seam that opens the socket**. §2 F3.

**The statement itself is NOT changed by the commit that lands this decomposition.**
`scripts/claim_surface_gate.py` refuses a published root claim whose `theorem_claim` has
moved since the owner's specification review, and that refusal is correct: a claim nobody has
approved in its present form must not be published. So the decomposition — the units, their
owners, carriers, classes, batteries and probes, and this root's `supported_by` — lands, and
the CLAIM CORRECTIONS §2 proposes are batched for owner review with the other two members of
this Phase-1 group. §10 lists them as the exact edits requested.

---

## 1. The root consequence

| | |
|---|---|
| **root theorem** | THM-0091 |
| **declared root severity** | `critical` |
| **worst credible failure consequence** | a web page in the user's browser obtains signed, attributed MCP-RE calls under the agent's identity — by DNS rebinding, or because the listener answered to any `Host` |
| **externally visible security failure** | a remote server sees perfectly valid RFC 9421 evidence for a tool call the user never made. Every other root about what a signature MEANS stays true and says nothing about who caused it |

That the page cannot read the reply is no comfort: **the side effect is the payload.**

---

## 2. Falsifying the root statement

### F1 — the statement asserted two structural facts and the registry recorded neither

*"possession of the scope IS that permission — there is no other constructor"* and *"the
authority set is derived from that scope and never from the flag"* are claims about what
**cannot be constructed**. Nothing in the unit's evidence attacked either. Worse, nothing
COULD: a mutation probe deletes a runtime check, and neither of these sentences names one —
`AcceptedHttpAuthority`'s claim in particular is that there is no check anywhere to delete,
which is precisely why a behavioural falsifier is the wrong instrument for it.

Both are now `structural` units with compile refusals: **S22** and **S23**, each measured
`refused by E0451`.

### F2 — the root's closure did not reach the predicates the statement names

The statement names three caller-shape refusals: a present `Origin`, a `Host` that does not
name this listener, a body that is not JSON. Two of the three are decided by
`is_loopback_host` and `is_json_content_type` in `serve/guards.rs` — which was
`client.local_serving_pipeline`'s, a unit whose own description reads *"what the local
listener does with an **admitted** request: … host and content-type guards, …"*.

An admission authority inside a post-admission unit. The root's closure reached the WIRING
(`check_framing_and_caller_shape` calls a predicate) and not the PREDICATE (which names a
rebound host correctly). `serve/guards.rs` and its two controls are
`client.caller_shape_admission`'s now, and **M90** attacks `is_loopback_host` directly.

### F3 — the seal was not load-bearing at the seam that opens the socket

**This is the finding the decomposition was for, and it was produced by a measurement rather
than by reading.** M86 deletes `BindScope::decide`'s refusal and expects two controls red:
the constructor's own, and `serve::tests::bind_refuses_a_non_loopback_address_unless_it_is_declared`,
whose doc comment says *"the guard must be what refuses, at the seam that opens the socket —
not a validator the caller may skip."*

Measured, first run: **one red, one green.** The composition control did not notice.

The cause, in `serve::bind`:

```rust
pub fn bind(local: &LocalConfig) -> std::io::Result<TcpListener> {
    if !local.allow_non_loopback && !local.bind.ip().is_loopback() {
        return Err(std::io::Error::new(ErrorKind::InvalidInput, format!(
            "local.bind {} is not a loopback address. …", local.bind)));
    }
    TcpListener::bind(local.bind)
}
```

It re-implements `decide`'s condition, copies its message verbatim, and **never obtains a
`BindScope`**. So the theorem's sentence — *possession of the scope IS that permission* — was
false of the one path that actually opens the listener: the listener was opened by a `pub fn`
taking a raw `LocalConfig`, and the seal guarded a value that path never held.

This is R-COMPOSE exactly: *a composition root may combine owner-provided facts; it must not
recreate an owner's security semantics by destructuring its representation.* And it is the
twelfth question #10: the same security fact represented twice, kept in agreement by
remembering, with the error message duplicated character for character.

**Corrected here, in nine lines**, under the Phase-1 allowance for *a very small
representation correction necessary to establish what the proposition actually is*:

```rust
    let scope = BindScope::decide(local.bind, local.allow_non_loopback)
        .map_err(|refusal| std::io::Error::new(ErrorKind::InvalidInput, refusal.0))?;
    TcpListener::bind(scope.listen_address())
```

Re-measured: **M86 now turns both controls red.** The signature is unchanged, the duplicated
condition and message are gone, and the seam holds a scope.

### F4 — `config/local.rs` was in the paths and declared no control

Three controls exist — an unstated off-host declaration is a refusal and never a permission, a
misspelled security switch is a startup failure rather than a silent default, a bind that is
not an address is refused by the type — and the battery named none of them. The same shape as
the Python member's `nonce_floor` finding: a conjunct of a declared root with passing controls
and no claim.

They are `client.local_leg_declaration`'s now, with **M87** attacking `deny_unknown_fields`.

### F5 — one file holds three authorities and has no tests module

`config/validation.rs` (192 lines) holds `check_local`, `check_trust_and_delegation` and
`check_routes` — its own module doc calls them *"three groups, and they answer different
questions"* — and carries **no `#[cfg(test)] mod tests`**, against the repository standard.
Only the first belongs to this root. The file stays in `client.local_leg_declaration`'s paths
so that an edit to `check_local` invalidates this root's evidence, which is the behaviour that
matters; the split is recorded as **P2-B**.

### F6 — what the falsification did NOT find

- The `depends_on = []` is CORRECT here, unlike on the two SDK roots. Admission is decided
  from the validated local configuration alone; nothing in the ingress path reads a trust
  document, and the existing scope sentence declining `client.trust_manifest_lifecycle` as a
  dependency is right.
- The non-claim paragraph is exact: no local-caller authentication is offered, and `Origin`'s
  PRESENCE is the refusal rather than a comparison.
- Nothing here is true only under a feature subset.

---

## 3. The decomposition

```
THM-0091  the sidecar signs only for a request its ingress policy admitted    critical
│
└── supported_by
    client.local_leg_declaration            tested      high      M87
    client.bind_scope                       tested      critical  M86
    client.bind_scope_sole_producer         STRUCTURAL  critical  S22
    client.accepted_authority               tested      critical  M85
    client.accepted_authority_sole_producer STRUCTURAL  critical  S23
    client.caller_shape_admission           tested      critical  M88, M89, M90
    client.local_request_surface            tested      high      M91
```

Seven leaves, seven falsifiers over nine probes. `depends_on = []`, and §2 F6 says why that
is right here.

**The two/two shape is the pattern, not an accident.** `bind_scope` and `accepted_authority`
each appear twice — once `tested`, once `structural` — because a seal says an illegal
inhabitant cannot be BUILT and says nothing about whether the decision is RIGHT. Deleting
`decide`'s refusal leaves the seal intact and the decision wrong; opening the field leaves the
decision intact and the seal gone. Two propositions, two owners, two instruments. This is the
same split ADR-MCPRE-068 Phase 0D-3 through 0D-13 made eleven times over, arriving at a root.

Each unit's proposition, carrier, class, severity and battery is in
`verification/policy/verification.toml` beside it.

---

## 4. Evidence classes

- **`structural` ×2** — the two seals. Each names its construction boundary, the hostile
  construction, the rustc refusal, and all four producer paths (module-tree visibility,
  alternate constructors, generated/deserialization, test-only construction). Both refuse at
  **E0451**, which is the FIELD's privacy — the boundary each unit claims — rather than
  E0603, which would be the module's and a different proposition.
- **`tested` ×5** — behavioural refusals over a real head, a real socket and a real
  `LocalConfig` document. Each has a `mutation://` falsifier that turns a declared control red.
- **`proved`** — none. These are decisions over strings, addresses and header shapes; there
  is no specification here a prover would discharge that a battery does not.
- **`measured`** — none. Nothing is scoped to a corpus or an environment.

---

## 5. Premises

`depends_on = []`, and no `[[assumption]]` is created. The ingress decision reads the
validated local configuration and the socket, and nothing else. The external boundary it does
end on is the operating system's `TcpListener::bind` and `SO_RCVTIMEO` semantics — recorded
here as a stated boundary rather than as a premise record, because no claim above it depends
on more than "the OS refuses an address that is not local, and a read timeout expires".

---

## 6. ADR-MCPRE-069 dispositions

| | count |
|---|---|
| control functions in the predecessor unit's paths | 21 |
| registered before | 16 |
| registered after | **20** |
| newly registered | 3 (`register`) + 1 (`register`, the composition control) |
| reattributed IN from `client.local_serving_pipeline` | 3 |
| `not-evidence` | 1 |

`register`: the three `config::local::tests` (§2 F4) and
`serve::tests::bind_refuses_a_non_loopback_address_unless_it_is_declared` — the composition
control, which was in a file the predecessor unit already owned and was claimed by nothing.
It is the control that measured §2 F3.

`reattribute` **in**: `serve::guards::tests::only_loopback_literals_and_localhost_are_accepted_hosts`,
`serve::guards::tests::only_json_content_types_are_accepted` and
`tests/local_leg_e2e_test#the_local_http_surface_refuses_everything_it_does_not_implement`.
The first two decide admission (§2 F2); the third's subject is what the HTTP surface refuses,
which is `client.local_request_surface`'s proposition and not the pipeline's.

`not-evidence`: the `find_head_end` helper's own coverage is inside
`the_head_terminator_is_found_at_its_own_end`, already registered.

`client.local_serving_pipeline` keeps its debt row and its remaining sixteen controls; its
description loses "host and content-type guards", which it should never have had.

---

## 7. Adequacy

Read forward: the operator's document is refused or complete (`local_leg_declaration`); the
bind is permitted and the scope proves it (`bind_scope` + its seal); the authority set comes
from that scope and from nothing else (`accepted_authority` + its seal); a request is framed
before any header is believed and the three refusals run before a byte is signed
(`caller_shape_admission`); and nothing outside `POST` + `Content-Length` + one exchange per
connection is parsed at all (`local_request_surface`).

**What they deliberately do NOT establish**: which local process sent an admissible request
(there is no local-caller authentication and none is offered); that the local leg is
confidential; that anything is served; what the sidecar then does with an admitted request —
that is THM-0084, THM-0057…THM-0061, and `client.local_serving_pipeline`'s.

---

## 8. The Phase-1 falsifier against the decomposition

| removed | the root's consequence then reachable by |
|---|---|
| `local_leg_declaration` | a misspelled `allow_nonloopback` reads as a document the operator did not write |
| `bind_scope` | an off-host listener is bound with no declaration |
| `bind_scope_sole_producer` | a scope for an unpermitted address is assembled directly, and the refusal guards nothing |
| `accepted_authority` | a rebound name reaches signing on an exposed listener |
| `accepted_authority_sole_producer` | a caller writes `AcceptedHttpAuthority { exposed: … }` and puts the conflation back, with no check anywhere to delete |
| `caller_shape_admission` | a browser page's `POST` is signed; or two `Content-Length`s let a reader and a writer disagree about where the message ends |
| `local_request_surface` | a dripping caller holds a worker; a chunked body lets one caller's bytes be read as another's |

Seven NOs. The inverse question returned nothing: every leaf's failure is reachable from a
browser or from an operator document, which is what this root is about. Concurrency, routing,
rendering and the close sequence were already outside it and stay outside.

---

## 9. Phase-2 obligations

| id | obligation | severity |
|---|---|---|
| **P2-A** | `serve::bind` is corrected here, but the SHAPE that allowed it is unaddressed: `bind` is `pub` and takes a raw `&LocalConfig`. Taking a `BindScope` would make the seam's obligation visible in the signature instead of inside the body | medium |
| **P2-B** | split `config/validation.rs` along the three authorities its own module doc names, and give each a `#[cfg(test)] mod tests` — it has none, against the repository standard | medium |
| **P2-C** | `mcp-re-client/src/lib.rs` and `main.rs` are in no unit's paths. `main.rs` is where the listener is opened and the refusal is reported to the operator | medium |
| **P2-D** | ADR-069's census tooling would not have found §2 F4 or the composition control: it reports per unit against `tested_symbols`, and both were inside an owning unit's own paths. The tooling is correct; what is owed is running it, which Phase 0 left unbuilt | high |

---

## 10. The claim corrections requested, and not taken

Each is an edit to `statement` or `scope` that this decomposition SUPPORTS but does not make.
`theorem_claim` is `statement + security_consequence + scope`, so any of them moves the
fingerprint and the published claim would be one the owner has approved in no form now on the
tree. None weakens or withdraws the promise.

**C1 — say that two of the facts are structural.** The statement already asserts *possession
of the scope IS that permission — there is no other constructor* and *the authority set is
derived from that scope and never from the flag*. The proposed wording adds that these are
compile-refused rather than checked, which is what S22 and S23 now establish, and adds the
operator-document half (*unstated is a refusal, and a misspelled declaration is a startup
failure rather than a silent default*) that `client.local_leg_declaration` carries.

**C2 — a scope paragraph recording the seal/decision split**, so a reader knows why
`bind_scope` and `accepted_authority` each appear twice: a seal says an illegal inhabitant
cannot be BUILT and says nothing about whether the decision is RIGHT.

**C3 — a scope sentence recording that the predicates the statement names are now in the
closure**, and that concurrency, routing, rendering and the close sequence are
`client.local_serving_pipeline`'s — each acting on a request this root has already admitted.

**C4 — no change to `depends_on`.** Unlike the two SDK members, `[]` is correct here: nothing
in the ingress path reads a trust document, and the existing scope paragraph declining
`client.trust_manifest_lifecycle` is right. Recorded so the review need not re-derive it.

The proposed text is §2's, verbatim, and the fingerprint it would produce is derivable from
it with `tools/verification/review --fingerprint THM-0091` once applied.
