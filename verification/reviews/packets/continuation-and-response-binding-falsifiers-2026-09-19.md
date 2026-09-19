# ADR-MCPRE-068 Phase 2, slice 18 — the establishment that did not happen

Two probes, `M240` and `M241`. Both propositions are about a record that reads as something
it is not.

## 1. A control that measured the precondition, not the backend

`proxy.continuation_materialization_shared` says: in a build that **carries** the backend, a
selected continuation store that cannot be established refuses startup rather than announcing
OFF.

The declared control reached that refusal by **withholding the control runtime** — so it
measured the seam's own precondition and never touched the store. The realistic failure is
the other one: the runtime is there, the operator selected a store, and the store cannot be
reached. That path has its own `?`, and nothing held it: `M240`'s weakening replaced it with
`Established::off` and every declared control stayed green.

`a_selected_store_that_cannot_be_reached_refuses_startup` points the establishment at a port
nothing can listen on without privilege, so the connect refuses rather than hanging.

**Why the weakening matters** is what the module itself already says: an ignored selection is
indistinguishable in the transcript from an operator who never set the flag. A deployment that
asked for cross-replica continuation correlation and got OFF prints the same startup line as
one that asked for nothing — so no log, no readiness probe and no audit can tell that a
selected security capability was silently downgraded.

The feature-gated sibling arm is not a second carrier. It refuses a selection a build **without**
the backend cannot establish — a different fact about a different binary.

## 2. Two bindings, and the signature carries only one

`http_profile.response_emission_binding` states two things about an emitted response:

| binding | binds the response to | carried by |
|---|---|---|
| the `;req` components | the request's **signature base** | the signature |
| the evidence block's request-evidence handle | the request's **evidence** | the body |

`M241` corrupts the handle and leaves `;req` untouched. The response still verifies as the
answer to this transmission, while the handle it carries names a request that does not exist.
That is exactly what makes these two conjuncts rather than one — and an audit reconciling a
response against the request it answers reads the **handle**, not the signature base, so a
wrong handle is a record that cannot be checked against anything.

## 3. What this slice discharged

| unit | probe | severity |
|---|---|---|
| `proxy.continuation_materialization_shared` | `M240` | critical |
| `http_profile.response_emission_binding` | `M241` | critical |

N1 moves 43 -> 41; the probe registry 261 -> 263. One control written, because a falsifier
proved the existing one measured a different failure.
