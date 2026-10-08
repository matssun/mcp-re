# Semantic Machine Model

Status: **Working model / pre-ADR**

## 1. Core form

The working semantic form is:

$$
step :
C \times S \times E \times A
\rightarrow O
$$

where:

- $C$ = validated semantic configuration;
- $S$ = current security state;
- $E$ = event / external evidence / completed external effect;
- $A$ = explicit authority/capability under which the transition is attempted;
- $O$ = closed outcome.

The purpose of this form is not to require one literal Rust function. It defines the semantic shape that the implementation must refine.

## 2. Closed outcome

A useful starting form is:

$$
O =
Commit(S', Effects)
\;|\;
Refuse(Reason)
\;|\;
Await(Pending)
$$

A security-relevant operation should not have an implicit fourth class of outcome.

This forces questions such as:

- Does failure mutate state?
- Is retry distinguishable from refusal?
- Are external effects committed before or after state?
- Can an incomplete effect increase authority?
- What must be persisted before `Commit` is considered complete?

The precise outcome algebra may evolve, but it should remain closed.

## 3. Recursive refinement

The same semantic form applies at multiple levels.

### System

$$
step_{system} :
C_{system}\times S_{system}\times E_{system}\times A_{system}
\rightarrow O_{system}
$$

### Subsystem

$$
step_{subsystem} :
C_i\times S_i\times E_i\times A_i
\rightarrow O_i
$$

### Narrow mechanism

$$
step_{mechanism} :
C_j\times S_j\times E_j\times A_j
\rightarrow O_j
$$

The goal is a refinement hierarchy, not one monolithic global state machine.

## 4. Security state $S$

Security state should be represented by explicit semantic states rather than loosely related booleans.

Example:

```text
Absent
Provisioned
Active
Retiring
Retired
Revoked
```

is preferable to independent flags such as:

```text
active
expired
revoked
published
```

unless every boolean combination is genuinely meaningful.

### Required property

Security-sensitive state representation should become private enough that:

$$
Mutation(S)
\Rightarrow
RegisteredTransition
$$

This should eventually be mechanically enforceable.

## 5. Configuration $C$

Raw configuration should not be consumed throughout security-sensitive implementation.

Preferred flow:

```text
Raw configuration
      ↓
parse
      ↓
validate
      ↓
ValidatedSecurityConfig
      ↓
construct
      ↓
Initial semantic state
```

A foundational property is:

$$
Accepted(c)
\Rightarrow
Invariant(InitialState(c))
$$

Semantic configuration should collapse irrelevant syntactic variation.

For example, CLI, environment, and Helm inputs that produce the same security semantics should normalize to the same configuration class.

## 6. Events and evidence $E$

`E` includes information entering the machine whose provenance matters.

Examples:

- verified request;
- certificate observation;
- Redis response;
- KMS completion;
- timeout;
- epoch observation;
- restart recovery input;
- signer rotation request;
- revocation observation.

External facts should move through typed validation boundaries.

Example:

```text
RawRequest
   ↓
CanonicalRequest
   ↓
SignatureVerifiedRequest
   ↓
AuthorizedRequest
```

Trusted forms should have constrained constructors.

Desired property:

$$
TrustedValue
\Rightarrow
ProducedByRegisteredBoundary
$$

## 7. Authority $A$

Authority should be represented explicitly.

Examples:

- signing authority;
- trust mutation authority;
- signer-retirement authority;
- continuation-consumption authority;
- registration authority.

Security effects should require possession of a capability value or equivalent proof object.

Desired properties include:

$$
Effect(e)
\Rightarrow
RequiredAuthority(e)
$$

$$
Authority(a)
\Rightarrow
ValidProvenance(a)
$$

$$
Revoked(a)
\Rightarrow
\neg FutureEffect(a)
$$

## 8. Pure decision, explicit effects

Where possible, separate semantic decision from external effects.

Conceptually:

```text
C + S + E + A
      ↓
    step
      ↓
TransitionPlan
      ↓
effect adapters
      ↓
completion/failure events
      ↓
    step
```

This isolates the security transition relation from Redis, KMS, PKCS#11, filesystem, network, and clock mechanics.

It also turns adapter failures into explicit events rather than hidden control flow.

## 9. Generated transition obligations

Every declared transition should automatically generate a standard family of questions.

### Preconditions

What configuration, state, evidence, and authority permit the transition?

### Postcondition

What state must result?

### Invariant preservation

$$
Invariant(S) \land Step(S,e,a)=S'
\Rightarrow Invariant(S')
$$

### Authority confinement

Could the transition occur without the required authority?

### Failure behavior

If an effect fails, what state remains?

A useful generic target is:

$$
Failure
\Rightarrow
Authority(State') \le Authority(State)
$$

where $\le$ means "no more permissive than".

### Recovery

What happens after process restart or store recovery?

### Rollback

Can previously revoked or superseded state become authoritative again?

### Concurrency

For overlapping transitions $t_1,t_2$, require either commutativity or an allowed serialization:

$$
Concurrent(t_1,t_2)
\Rightarrow
EquivalentToAllowedSerialOrder
$$

### Reachability

Is the transition actually reachable under supported configuration, or is a theorem vacuous?

## 10. Persistence and recovery

Security state that survives process death must be modelled explicitly.

Define a recovery relation:

$$
recover :
PersistentState \times Environment
\rightarrow S
$$

Then prove the relevant invariant:

$$
ValidPersistentState(p)
\Rightarrow
Invariant(recover(p))
$$

Examples:

- revoked authority cannot reappear after restart;
- epoch cannot recover below the accepted floor;
- consumed continuation does not revive if the persistence contract promises one-shot consumption.

## 11. Observation

State-transition correctness alone does not cover confidentiality or information flow.

Subsystems with confidentiality requirements need an observation function:

$$
observe(observer,S)
$$

or an equivalent relational model.

This permits properties over multiple executions, for example:

$$
SamePublicInputs
\land DifferentSecrets
\Rightarrow
SameAllowedObservations
$$

where required.

## 12. Composition

MCP-RE should be modelled as multiple bounded semantic machines, not one enormous machine.

Candidate machines may include:

- configuration;
- identity;
- admission;
- registration;
- attestation;
- trust resolution;
- trust epoch;
- signer lifecycle;
- replay;
- continuation;
- transparency;
- audit;
- shutdown/drain.

The global state is a composition:

$$
S_{global}
=
S_1 \times S_2 \times \cdots \times S_n
$$

but machines interact only through declared contracts.

Cross-machine invariants become composition theorems.

Examples:

$$
Admission.Accepted(actor)
\Rightarrow
Identity.Verified(actor)
$$

$$
Continuation.Live(actor)
\Rightarrow
AdmissionEvidence(actor)
$$

$$
Signing.Active(epoch)
\Rightarrow
TrustEpoch.Current(epoch)
$$

## 13. Implementation correspondence

For each modelled subsystem, create an explicit mapping:

```text
Rust type              -> semantic state
Rust method/API        -> transition
adapter completion     -> event
capability type        -> authority
config validator       -> configuration constraint
error/refusal          -> outcome
persistent record      -> recovery input
```

Every production security path should map.

If code cannot be mapped, one of two things is true:

1. the semantic model is incomplete; or
2. the implementation contains behavior that should not exist.

That discrepancy is a primary migration signal.

## 14. Refactoring rule

Refactor only the mismatches necessary to make the correspondence sound.

Do not use formalization as a reason for broad aesthetic cleanup.

After correspondence is established, add structural gates that enforce:

$$
SecurityEffect_{production}
\Rightarrow
RegisteredMachineTransition
$$

The goal is to make future unmodelled security paths difficult or impossible to introduce.
