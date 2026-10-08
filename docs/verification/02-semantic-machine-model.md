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

### 1.1 Determinism

`step` is a **function**: given complete $C$, $S$, $E$ and $A$, the outcome is determined.

Every nondeterministic or external observation that the transition decision depends on is therefore part of $E$, not hidden inside `step`:

- clock observations (`now` is an input, never a call);
- KMS, PKCS#11 and other signer completions, including their failures and timeouts;
- Redis and other store results, including outages and malformed replies;
- entropy draws, where the decision depends on the drawn value;
- recovery input read at restart;
- scheduler or interleaving observations, where the order of two events is semantically relevant;
- external failures of any adapter.

Nondeterminism does not disappear under this choice; it moves. It lives in **which event sequences can occur**, and properties that must hold under every interleaving or every adapter result are stated by quantifying over the admissible event sequences, not by making `step` itself relational.

The reason for the choice is practical and matters when the model reaches Lean: a total function over closed inputs is directly definable and evaluable, its proofs are proofs about one outcome, and a refinement claim against it (05 §2) compares an implementation step with one semantic outcome instead of with a set.

If a machine is found where this cannot be stated truthfully (where the decision depends on something that cannot be named as an observation), the alternative is a relational form

$$
step \subseteq C \times S \times E \times A \times O
$$

recorded for that machine, with the reason. It is not adopted by default, and a switch to a nondeterministic or powerset model for the architecture as a whole would be an architectural decision, not a modelling convenience.

## 2. Closed outcome

A useful starting form is:

$$
O =
Commit(S', Effects)
\;|\;
Refuse(Reason)
\;|\;
Await(S', Pending)
$$

A security-relevant operation should not have an implicit fourth class of outcome.

### 2.1 Pending effects are state

A security-relevant outstanding external effect, such as a signature requested from KMS or a store write not yet acknowledged, **is itself semantic state**. `Await` therefore carries a successor state: the outstanding effect is recorded in $S'$, or carried alongside it as `Pending`. The exact representation is for the pilot to determine (05 §9, Q2). Either way, the model must be able to express and constrain:

- **completion correlation**: which outstanding effect a completion event belongs to;
- **duplicate and stale completions**: a completion that arrives twice, or for an effect that is no longer outstanding;
- **timeout and cancellation**: an outstanding effect abandoned before it completes;
- **retry**: reissuing an effect, and the relation between the two attempts;
- **restart while pending**: what recovery reconstructs about effects that were outstanding at process death;
- **authority change or revocation while pending**: whether a completion may still take effect after the authority under which it was issued has changed.

A wait with genuinely no security-relevant outstanding effect may leave the state unchanged ($S' = S$). That is the exception, and the machine records why the wait is state-neutral.

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

### 5.1 Semantic configuration classes

Two raw configurations are equivalent when they have the same security semantics:

$$
c_1 \sim c_2
\iff
SecuritySemantics(c_1) = SecuritySemantics(c_2)
$$

where $SecuritySemantics$ is what validation produces: the `ValidatedSecurityConfig` value, or the part of it the security machines consume. CLI flags, environment variables, Helm values and file inputs that normalize to the same validated security semantics belong to the same **semantic configuration class** $[c]$.

Two consequences follow:

- coverage is measured over classes, not over syntactic permutations. Exhaustively enumerating every combination of input spelling measures the parser, not the security behavior;
- the normalization itself carries an obligation: if two inputs that should mean the same thing normalize differently, or two that mean different things normalize the same, the class structure is wrong. That obligation belongs to the configuration machine and is checked there.

Configuration theorems (03 §2, Layer 4) quantify over classes, or over symbolic constraints that describe sets of classes, rather than over enumerated inputs. Where the class space is small and finite, enumerating it is a legitimate proof method; where it is not, the constraint form is used.

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

but the product is an organizing abstraction, not a claim that the machines are independent. Machines interact only through declared contracts, and those contracts include **cross-machine invariants**:

$$
I_{ij}(S_i, S_j)
$$

a predicate over the joint state of two (or more) machines that must hold in every reachable global state. The reachable global states are therefore a subset of the product:

$$
Reachable(S_{global}) \subseteq \{\, (s_1,\dots,s_n) \mid \textstyle\bigwedge_{(i,j)} I_{ij}(s_i,s_j) \,\}
$$

**Composition correctness is not implied by the Cartesian product of individually correct machines.** Each machine can preserve its own invariant while a pair of transitions, one in each machine, breaks an $I_{ij}$: a signer retired after a trust-state change has been observed by one replica but not another, a continuation that outlives the admission it depended on. A composition invariant is established by showing that every transition of either machine preserves it, including under the interleavings that the event model admits (§1.1).

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

Some cross-machine relationships are not state predicates but **ordering requirements**: signer retirement and a trust-state change may have to be applied in a particular order, or atomically, for the invariant to survive the transition between them. These are stated as composition obligations over the event sequences, not as invariants over a single state.

### 12.1 Authoritative state and replica views

Where a machine runs on several replicas, the model carries **both**:

- the **authoritative** (logical) security state, $S^{auth}$; and
- each replica's **observed** (local) state, $S^{view}_r$.

The model does not assume they are equal. The relation a replica's view must satisfy is part of the model, for example a bounded-staleness or currentness relation

$$
AllowedView(S^{view}_r,\ S^{auth},\ C,\ t)
$$

A replica decides on $S^{view}_r$, and that the view satisfies the relation is itself an obligation. The exact relation, its representation, and which invariants are stated over views and which over $S^{auth}$ are for the pilot to derive (05 §9, Q5).

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

### 13.1 Mapping is not refinement

A mapping **names** which Rust method corresponds to which transition. It does not establish that the method does what the transition says. Those are two different facts, and the second one requires evidence.

Refinement is stated through an abstraction function from implementation state to semantic state:

$$
\alpha : ImplementationState \rightarrow SemanticState
$$

together with abstractions of events and authority, $\alpha_E$ and $\alpha_A$. The intended rule is that every security-relevant implementation step corresponds to an allowed semantic transition:

$$
ImplStep(i, e, a) = i'
\;\Rightarrow\;
SemanticAllows(\alpha(i),\ \alpha_E(e),\ \alpha_A(a),\ \alpha(i'))
$$

and that an implementation step's outcome (commit, refusal, await) is the semantic outcome under $\alpha$. Implementation steps that are not security-relevant must leave $\alpha(i)$ unchanged (stuttering).

A mapping table is the input to that claim. It becomes evidence only when the refinement statement for the mapped transition is established. The precise form (simulation, forward refinement, the treatment of stuttering and of steps that `Await`) is developed in `05-refinement-and-closure-model.md` §2.

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
