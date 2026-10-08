# Refinement and Closure Model

Status: **Working model / pre-ADR**

This document brings together the formal relationships between the semantic machine model (02) and the theorem and proof layers (03). It states, at working-model level, what it means for an implementation to refine a machine, for an obligation to be discharged, for the theorem package to be closed, and for a machine to count as migrated.

Nothing here is binding. Where a statement would need an architectural decision to become precise, it says so, and §9 lists those points as questions for the pilot.

## 1. Transition semantics

### 1.1 The step function

For each machine:

$$
step : C \times S \times E \times A \rightarrow O
\qquad
O = Commit(S', Effects) \mid Refuse(S', Reason, Effects) \mid Await(S', Pending)
$$

`step` is **deterministic**: a total function of complete inputs (02 §1.1). Every observation the decision depends on, such as clock readings, signer and store results, entropy where its value matters, recovery input and relevant interleavings, is an event in $E$.

### 1.2 Executions

Fix a semantic configuration class $[c]$ (§7). An execution is a sequence of events and authorities

$$
r = (e_1, a_1), (e_2, a_2), \dots
$$

drawn from the event sequences the environment model admits. Starting from $InitialState([c])$, each pair is fed to `step` in turn. Let $s_0 = InitialState([c])$. The successor is

$$
s_{k} =
\begin{cases}
S' & \text{if } step([c], s_{k-1}, e_k, a_k) = Commit(S', \_) \\
S' & \text{if the outcome is } Refuse(S', \_, \_) \\
S' & \text{if the outcome is } Await(S', \_)
\end{cases}
$$

$ReachableStates([c])$ is the set of all $s_k$ over all admissible executions.

Nondeterminism lives in the quantifier over admissible event sequences. A property that must hold "whatever the store returns" or "under any interleaving" is a property over all admissible $r$. It is not a property of a relational `step`.

A security-relevant outstanding external effect is semantic state (02 §2.1). `Await` carries a successor state that records it, either inside $S'$ or as the `Pending` component alongside it; the exact representation is open question Q2 (§9). The model constrains completion correlation, duplicate and stale completions, timeout and cancellation, retry, restart while pending, and authority change or revocation while pending. A wait with no security-relevant outstanding effect has $S' = s_{k-1}$, and the machine records why.

### 1.3 The relational alternative

A machine whose decision depends on something that cannot truthfully be named as an observation may use a relational form, $step \subseteq C \times S \times E \times A \times O$. That machine records the choice and the reason. The architecture as a whole does not move to a nondeterministic or powerset model by default; doing so would be an architectural decision.

## 2. Implementation abstraction and refinement

### 2.1 Abstraction

Refinement is stated through abstraction functions:

$$
\alpha : ImplState \rightharpoonup S
\qquad
\alpha_E : ImplEvent \rightarrow E
\qquad
\alpha_A : ImplAuthority \rightarrow A
\qquad
\alpha_{Eff} : ImplEffect \rightarrow Effect
$$

$\alpha$ is partial. It is defined on implementation states that satisfy the representation invariant $RI$, the condition under which the Rust values denote a semantic state at all. Part of every refinement claim is that $RI$ holds initially and is preserved.

$ImplState$ is the **security-relevant** implementation state: everything $\alpha$ reads. State that $\alpha$ ignores cannot affect security, and part of the mapping work (P1) is to justify that claim for each piece of ignored state.

### 2.2 Refinement obligation

For every implementation step $i \xrightarrow{e,\,a} i'$ with $RI(i)$:

$$
RI(i')
\;\land\;
\Big(
\underbrace{\alpha(i') = \alpha(i) \land NoSecurityEffect}_{\text{stutter}}
\;\lor\;
\underbrace{Corresponds\big(step([c], \alpha(i), \alpha_E(e), \alpha_A(a)),\ i',\ \text{effects}\big)}_{\text{semantic step}}
\Big)
$$

where $Corresponds$ requires the following.

- **Commit.** If the semantic outcome is $Commit(S', Eff)$, then $\alpha(i') = S'$ and the implementation's security effects map under $\alpha_{Eff}$ to exactly $Eff$.
- **Refuse.** If the semantic outcome is $Refuse(S', R, Eff)$, the implementation refuses with a reason mapping to $R$, $\alpha(i') = S'$, and its security effects map under $\alpha_{Eff}$ to exactly $Eff$. The ordinary refusal has $S' = \alpha(i)$ and no effects. A refusal that consumes one-shot state, records a monotonic failure, burns a token or writes evidence does so because the refusal transition says so (02 §2.2), and the refusal transition's own obligations are that its state and effects do not increase authority and do not perform the refused operation.
- **Await.** If the semantic outcome is $Await(S', P)$, then $\alpha(i') = S'$ and the implementation's outstanding work maps to $P$. Outstanding effects are part of what $\alpha$ reads.

This is a forward simulation in which the implementation may only do what the semantics allows. It is a **safety** refinement: it bounds what the implementation can do. It does not show that the implementation eventually does anything. Liveness and bounded-progress obligations need their own evidence (§3.3).

### 2.3 Mapping versus refinement

A mapping table entry, such as "`SignerLifecycle::retire` is the transition Retire", is an input to §2.2. It is not evidence for it. A transition counts as refined only when the refinement obligation for that transition has admissible evidence.

### 2.4 The three-part chain

$$
ModelCorrectness
+
ImplementationRefinement
+
MutationClosure
\Rightarrow
ProductionProperty
$$

The intended roles, without mandating any tool:

| part | establishes | typical method |
|---|---|---|
| model correctness | the property holds of the semantic machine over all admissible executions | Lean |
| implementation refinement | the production operation satisfies §2.2 for its transition | Verus, or an equivalent method suited to the code |
| mutation closure | no production path reaches the state or the effect except through the refined operation | structural gate, type-system confinement, visibility |

The parts compose only if they talk about the same things. The property proved in the model must be stated over $\alpha$-images. The refined operation must be the one the closure gate confines. The gate's notion of "the state" must be what $\alpha$ reads. Agreement between the parts is itself checked when the chain is reviewed.

Where an operation mixes a pure decision with I/O, the usual split follows 02 §8. Refinement is proved over the pure decision core. A structural part shows that the adapter only executes the decided plan and reports completions as events. That makes the refinement leaf a `Hybrid` obligation (§3).

## 3. Obligation requirements and admissible evidence

### 3.1 Requirement and admissibility

Every obligation $o$ carries a requirement, fixed when the obligation is generated:

$$
Requirement(o) \in \{Formal,\ Structural,\ Executable,\ External,\ Hybrid\}
$$

$$
Discharged(o) \iff Established(o) \lor AssumedExternally(o)
$$

$$
Established(o) \iff \exists e:\ Valid(e,o) \land Class(e) \in Admissible(Requirement(o)) \setminus \{External\}
$$

$AssumedExternally(o)$ holds when $Requirement(o) = External$ and a current, explicit external premise states $o$. The two are reported separately: an externally assumed proposition is **assumed**, never **established**, and a theorem that depends on it is verified **relative to** that premise (01 §3.1). For a `Hybrid` obligation, if any part is assumed externally, the whole is discharged relative to that premise.

| requirement | admissible evidence | not admissible |
|---|---|---|
| `Formal` | a machine-checked proof of the stated claim over its full quantifier; exhaustive finite checking meeting the conditions below | tests over samples; review prose; enumeration whose completeness is asserted or sampled |
| `Structural` | compiler/type-system enforcement; a gate that fails on the forbidden construct and is shown live by a falsifier that turns it red | a gate with no falsifier; a convention |
| `Executable` | tests or probes run in the build/feature lane where the property exists, with mutation evidence that they observe the clause | a lane that compiles the test to zero cases; a test of a different lane |
| `External` | a registered premise about something outside MCP-RE's implementation boundary, reviewed at its current text | anything about MCP-RE-owned behavior |
| `Hybrid` | each named part discharged by evidence admissible for that part | one part standing in for another |

**Exhaustive finite checking** is admissible `Formal` evidence only when all of the following hold:

1. the domain is mechanically established to be finite;
2. the enumerated set is mechanically established to be the complete domain;
3. the predicate checked is the proposition being claimed;
4. every element is checked;
5. the checking mechanism sits inside the declared proof/trust boundary.

If the completeness of the enumeration is only asserted or sampled, the evidence is `Executable`, not `Formal`.

The rules this enforces:

- tests do not discharge a universal formal obligation;
- an external premise never absorbs MCP-RE-owned behavior. An internal obligation found at a boundary is still internal;
- a structural gate establishes absence of a path, not correctness of the path that exists.

### 3.2 Validity

$Valid(e, o)$ means:

1. $e$ is about $o$ itself, not about a neighbouring claim, so its subject is the obligation's subject;
2. $e$ is current on the axes that apply. Review-current: the claim, premises and selection it was reviewed against are unchanged. Evidence-established: it executed successfully under the current policy and toolchain (03 §10);
3. $e$ is non-vacuous. A proof whose hypotheses are unsatisfiable, a test that ran zero cases, or a gate that measured an empty population is not evidence.

### 3.3 Property class constrains the requirement

The property class (01 §8a) does not determine the requirement, but it constrains which requirements make sense. Working guidance:

| class | usual requirement |
|---|---|
| safety | `Formal` for the model; `Hybrid` (refinement + closure) for production |
| integrity/authenticity | `Formal`, or `Hybrid` with `External` for primitives below the verified interface |
| liveness / bounded progress | `Formal` over the model given `External` timing premises for adapters; `Executable` for operating bounds |
| availability/degradation | `Formal` for the direction of failure (fails toward refusal); `Executable` for the operating envelope |
| recovery/rollback | `Formal` over the recovery relation (02 §10); `Executable` against the real store |
| concurrency/ordering | `Formal` over admissible interleavings; `Structural` for the serialization point |
| confidentiality/noninterference | relational `Formal`, or `Structural` absence of a flow path; `Executable` alone is not admissible |
| composition | `Formal` over the cross-machine invariant (§6) |

The guidance is a starting point. The requirement recorded on the obligation is what counts. Lowering it is a change to the obligation and is reviewed as one.

## 4. Logical dependency DAG and traceability graph

### 4.1 Two graphs

Let $N$ be the set of theorems, premises and obligations.

- The **logical dependency graph** $G_L = (N, E_L)$ has an edge $u \rightarrow v$ when establishing $v$ uses $u$ (`requires`, `derived_from`). $G_L$ **must be acyclic**.
- The **traceability graph** $G_T = (N \cup Artifacts, E_T)$ has edges that locate a node without being part of its argument: `implemented_by`, `refines`, `preserves`, `projects_to`, `covers_configuration`, `associated_with_transition`, `supported_by`, and `discharges_assumption` when it is historical. $G_T$ may contain cycles.

An edge's graph is determined by its use, not its name (03 §3.3).

### 4.2 Two local axes, one composed verdict

The two assurance axes are **local** to each node:

- $ReviewCurrent(v)$: the exact proposition and the semantic material reviewed for $v$ are current. The review digest covers the claim, premises, semantic sources, selected tests and proved symbols.
- $EvidenceEstablished(v)$: the current evidence for $v$'s **own** supporting units, refinement and proof surface is established. The evidence digest adds the toolchain, the policy and execution.

Neither axis propagates. A child's stale evidence does not make the parent's own evidence stale, and reporting it that way would describe the parent's evidence falsely.

The logical DAG propagates the **final verdict**:

$$
CurrentlyVerified(v) \iff ReviewCurrent(v) \land EvidenceEstablished(v) \land \forall u \in LogicalDeps(v):\ CurrentlyVerified(u)
$$

where $LogicalDeps(v) = \{u \mid (u \rightarrow v) \in E_L\}$.

A dependency change can still move $ReviewCurrent(v)$ directly, but only through $v$'s own review digest: where the dependency's claim, or other semantically relevant information about the dependency, is part of what was reviewed for $v$, changing it moves $v$'s digest.

The logical graph alone controls dependency propagation. Traceability edges do not become logical dependencies. Semantically relevant traceability and correspondence information may still be part of $v$'s own review or evidence digest: changing which implementation path refines a transition, for example, requires correspondence re-review of the theorems concerned, with no new dependency edge. Which traceability information is semantically relevant in this sense is open question Q9 (§9).

## 5. Obligation generation and closure

### 5.1 Generators

Each generator $g_k$ maps its domain to candidate obligations:

$$
g_k : Domain_k \rightarrow \mathcal{P}(Obligations)
\qquad
\mathcal{O} = \bigcup_k g_k(Domain_k)
$$

The generators are security goals, semantic machines, accepted configuration classes, trust boundaries, the authority/capability graph, the implementation/security-surface census, failure/recovery, persistence/restart/rollback, concurrency, threat derivation, and mutation/proof-coverage analysis (01 §8).

Each generator records its **coverage**: what part of its domain it enumerated, and how that was measured. A generator that enumerated an empty population, or ran over a domain that could not be measured, has not run. An empty result is evidence only if the population it was drawn from was non-empty and complete.

The outputs are **reconciled**. Duplicates are merged. An obligation found by only one generator is examined for why the others missed it. Each obligation is recorded with its property class and requirement.

### 5.2 Disposition

At closure, each obligation has a terminal disposition. Legitimate terminal dispositions include:

- **Discharged** (§3.1): **established** by proof, structure or other admissible evidence, or **assumed externally** by a current explicit premise where the obligation concerns something outside MCP-RE. The two are recorded and reported separately;
- **Superseded**, by another obligation that covers it;
- **Disproved / non-defect**, with the reason the obligation does not hold as a requirement or the reported defect does not exist;
- **Architectural constraint** that changes the declared guarantee, so that the obligation no longer applies to the guarantee as declared;
- **Excluded** from the model's declared scope, explicitly;
- **NotSecurityRelevant**, with a reviewed reason.

**Guarantee- and scope-changing dispositions are owner decisions.** `Architectural constraint` and `Excluded` are terminal only when an explicit owner-ratified decision changes the declared architecture, guarantee or scope. An implementation or evaluation agent may not grant them. Before either is terminal:

1. the authoritative guarantee, architectural constraint, threat model or declared scope is updated;
2. the owner decision and the changed text are linked from the disposition;
3. the obligation generators affected by the change are rerun (§5.1);
4. any new obligation the constraint or exclusion creates remains visible and is itself disposed.

An architectural constraint may narrow the guarantee truthfully. It may not state that an applicable obligation is accepted but unsatisfied. An exclusion removes something from the model only by explicitly changing the declared scope; it is never an unrecorded exception.

The same owner-ratification requirement applies to `NotSecurityRelevant` when it would remove a surface or property that was previously part of the declared security model.

This is what prevents these categories from becoming a renamed `accepted-risk`.

**There is no `accepted-risk` disposition.** An undischarged security obligation inside the declared MCP-RE security model cannot reach terminal closure by being accepted. An obligation that remains applicable and is not discharged remains **open**, and `Open` is not a terminal disposition.

### 5.3 Closure condition

$$
Closed
\iff
\Big(\forall k:\ Covered(g_k)\Big)
\;\land\;
\Big(\forall o \in \mathcal{O}:\ Terminal(o)\Big)
$$

where $Terminal(o)$ means one of the terminal dispositions of §5.2. Both conjuncts are required. The second without the first is the statement "nothing we looked for is missing", which says nothing about what was not looked for.

The claim remains **relative and closed-world** (01 §3). It is relative to the declared generators, the declared environment and threat model, and the declared external premises.

## 6. Cross-machine composition

### 6.1 Composition invariants

For machines $M_i$ and $M_j$ that share meaning, a composition invariant is a predicate over their joint state:

$$
I_{ij}(s_i, s_j)
$$

that must hold in every reachable global state. The reachable global states are a subset of the product $S_1 \times \dots \times S_n$, cut down by the $I_{ij}$.

Examples:

- admission accepted ⇒ identity verified;
- signing at epoch $e$ ⇒ trust epoch authorizes $e$;
- continuation live ⇒ the admission it depended on is still valid;
- signer retired ⇒ no trust state still names it as active.

### 6.2 Preservation

An invariant is preserved when every transition of every participating machine preserves it:

$$
I_{ij}(s_i, s_j)
\land
step_i(\dots, s_i, \dots) = Commit(s_i', \_)
\Rightarrow
I_{ij}(s_i', s_j)
$$

and symmetrically for $M_j$. This must hold under every interleaving of events across the two machines that the environment model admits.

Individually correct machines do not compose correctly by default. The preservation obligations are separate obligations, generated from the declared $I_{ij}$ (03 §6, item 11).

### 6.3 Ordering contracts

Some cross-machine requirements are not predicates over one state but constraints on order: retire the signer before publishing the trust change, or the reverse, or atomically. These are stated as composition obligations over event sequences.

Where machines run on several replicas, the model carries both the authoritative state and each replica's observed state, and does not assume they are equal (02 §12.1). The relation between them, for example $AllowedView(S^{view}_r, S^{auth}, C, t)$, is part of the model, and that each view satisfies it is an obligation. The exact relation and its representation are open question Q5 (§9).

## 7. Semantic configuration classes

$$
SecuritySemantics : RawConfig \rightarrow ValidatedSecurityConfig \cup \{Refused\}
\qquad
c_1 \sim c_2 \iff SecuritySemantics(c_1) = SecuritySemantics(c_2)
$$

The accepted classes are $AcceptedClasses = \{[c] \mid SecuritySemantics(c) \neq Refused\}$.

Obligations generated here:

- **normalization soundness**: inputs that should mean the same thing normalize to the same class, and inputs that mean different things do not;
- **refusal correctness**: every raw configuration that must not run is refused, with no partial acceptance;
- **initial invariant**: $\forall [c] \in AcceptedClasses:\ Invariant(InitialState([c]))$;
- **class coverage**: every Layer-4 theorem quantifies over all accepted classes, or over a symbolic constraint whose meaning is a set of classes, and says which.

Coverage is over classes, not over syntactic permutations of CLI, Helm and environment inputs. Enumerating a small finite class space is a legitimate proof method. Enumerating input spellings is not coverage.

## 8. When a machine is migrated

Having a model and having proofs is not enough. A semantic machine counts as **migrated** when all of the following hold:

1. its security purpose is stated;
2. its semantic machine is defined: $C$, $S$, $E$, $A$, $O$, transitions, failure, recovery, rollback and concurrency, and observations where confidentiality applies;
3. the production implementation mapping is complete;
4. there are zero unclassified security-relevant production sites;
5. every generated obligation has a terminal disposition (§5.2), and every discharged obligation is discharged by evidence admissible for its requirement, with externally assumed obligations reported as assumed;
6. every implementation mismatch is resolved, or the model is explicitly amended with a reason;
7. the refinement obligation (§2.2) is established for every mapped transition; a mapping without refinement does not count;
8. structural bypass closure is in place, and each closure gate is shown live by a falsifier;
9. the relevant configuration classes are covered (§7);
10. failure, recovery, rollback and concurrency are addressed by obligations, not only by tests of the happy path;
11. every required composition obligation with neighbouring machines is established (§6);
12. every theorem in the machine is $CurrentlyVerified$ (§4.2).

A machine that meets items 1–10 and 12 for its own obligations while a required composition obligation (item 11) is still open is **LOCALLY_MIGRATED / COMPOSITION_OPEN**. That is a descriptive state, not migration. The open composition work may belong to the neighbouring machine, but the unresolved theorem still prevents either machine from being called **MIGRATED**. That name is reserved for a machine whose required composition contracts are established.

Migration is a state that can be lost. A change that moves a digest or adds an unmapped site returns the machine to non-migrated until it is re-established.

## 9. Open questions for the pilot

These are points where the model cannot be made precise without either a decision or contact with real code. The delegated-signing / trust-epoch pilot is expected to answer them, or to show that the question was wrong.

- **Q1 — Determinism.** Can every transition in delegated signing and trust epoch be expressed as a deterministic `step` with all observations in $E$? If one cannot, which one, and why?
- **Q2 — Pending-effect representation.** Decided: a security-relevant outstanding effect is semantic state (02 §2.1). Open: its exact representation (inside $S'$ or as `Pending` alongside it), and how the pilot's effects express correlation, duplicate and stale completion, timeout and cancellation, retry, restart while pending, and authority change while pending.
- **Q3 — Abstraction.** What is $\alpha$ for real Rust state that spans memory, Redis and KMS? Where does the representation invariant $RI$ live, and can it be established at the type level?
- **Q4 — Refinement method.** Can the pure-decision / adapter split (02 §8) be achieved without distorting the code, so that refinement is provable over the decision core? Where it cannot, what is the honest `Hybrid` decomposition?
- **Q5 — Replica relation.** Decided: both authoritative and per-replica observed state are modelled, without assuming equality (02 §12.1). Open: the exact $AllowedView$ relation (bounded staleness, currentness, or another form), its representation, and which invariants are stated over views and which over the authoritative state.
- **Q6 — Existing registry.** How do the existing THM/ASM entries map to generated obligations? Which theorems correspond to no generated obligation? Which generated obligations have no theorem? Which premises are really MCP-RE-owned behavior?
- **Q7 — Requirements.** Is the five-valued requirement set enough, or does the pilot need more structure, for example distinguishing proof over the model from proof over code?
- **Q8 — Generator coverage.** How is coverage measured for each generator over a real subsystem? What is the unit of the implementation-surface census?
- **Q9 — Graph split.** Which existing registry relations are logical and which are traceability? Does any existing invalidation rule propagate along an edge that §4 classifies as traceability? Which traceability and correspondence information is semantically relevant, and so belongs in a theorem's fingerprint?
- **Q10 — Configuration classes.** What is $SecuritySemantics$ for the pilot's configuration surface, and how many accepted classes are there?
- **Q11 — Existing machinery.** Which remediation-era structures (04 §11.1) already correspond to model elements, and which would need rewriting?
- **Q12 — Model fitness.** Where did the working model have to be amended, and does any amendment generalize beyond the pilot?
