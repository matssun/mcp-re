<!-- SPDX-License-Identifier: Apache-2.0 -->
# Grill transcript — MCP-RE next PRD (Claude ↔ Codex)
Session 2026-07-15. Griller: Claude. Answerer: `codex-cli 0.142.2` (read-only sandbox), primed
with `.claude/skills/pp-grill-me/stance-profile.md` + accumulating settled decisions.
Judge: general-purpose agent, same profile as sole rubric.

Skim-able record: each question is the griller's framing (recommendation + codebase evidence);
each answer is Codex standing in for Mats. **Authoritative outcomes are in**
[`mcp-re-next-grill-decisions.md`](mcp-re-next-grill-decisions.md) — where Mats overrode Codex,
the decisions file wins.

---

## A1 — Branch A — one PRD vs two

### Question (griller)

```text
QUESTION (Branch A — Frame & scope, Q1):

The proposed new PRD covers five workstreams: (1) regenerate the evidence spine (claim matrix, security boundary, threat coverage, traceability) for the current RFC 9421 architecture; (2) root-authority production lifecycle (governed rotate-root controller, break-glass revocation, manifest distribution, GKE fleet lane); (3) production residuals (fix the 2/590 GKE rolling-update drop, AWS KMS live proof, land uncommitted MRT work); (4) an EMA authorization-artifact binding profile (bind the EMA-issued access token + its sender constraint into the RFC 9421 signed request, with a hermetic IdP→ID-JAG→AS→token→client-proxy→server-proxy conformance lane); (5) ecosystem readiness (standalone conformance-vector package, independent non-Rust verifier, fuzzing, MCP community proposal, SEP-3004 composition posture).

Is that ONE PRD covering all five workstreams, or should it split into TWO PRDs — e.g. "production completion" (workstreams 1-3) and "authorization-evidence interoperability + ecosystem" (workstreams 4-5) — each landing its own release?

My recommendation: ONE PRD. Reasoning: the five workstreams share a single thesis — "MCP-RE's next chapter is completing the production authority story and composing with stable enterprise authorization" — and they interlock (the EMA profile's claims can't be published without the regenerated evidence spine; the spine can't document a finished state until the residuals close). Two PRDs would force an artificial ordering barrier between things that are one coherent argument, and #148 itself proved a broad PRD works (it carried 6 ADRs and 9 slices). Counter-argument to weigh: five workstreams is a lot of surface for one PRD, EMA is genuinely new capability while 1-3 are completion work, and a PRD that spans two releases can't have one clean success metric.

Answer decisively: one PRD or two, and why.
```

### Answer (Codex)

One PRD: v0.13 is the coherent unit.

The thesis is not “finish some production chores, then maybe do EMA”; it is “MCP-RE is production-authority complete and can bind stable enterprise authorization without interpreting it.” Splitting this would create a fake boundary: the EMA binding profile cannot be claimed without the regenerated evidence spine and `security_traceability_manifest.json`, and the spine is dishonest until `docs/PROJECT_STATUS.md`, root lifecycle, rolling-update loss, AWS KMS proof, and MRT are brought current. EMA is new capability, yes, but it is not a separate product direction; it is the first serious proof that `artifact_bindings[]` and BIND, DON’T INTERPRET survive contact with the real MCP authorization stack.

The success metric stays clean: v0.13 ships when all five workstreams are green, machine-checked, and claimable. If that is too much surface, the answer is tighter slice discipline inside the PRD, not splitting one architectural argument into two releases.

---

## A3 — Branch A — evidence-spine ordering / unbacked claims

### Question (griller)

```text
QUESTION (Branch A — Frame & scope, Q3):

Assume ONE PRD covering all five workstreams (settled in Q1).

The evidence spine (claim matrix + security boundary + threat-coverage matrix + traceability manifest, all currently STALE — scoped to the deleted draft-01 object envelope) has to be regenerated for the current RFC 9421 HTTP-profile architecture. WHEN in the PRD does that happen?

Option A — "Claims first, gate": the regenerated claim matrix is written EARLY and is a GATE for the PRD itself. Every workstream then must land its claims into an already-correct spine. The matrix states the target claims up front (including EMA binding claims that aren't built yet), marked as unbacked until their named test goes green.

Option B — "Closing artifact per workstream": each workstream regenerates its own slice of the spine as it completes, so the spine always documents a finished state and never contains an unbacked claim. The full refreshed matrix exists only when the last workstream lands.

Option C — split: the immediate HONESTY fixes (docs/PROJECT_STATUS.md still says "Current release: v0.10.1" and still claims a "zero-drop rolling update" that the v0.12.1 changelog contradicts with a 2-of-590 drop) happen NOW, at the very front, decoupled from the structural regeneration, which then follows Option A or B.

My recommendation: Option C's honesty fixes first (immediately — an over-claim sitting in a current-facing doc is a live defect, not a planning item), then Option A for the structure — the claim matrix is written early as the PRD's contract, with every not-yet-backed claim explicitly marked unbacked and CI-blocked from publication until its named test is green. Reasoning: the project's discipline is "no test, no claim", and the honest way to run that discipline is for the claim to exist as a WRITTEN TARGET that CI refuses to let you publish until the evidence lands — that makes the matrix drive the work rather than describe it afterwards. Option B risks the spine being perpetually behind and gives no single contract to build against.

Counter-argument to weigh: a claim matrix containing unbacked claims is exactly the "over-claiming" failure mode #148 was built to prevent; if the matrix is the reviewer-facing artifact, an unbacked row in it is dangerous even if marked. Maybe the target claims belong in the PRD (which is a plan) and the matrix (which is evidence) only ever gets a row when the test is green.

Answer decisively: which option, and specifically — can a claim exist in the claim matrix before its test is green, marked unbacked, or never?
```

### Answer (Codex)

Option C first, then Option A. The stale `docs/PROJECT_STATUS.md` over-claim is a live defect: fix the release number and the false zero-drop statement immediately, before PRD planning gets another sentence.

Then the regenerated claim matrix becomes the PRD contract early, not a closing scrapbook. A claim may exist in that matrix before its test is green only if it is explicitly marked `unbacked`, mapped to a named required test in `security_traceability_manifest.json`, and mechanically blocked from any published/release claim surface until green plus owner sign-off. That is not over-claiming; over-claiming is presenting it as satisfied. The matrix must drive the work, because if EMA binding, root-authority lifecycle, residual closure, and ecosystem readiness do not land into one spine from day one, the evidence architecture will drift again.

---

## B1 — Branch B — the rolling-update drop

### Question (griller)

```text
QUESTION (Branch B — Production residuals, Q1): the rolling-update drop.

CODEBASE EVIDENCE (verified, cite these):
- `deploy/helm/mcp-re-proxy/values.yaml:150` ALREADY has `drainPreStopSeconds: 6`, and its comment says it exists precisely to "close the L4 LoadBalancer endpoint-propagation race that can drop a single new connection at the instant a rolling update terminates a replica."
- `deploy/helm/mcp-re-proxy/templates/deployment.yaml:167-177` implements it as `lifecycle.preStop.exec.command: ["sleep", "6"]`, with the comment "Without this, a new connection can reach a pod in the ~1s between SIGTERM and its removal from the LB."
- `drainGracePeriodSeconds: 30` → `terminationGracePeriodSeconds`. The proxy's own bounded graceful drain (MCPRE-115, `async_serve.rs:231-239`) is correct and green in-process: accept loop stops, in-flight finish, bounded by `drain_grace >= request_deadline`.
- readinessProbe is `tcpSocket` on the bind port, `periodSeconds: 5`.
- The GKE cluster is provisioned by `docs/security/gke-multi-replica-validation.sh` as a **Standard, zonal e2-standard-2 x2** cluster, and the proof runs over a **real L4 LoadBalancer** Service.
- v0.12.1 CHANGELOG "Known issues": the rollout dropped **2 of 590** in-flight requests; in-process and kind lanes pass; "Likely resolved by a longer `drainPreStopSeconds`."

So the mechanism the changelog proposes as the fix ALREADY EXISTS and is already enabled at 6s. The proposed "fix" is bumping a number on an existing knob.

THE PROBLEM WITH THAT: an L4 Service LoadBalancer on GKE routes via kube-proxy/iptables. Endpoint removal must propagate to every node's kube-proxy before no new connections arrive. That propagation has no bounded upper latency — it is a race with an unbounded tail. No finite `sleep` value makes the drop probability zero; it only makes it smaller. A test that goes green at `sleep 20` has not proven zero-drop; it has proven the race did not fire in that run. That looks like exactly the kind of self-asserted pass S8/S15 forbid, and exactly the band-aid-vs-real-cause line S5 draws.

THREE CANDIDATE ANSWERS:

(1) **Bump the number.** Raise `drainPreStopSeconds` 6 → ~20-30, re-run Proof 4, call it green. Cheap. But the property is still probabilistic; the green is a sample, not a proof.

(2) **Architectural fix — remove the race.** Move off kube-proxy L4 to GKE **container-native load balancing (NEG-backed)** with a `BackendConfig` connection-draining timeout. The LB then addresses pod IPs directly and honours endpoint removal before termination, so the propagation race is eliminated by construction rather than out-waited. Costs: changes the declared deployment topology of the proof (and the Helm/Service surface), GKE-specific mechanism, more infra to stand up and validate live.

(3) **Narrow the claim honestly (the S14/int53 move).** Accept that "zero-drop rolling update" is not achievable-by-construction over an arbitrary L4 LB, and make it a **declared-tier claim** — exactly like the existing fleet posture, where the multi-node replay claim holds ONLY for a deployment that declares the shared quorum-durable tier and `--fleet` fails closed on a node-local cache (ADR-MCPS-049; security-boundary §8; the four-axis §B deployment-tier matrix). So: zero-drop is claimed only under a declared LB/drain tier, with the untiered case documented as a known, tested limitation.

Note the precedent that governs here: the v0.6 int53 ruling — the STRICTEST deterministic domain plus an honest, documented, TESTED limitation BEAT widening the highest-risk surface. And note this project already expresses exactly this shape as a tiered claim (§B), not as a flat one.

Also consider a real interaction: MCP-RE is replay-protected with per-request nonces. A dropped in-flight request cannot simply be retried by the client with the same nonce — it would be rejected as a replay. So "the client retries" is NOT an available mitigation the way it is for ordinary HTTP. Say whether that changes your answer.

Answer decisively: which of (1)/(2)/(3), or a specific combination, and state exactly what the claim wording becomes and what test makes it green. Is this a release blocker for the PRD?
```

### Answer (Codex)

I pick **(2) plus (3)**: build the NEG-backed declared LB/drain tier, and make zero-drop a tiered claim only for that tier. We do **not** bump `drainPreStopSeconds`; the knob already exists at `deploy/helm/mcp-re-proxy/values.yaml:150` and is wired at `deploy/helm/mcp-re-proxy/templates/deployment.yaml:167-177`, so increasing it is just sampling the unbounded kube-proxy propagation race harder, not proving the property.

Claim wording becomes: **“MCP-RE supports zero-drop rolling updates only for deployments declaring the NEG-backed GKE container-native load-balancing drain tier, with BackendConfig connection draining enabled and live-validated; ordinary kube-proxy L4 LoadBalancer deployments are a documented tested limitation and do not carry the zero-drop claim.”** The green test is a live GKE black-box rolling-update proof over that declared tier: assert every accepted request completes with no missing responses, 5xx, or timeouts, while independently verifying the Service is NEG-backed and the BackendConfig drain policy is actually attached; the old L4 proof remains as the negative/limitation lane.

The nonce replay interaction makes this stricter, not softer: a dropped in-flight signed request cannot be hand-waved as “client retries,” because replay protection correctly rejects nonce reuse. Yes, this is a release blocker for this PRD until the flat zero-drop claim is removed, the tiered claim is implemented and green, and `docs/PROJECT_STATUS.md` stops repeating the stale v0.11 zero-drop statement.

---

## B2 — Branch B — AWS KMS live proof

### Question (griller)

```text
QUESTION (Branch B — Production residuals, Q2): AWS KMS live proof — in scope or explicitly parked?

FACTS:
- ADR-MCPS-028 shipped NATIVE cloud-KMS response signers for BOTH AWS KMS and GCP Cloud KMS (Ed25519, non-exporting). The AWS adapter is written and merged.
- GCP Cloud KMS is LIVE-PROVEN: real `asymmetricSign`, fail-closed negative lanes, a one-command reproduction harness (`docs/security/gcloud-kms-validation.sh`), and now a live GKE run with KMS custody via Workload Identity.
- AWS KMS is **shipped but NOT live-proven**. `docs/PROJECT_STATUS.md` therefore lists as an explicit NON-CLAIM: "broad multi-cloud live validation: GCP Cloud KMS is live-proven; the AWS KMS adapter is shipped but **not** yet live-proven, so multi-cloud custody is not claimed until AWS is also live-proven."
- So today there is shipped, merged, untested-against-reality code on a security-critical custody path. It has unit/mock coverage but has never signed against a real AWS KMS key.
- Cost to close: an AWS account, a KMS key, a fenced live lane mirroring the GCP one (`gcloud-kms-validation.sh` is the template), and CI wiring. Mats is a solo developer paying his own cloud bills.

THE TENSION:
- S15 says security/crypto/wire-interop code is golden-vector-gated and must be cross-verified against an independent authoritative implementation — never trust a self-asserted pass. A KMS signer that has never signed against the real KMS is precisely a self-asserted pass.
- S7 says nothing is dismissed as "pre-existing" — this code is in the tree, so its untested state is a live defect, not someone else's problem.
- S1/S3 say do it now, don't defer.
- BUT S10 is the brake: aggressive within scope, conservative about scope creep. AWS live-proving is arguably a different cloud's infra project, not part of "enterprise authorization binding and production authority completion."
- AND the non-claim is currently HONEST — the project correctly refuses to claim multi-cloud custody. Nothing is over-claimed today. So this is not an honesty defect the way PROJECT_STATUS.md's stale zero-drop claim is.

THREE OPTIONS:
(1) **In scope**: build the fenced AWS live lane in this PRD, live-prove it, and upgrade the claim to multi-cloud custody.
(2) **Explicitly parked with a named trigger**: keep the honest non-claim; record a concrete trigger (e.g. "the first adopter/sponsor who needs AWS custody", or "when an AWS account is funded") and an owner. Do NOT let it drift as an unowned maybe.
(3) **Delete the AWS adapter** from the tree. Zero-technical-debt reading of S4: unproven, unclaimed, unexercised code on a security-critical custody path is dead weight that invites a false sense of multi-cloud support. If it isn't live-proven it doesn't ship — and if it isn't going to be live-proven this cycle, it shouldn't sit in the tree pretending.

Note option (3) is the aggressive-and-strict reading and has direct precedent in this project: stdio was DELETED rather than kept as "legacy compat"; direct-root response signing was DELETED from the runtime surface rather than kept as a fallback; the JCS/object carrier was DELETED rather than kept as an alternative. This project's pattern is: an unblessed path is removed, not retained.

Answer decisively: (1), (2), or (3), and if (2) name the concrete trigger and owner. Address whether the stdio/direct-root/JCS deletion precedent actually applies to the AWS adapter or is disanalogous.
```

### Answer (Codex)

(3) Delete the AWS adapter from the tree.

`docs/PROJECT_STATUS.md` is honest today, but honesty is not enough: merged security-critical custody code that has never exercised real AWS KMS is still an unproven runtime path. If we are not funding and wiring the fenced AWS live lane in this PRD, then the correct move is removal, not a parked maybe. The deletion precedent applies: stdio, direct-root signing, and the JCS/object carrier were removed because unblessed paths create false architectural surface area; an unproven KMS custody backend has the same failure mode on a security boundary. GCP stays because it has real `asymmetricSign`, negative lanes, and the reproducible harness in `docs/security/gcloud-kms-validation.sh`; AWS comes back only as a coherent PR with live AWS KMS proof, negative lanes, CI wiring, and claim-matrix evidence. Multi-cloud custody remains a non-claim until that PR exists.

---

## C1 — Branch C — ADR structure (run hung; unanswered)

### Question (griller)

```text
QUESTION (Branch C — Root-authority production lifecycle, Q1): ADR structure.

The root-authority verifier machinery (§H TrustedIssuerSet, §I signed TrustAnchorManifest) was built UNDER ADR-MCPRE-052, which is titled "Delegated Signing-Key Attestation — a JOSE/JWS Delegation Credential Carried in the RFC 9421 HTTP Evidence" and is status:implemented. The remaining work is the governed production controller (`mcp-re-admin rotate-root`), break-glass revocation governance, manifest distribution to a live fleet, and a GKE fleet-scale rotation lane.

Where does that decision live?

(1) **New ADR-MCPRE-053: Root Authority Lifecycle and Trust-Anchor Transition.** ADR-052 is about the delegated-signing MECHANISM (how a short-TTL key is attested on the hot path). Root-authority lifecycle is a different decision class: it is about AUTHORITY CHANGE and its governance — rare, high-consequence, off the hot path, and with a fundamentally different threat model (a compromised trust anchor invalidates every descendant at once). Two different decisions should be separately ratifiable and separately supersedable. ADR-052 is already implemented and ratified; re-opening an implemented ADR to bolt on a new decision muddies both its status and its record.
(2) **Extend ADR-052 §H/§I.** The trust-anchor set and manifest were ALREADY specified as §H/§I of ADR-052, so the lifecycle is a continuation of a decision already made there, and splitting it invents a boundary the code doesn't have (`TrustedIssuerSet` and `TrustAnchorManifest` live in `mcp-re-client-core`, the same crate the delegation verifier uses). One ADR, amended.

Note the countervailing evidence for (2): the §H/§I sections ALREADY live inside ADR-052, so the "different decision class" argument is weakened by the project's own filing choice — someone already decided root-authority trust material belonged in the delegated-signing ADR.
Note the countervailing evidence for (1): ADR-052 is status:implemented. This project's ADRs record decisions, and an implemented ADR that keeps growing new unimplemented sections is a status lie — it would be simultaneously "implemented" and "not implemented".

Answer decisively: (1) or (2). If (1), state precisely what ADR-053 decides that ADR-052 does not, and whether ADR-052 §H/§I get superseded/moved or stay where they are (and if they stay, how a reader knows which ADR governs the trust anchor).
```

### Answer (Codex)

_(no answer — run hung on stdin and was killed; question carried to Mats directly)_

---

## C2 — Branch C — governance for a solo operator

### Question (griller)

```text
QUESTION (Branch C — Root-authority production lifecycle, Q2): the governance control point, for a SOLO operator.

VERIFIED STATE (docs/spec/root-authority-rotation.md):
- BUILT: `TrustedIssuerSet` (current / retiring-with-valid_until / revoked / unknown, fail-closed) and the signed, versioned `TrustAnchorManifest` (signed by a pinned ORG/ADMIN manifest key — a higher authority than the issuer roots it lists, so an ordinary serving proxy cannot mint a new root authority; rejects untrusted signer, bad signature, expired manifest, and rollback below the highest accepted version). Live cross-KMS rotation ran GREEN against real Cloud KMS with fenced disposable roots.
- DESIGN ONLY: the production governed controller `mcp-re-admin rotate-root --provider gcp-kms --keyring <ring> --old-issuer-kid root-a --new-issuer-kid root-b --overlap 24h`, plus this governance list, quoted verbatim from the doc:
    - scheduled rotation → one explicit admin command / CI release approval;
    - emergency compromise → break-glass command that immediately publishes a manifest with the old issuer `revoked`, **optionally two-person approval**;
    - every rotation is audited (who, when, old→new, overlap);
    - the manifest signer (org/admin key) is itself high-value custody — offline root, threshold/admin approval, or a dedicated KMS key.

THE HONESTY PROBLEM: MCP-RE is a SOLO-OPERATOR project. "Two-person approval" and "who, when" audit attribution are governance controls that presuppose an organization with more than one person. Building a two-person-approval mechanism that one person satisfies by approving twice is security theater — it produces an audit trail that LOOKS like dual control and isn't. That is precisely the "attested-in-the-abstract" failure mode this project rejects elsewhere, and it collides with S8 (anti-gameable evidence, never trust a self-asserted OK).

But the opposite failure is just as real: shipping a root-rotation controller with NO governance because "I'm the only one here" produces a design that cannot be adopted by an actual enterprise, which is the stated target user.

THE QUESTION: what does the governed controller actually implement, and what does it merely document?

(1) **Mechanism, not staffing** — implement the CONTROL POINTS as real, testable mechanism (an explicit admin command that is the ONLY path to publish a manifest; a distinct break-glass subcommand; a mandatory audit record per rotation; a required approver identity that must be supplied and is bound into the audit record), and treat "how many humans must approve" as DEPLOYMENT POLICY the mechanism enforces but does not staff. A solo deployment configures approvers=1 and the mechanism honestly records one approver; an enterprise configures 2+ and the mechanism refuses to proceed without two distinct approver identities. The mechanism is real and tested at both settings; the staffing is the deployer's.
(2) **Build only what a solo operator actually exercises** — the admin command + audit record; declare multi-party approval explicitly out of scope with a named trigger (first enterprise adopter), because building an approval-quorum feature nobody exercises is unproven code on the highest-authority path — the exact class of thing that just got argued about with the AWS adapter.
(3) **Full governance now** — implement two-person approval as a hard requirement for break-glass regardless, on the grounds that trust-anchor revocation is the single highest-authority action in the system.

Note the precedent the project ALREADY set for exactly this shape: client key custody (ADR-MCPS-044) mandates **"properties not products"** — the ADR specifies required PROPERTIES (signer identified in evidence, bound to route/audience, non-exportable where supported, production must not use unprotected file keys) and explicitly refuses to mandate a mechanism, with hardware/KMS-only as an opt-in HARDENING PROFILE rather than the base rule. Consider whether root-authority governance should follow that same properties-not-products pattern, and if so say exactly which properties are mandatory vs which form a hardening profile.

Also answer: is the approver identity bound INTO the signed manifest itself (so the authorization for a trust-anchor change is historically verifiable years later, per S16), or only into a side audit log (which is not signed evidence and can be lost)?

Answer decisively.
```

### Answer (Codex)

I’d implement **(1): mechanism, not staffing**. The governed controller owns the control points: `mcp-re-admin rotate-root` is the only production manifest-publish path, break-glass is a distinct command, every rotation emits a mandatory audit record, and approval quorum is enforced from deployment policy. Solo MCP-RE configures `approvers=1` and records exactly one approver; enterprise deployments configure `2+`, and the controller rejects duplicate identities and insufficient quorum.

This follows the ADR-MCPS-044 “properties not products” precedent: mandatory properties are explicit authority change, enforced quorum, distinct approver identities, immutable rotation facts, rollback protection, expiry/fail-closed behavior, and machine-checked negative tests. The hardening profile is `approvers>=2`, threshold/offline or dedicated-KMS manifest signing, and external append-only audit retention. I will not hard-require two-person approval in the base solo profile, because fake dual control is worse than honest single control.

The approver identity is bound into the **signed `TrustAnchorManifest` itself**, not only a side audit log. The manifest must carry the governance policy id, quorum, approver identities, approval evidence, manifest version, and canonicalization id, so years later the trust-anchor transition is historically verifiable from the signed record itself; the audit log is secondary operational evidence, not the source of authority.

---

## C3 — Branch C — manifest distribution + propagation bound

### Question (griller)

```text
QUESTION (Branch C — Root-authority production lifecycle, Q3): manifest distribution and its propagation bound.

VERIFIED STATE:
- The verifier already consumes a `SignedTrustAnchorManifest` (`mcp-re-client-core/src/trust_manifest.rs`): `load_signed_manifest` rejects an untrusted signer, a bad signature, an EXPIRED manifest (fail closed), and a ROLLBACK to a version below the highest already accepted; on success it yields a `TrustedIssuerSet`.
- `docs/spec/root-authority-rotation.md` says distribution "starts as a **static file / config channel** and can later move to a **signed remote feed / resolver** without changing the verifier — it already consumes a `SignedTrustAnchorManifest`."
- The fleet runs as N identical replicas on GKE behind a load balancer.
- PRECEDENT — the project ALREADY solved the analogous cross-replica trust problem for DELEGATED keys: ADR-MCPS-021 defines a **bounded trust-propagation window** with explicit per-tier revocation-lag bounds; a Redis-backed **trust-epoch source** flushes the Push-tier trust cache across replicas on an epoch advance, and reverts to the bounded-staleness guarantee on a read outage. An e2e proves a revocation reaches a sibling replica, with a negative control (MCPS-84/85/86).

THE QUESTION: how is the signed `TrustAnchorManifest` distributed to a live GKE fleet, and what is the propagation bound?

(1) **Static file / ConfigMap mount** — the manifest is a mounted file; a rotation means a ConfigMap update and a rolling restart (or a kubelet-driven file refresh, which is itself eventually-consistent with an unbounded-ish tail ~60-90s). Simple, no new infra. But: a BREAK-GLASS REVOCATION — the single most time-critical action in the system — would then be bounded by a Kubernetes config-propagation delay or a full rolling restart, which is exactly the wrong latency profile for "the old root is compromised, revoke it NOW". And a rolling restart to revoke a compromised trust anchor interacts badly with the rolling-update drop just discussed in Branch B.
(2) **Reuse the ADR-021 trust-epoch/Redis channel** — distribute the manifest (or an epoch advance pointing at it) through the SAME shared-tier mechanism already proven to propagate delegated-key revocation across replicas, inheriting its bounded-staleness guarantee, its fail-closed-on-outage behavior, its per-tier lag bounds, and its existing cross-replica e2e + negative control. One trust-propagation mechanism for both key layers instead of two.
(3) **Signed remote feed / resolver** — build the resolver endpoint now.

Consider carefully: the manifest is SIGNED by the org/admin key and is rollback-protected and expiry-fail-closed AT THE VERIFIER. That means the distribution channel is UNTRUSTED BY CONSTRUCTION — Redis cannot forge a manifest, cannot roll it back below the highest accepted version, and cannot extend its expiry. So using the existing shared tier as the transport costs nothing in trust while inheriting a proven, bounded, fail-closed propagation path. Say whether that reasoning holds or whether it misses something.

Also answer precisely:
- What is the DECLARED propagation bound for a break-glass root revocation, and which existing §B axis (if any) does root-manifest propagation belong to — is it Axis 2 (trust propagation), or is a trust-ANCHOR change a different property from delegated-key revocation and therefore its own thing? (Note: Branch B just established that inventing a new §B axis for a property that isn't one of the four security dimensions is forbidden — but trust propagation IS Axis 2, so this may legitimately BE Axis 2. Decide.)
- What happens to in-flight requests signed under a root that gets revoked mid-flight?
- Does the manifest's `expires_at` create an availability failure mode — i.e. if an operator forgets to re-publish, the whole fleet fails closed on a valid, uncompromised root? Is that correct behavior or a footgun, and what's the mitigation?

Answer decisively.
```

### Answer (Codex)

We use option 2: reuse the ADR-021 Redis trust-epoch channel for `SignedTrustAnchorManifest` distribution; Redis is only an untrusted transport because the verifier already pins the org/admin signer, rejects bad signatures, wrong profile, expiry, and rollback in [trust_manifest.rs](/Users/mats/dev/mcp-re/mcp-re-client-core/src/trust_manifest.rs:144), and the rotation doc already defines the manifest as the signed versioned authority set in [root-authority-rotation.md](/Users/mats/dev/mcp-re/docs/spec/root-authority-rotation.md:29). Static ConfigMap distribution is wrong for break-glass, and a new remote resolver is unnecessary architecture until we have a reason the proven trust-epoch path cannot carry this state.

The declared production bound is ADR-021 `PUSH` with `T=60s`: push should invalidate immediately, but the claim is “fleet-wide within 60s,” never zero-window; this is §B Axis 2 trust propagation, because root-manifest propagation is still revocation/trust propagation, just at the trust-anchor layer, and [v0.5-claim-matrix.md](/Users/mats/dev/mcp-re/docs/spec/v0.5-claim-matrix.md:68) already owns that dimension. In-flight requests are judged at verification time: if the request has not passed verification when the revoked-root manifest is accepted, it fails closed; if it already passed verification and was dispatched, MCP-RE does not pretend to retroactively unsend it, and the exposure is the declared Axis 2 window plus normal request deadline. `expires_at` failing the fleet closed is correct, not a footgun: stale trust material is worse than an outage. The mitigation is operational, not a verifier fallback: the governed controller republishes well before expiry, CI/monitoring pages before the renewal window closes, and failure to republish is treated as an authority lifecycle incident.

---

## D1 — Branch D — the owner-signed security boundary

### Question (griller)

```text
QUESTION (Branch D — Evidence spine, Q1): what happens to the owner-signed security boundary?

VERIFIED STATE (`docs/spec/security-boundary.md`, first lines):
- "**Status: SIGNED OFF by the owner — Mats Sundvall, 2026-05-30** (release gate satisfied for the single-node profile). See Section 7."
- "**v0.5 proposal-readiness: SIGNED OFF by the owner — Mats Sundvall, 2026-06-23** (mechanical gate #156 green; no wire-envelope change, draft-01 frozen). See Section 10."
- And then, bolted on top, a profile-status note: "The object-signature guarantees described below are those of the MCP-RE **native / object profile** (Ed25519-over-JCS, `_meta` envelope), which is **DEPRECATED** — not a security mechanism, not an alternative carrier, not a fallback. The one live security carrier is the RFC 9421 + RFC 9530 HTTP profile."

So: the project's single canonical honesty gate is a document whose owner sign-off attests to the guarantees of a carrier that **has since been deleted**. The signature is real; the thing it signed is gone. Note also that ADR-MCPS-032 made this doc THE single canonical boundary (`docs/SECURITY_BOUNDARY.md` is a redirect stub), and ADR-MCPS-036 makes owner sign-off half the dual readiness gate — so this document is load-bearing, not decorative.

THREE OPTIONS:

(1) **New document, new sign-off; archive the old one.** A sign-off is a DATED ATTESTATION about a specific system state. You cannot retroactively change what was signed without destroying the meaning of the signature. So `security-boundary.md` as signed on 2026-05-30/2026-06-23 is a historical record of an attestation that was true then — it moves to `docs/archive/` intact, and the HTTP profile gets a NEW boundary document requiring a NEW dated owner sign-off. Precedent: this is exactly how PRD #148 is being treated (closed as historical, not rewritten), and how the JCS-era material was already handled (`docs/archive/` + git tag `pre-adr-mcpre-050-jcs`).

(2) **Amend in place with a supersession chain.** Keep one canonical file, append new sections for the HTTP profile, mark the object-profile sections superseded, re-sign. One doc, one path, no redirect maze — and ADR-MCPS-032's whole point was ONE canonical boundary doc, so spawning a second one may violate that ADR.

(3) **Rewrite in place and re-sign.** Cleanest read, but it silently destroys the record of what was attested and when.

Consider carefully: does option (1) actually violate ADR-MCPS-032 (one canonical boundary), or does it satisfy it — since after the move there would still be exactly ONE canonical boundary doc (the new one), with the old one being ARCHIVE, not a competing claim? Is an archived, superseded, dated attestation a "competing boundary document" or simply history?

Also answer:
- Is the 2026-05-30 sign-off still meaningful for anything, or is it void the moment the carrier it describes is deleted?
- Does the new boundary document need a NEW owner sign-off before the PRD can ship, and is that sign-off a gate on the PRD or on each workstream? (Recall the settled Branch A rule: the spine regenerates per-workstream as each lands green.)
- ADR-MCPS-036 forbids self-approval. What does "no self-approval" even mean for a solo project, and is the honest answer here the same shape as the Branch C ruling on fake dual control?

Answer decisively.
```

### Answer (Codex)

Pick **(1): new document, new sign-off; archive the old one intact**.

A dated owner sign-off is evidence about the system state it attested to, so `docs/spec/security-boundary.md` signed on 2026-05-30 and 2026-06-23 remains meaningful as historical evidence for the single-node / v0.5 object-profile state, but it is no longer valid current boundary evidence after the native object carrier was deleted. Archiving it under `docs/archive/` does not violate ADR-MCPS-032; archive is history, not a competing canonical boundary. The new live canonical boundary stays at the canonical path and describes the HTTP-only `mcp-re-http-v1` architecture.

The new boundary needs a new dated owner sign-off before this PRD ships. More precisely: sign-off gates each workstream’s promotion into the regenerated evidence spine, and the PRD cannot ship until all five workstreams have green mechanical evidence plus owner sign-off where the boundary claim changed.

For solo ownership, “no self-approval” means Claude/Codex cannot implement and then approve its own work. Mats signs as accountable owner, honestly as quorum=1, backed by machine-checked evidence; pretending there is independent dual control would be worse than stating the real control model.

---

## D3 — Branch D — forbidden-claim guard coverage hole

### Question (griller)

```text
QUESTION (Branch D — Evidence spine, Q3): the forbidden-claim guard has a coverage hole.

VERIFIED STATE (`mcp-re-conformance/tests/forbidden_claim_guard_test.rs`):
- It scans proposal-facing docs from DISK and FAILS if a forbidden phrase appears as a LIVE (non-negated) claim. `FORBIDDEN_PHRASES` currently = "prevents tool poisoning", "provides RBAC", "proves a signer is a safe agent", "proves on_behalf_of delegation is legitimate", "authorization_hash_mismatch", "unconditional multi-node replay", "secures all MCP", "validates tool descriptors". Negation markers ("no ", "not ", "never", "cannot", "by design", …) distinguish a repudiation from a claim.
- Per ADR-MCPS-036 the list "must be maintained alongside §A's Forbidden claim column".
- **THE SCANNED SET IS EXACTLY FIVE FILES**: `docs/spec/security-boundary.md`, `docs/spec/v0.5-claim-matrix.md`, `docs/spec/threat-coverage-matrix.md`, `docs/spec/composability.md`, `docs/spec/proposal-scope.md`. The test's own comment says it "deliberately does NOT scan historical ADRs, the v0.3-… files, the grilling seed, or test fixtures — a forbidden phrase is legitimate THERE (it is named to be repudiated)."

THE HOLE: `docs/PROJECT_STATUS.md` is NOT in the scanned set. That is precisely the document that currently carries the two live over-claims this PRD has to fix — the stale "Current release: v0.10.1" and the stale v0.11 "zero-drop rolling update" that the v0.12.1 CHANGELOG contradicts with a 2-of-590 in-flight drop. The guard was built to make over-claiming mechanically impossible, and the actual over-claim sailed straight past it because it lives in an unscanned file. The same hole applies to `docs/fleet-deployment-guide.md` and the SLO/benchmark doc — the exact files Branch B just decided the bounded zero-drop claim will live in — and to `README.md`.

So the honesty machinery is guarding the documents a standards reviewer reads, and NOT the document an ADOPTER reads first.

ANSWER THESE:
(1) Does the scanned set expand to cover every CURRENT-FACING claim surface (PROJECT_STATUS.md, README.md, fleet-deployment-guide.md, the SLO doc), or is there a principled reason the guard should only cover the five proposal-facing docs? If it expands, what is the PRINCIPLE that decides membership — "any doc that states a capability in the present tense about the shipped system"? Give a rule, not a file list, because a file list rots.
(2) What NEW forbidden phrases does this grill's own output require? Candidates from decisions already signed off: an unqualified/topology-independent "zero-drop" claim (Branch B bounded it to declared GKE+NEG topology + declared drain config + declared load envelope); "multi-cloud custody" used as anything broader than "validated support for more than one cloud KMS provider"; any wording implying INSTANT/immediate root revocation (Branch C declared a bounded propagation window and forbade implying instant); any wording implying staffed dual control where the mechanism only enforces distinct identities (Branch C's honesty gap — identity-distinctness is not human-distinctness). Name the exact phrases.
(3) The guard uses NEGATION MARKERS to tell a repudiation from a claim. Several of this grill's new forbidden framings are QUALIFIED claims, not negated ones — "validated zero-drop under the declared topology" is legitimate, bare "zero-drop rolling update" is not, and both contain the same substring with NO negation marker present. The existing negation-marker mechanism cannot express "this phrase is allowed only when qualified". Does the guard need a new mechanism (e.g. a required-qualifier rule: the phrase must co-occur with a declared-tier/topology qualifier on the same line), or is that over-engineering — and if the mechanism can't express it, is a bare-"zero-drop" ban the honest fallback?

Answer decisively on all three.
```

### Answer (Codex)

Yes: the guard expands to every current-facing claim surface, not just proposal-facing docs. Principle: any non-historical, non-fixture document that states present-tense capability, security, operability, evidence, custody, or deployment behavior of the shipped MCP-RE system is in scope; archived ADRs, repudiation examples, fixtures, and explicitly historical specs are out. The immediate paths are `docs/PROJECT_STATUS.md`, `README.md`, `docs/fleet-deployment-guide.md`, the SLO/benchmark doc, and the existing five spec files, but the rule is the contract.

New forbidden framings are: bare `zero-drop rolling update`, `topology-independent zero-drop`, `general zero-drop`, bare `multi-cloud custody`, `instant root revocation`, `immediate root revocation`, `zero-window root revocation`, `staffed dual control`, `human-distinct approvers`, and `two-person approval` unless the text explicitly states the actual mechanism and limitation. For AWS, the allowed claim is exactly the narrow one: native non-exporting delegated-root signing validated against Google Cloud KMS and AWS KMS; nothing about AWS fleet maturity, failover, IAM architecture, or equivalent revocation behavior rides along.

The guard needs a required-qualifier mechanism now. Negation markers are not expressive enough because the honest claim is qualified, not negated: `validated zero-drop under declared GKE + NEG/container-native load balancing + declared readiness/drain configuration + declared load envelope` is allowed, bare `zero-drop rolling update` is not. Same-line or same-paragraph qualifier rules are the right fix; if a phrase needs qualification and the qualifier is absent, fail closed. A blanket bare-phrase ban is acceptable only as the interim implementation while the qualifier rule lands in the same PRD workstream, not as the final design.

---

## E1 — Branch E — does EMA need a new artifact_type?

### Question (griller)

```text
QUESTION (Branch E — EMA binding profile, Q1): does EMA need ANY new artifact_type at all?

VERIFIED CODEBASE EVIDENCE (this reframes the whole branch — the seed assumed far more was missing):
`mcp-re-http-profile/src/artifact.rs` ALREADY implements typed artifact-binding verification, and its module doc says:
  "The three typed OAuth-family proofs all reduce to the same primitive — `base64url-no-pad(SHA-256(credential bytes))` — but over different, type-tagged byte sources:
   - `oauth-dpop` → RFC 9449 `ath` = SHA-256 of the access token;
   - `oauth-mtls` → RFC 8705 `x5t#S256` = SHA-256 of the DER certificate;
   - `oauth-rar` → SHA-256 of the canonical RFC 9396 `authorization_details`."
- `verify_dpop_ath(binding, access_token)`, `verify_mtls_x5t_s256(binding, cert_der)`, `verify_rar_details(binding, authorization_details_canonical)` all exist and are tested.
- `ArtifactType` (in `block.rs`) is a CLOSED enum: `oauth-dpop`, `oauth-mtls`, `oauth-rar`, `pdp-decision`, `dtr-approval`, `classifier-result`, `human-approval`. The last four have NO typed verifier and are explicitly REJECTED by `verify_artifact_binding` ("no typed verifier for this artifact_type yet") "so a caller cannot silently treat an un-verifiable type as verified".
- `BindingType` is `opaque-digest` | `reference-digest`. Typed OAuth proofs require `opaque-digest`.
- The `AudienceTuple` already has `audience_id` + `target_uri`, and an `audience_hash()`; the wire code `mcp-re.invalid_audience` exists.
- Module doc: "the raw `authorization` / `dpop` headers are RFC 9421-covered exactly once, and the client certificate comes from the mTLS layer. The digest, never the bytes, is the binding."

THE OBSERVATION: an EMA-issued MCP access token IS an OAuth 2.0 access token. It is obtained via RFC 8693 token exchange (ID-JAG → MCP Authorization Server → audience-restricted access token) and then presented to the MCP resource server. Binding it is EXACTLY what `oauth-dpop` (SHA-256 of the access token = RFC 9449 `ath`) or `oauth-mtls` (RFC 8705 `x5t#S256`) already do. Nothing about the token's EMA provenance changes the cryptographic binding primitive.

So the sharp question: **is "EMA support" in MCP-RE actually ZERO new wire vocabulary — just the existing `oauth-dpop`/`oauth-mtls` types, plus a conformance lane and a policy mode?** Or is a new `ArtifactType` (e.g. `ema-access-token`, or an `ema-id-jag`) genuinely needed?

Arguments that NO new type is needed (and minting one would be a mistake):
- S13 (domain terminology is the north star): the domain-canonical description of this artifact IS "OAuth 2.0 access token, sender-constrained via DPoP (RFC 9449) or mTLS (RFC 8705)". "EMA" is a PROVENANCE story about how the token was ISSUED — it is not a different kind of credential on the wire. Naming an artifact type after the issuance ceremony rather than the credential class would be an invented synonym for a thing the RFCs already name.
- BIND-DON'T-INTERPRET: MCP-RE binds a digest of opaque bytes. It cannot tell — and by its own architecture MUST NOT care — whether the access token it is binding came from an EMA/ID-JAG exchange or an ordinary OAuth code flow. If MCP-RE needed a distinct `ema-*` type, that would mean it is INTERPRETING the token's provenance, which is precisely the boundary violation the project refuses.
- S4 (no redundant surface): a second type whose verifier is byte-identical to `oauth-dpop`'s is dead vocabulary.
- The ID-JAG never appears on the runtime request at all (it is consumed at the Authorization Server), so there is nothing to bind for it.

Arguments that a new type might be needed:
- Audit/interop consumers may want to know the authorization was enterprise-managed.
- The MCP resource identifier / `resource` parameter comparison might need its own binding.

ANSWER DECISIVELY:
(1) Does the EMA profile add ANY new `ArtifactType` value, or is EMA composition exactly `oauth-dpop`/`oauth-mtls` + policy + a conformance lane + documentation? Remember: new protected wire vocabulary is always Mats' call — so if your answer is "no new type", say so plainly and the decision is cheap; if it IS needed, name exactly why the existing types cannot express it.
(2) If no new artifact type: what does the "EMA composition profile" actually CONSIST of as shippable work? Be concrete.
(3) Where does the EMA-specific part live that is NOT a binding — i.e. the check that the token's `resource`/audience matches MCP-RE's `audience_id`? Is that a new mechanism, an existing `audience` check, or a POLICY concern outside the profile? Note that comparing a token's `aud`/`resource` claim to MCP-RE's audience would require PARSING THE TOKEN — which is interpretation, not binding. Does that break the boundary, and if so who does that check instead?
```

### Answer (Codex)

No new `ArtifactType`. EMA support is composition: use the existing `oauth-dpop` or `oauth-mtls` binding over the presented OAuth access token/certificate, keep `opaque-digest`, document the EMA profile, add positive/negative conformance vectors, and add a policy mode that requires one of those sender-constrained OAuth bindings for EMA deployments. Minting `ema-access-token` would be dead vocabulary: [artifact.rs](/Users/mats/dev/mcp-re/mcp-re-http-profile/src/artifact.rs) already says the primitive is SHA-256 over the credential bytes, and [block.rs](/Users/mats/dev/mcp-re/mcp-re-http-profile/src/block.rs) already has the closed OAuth artifact types.

The ID-JAG is not a runtime artifact; it is consumed by the Authorization Server during RFC 8693 token exchange, so MCP-RE has nothing to bind there. The EMA-specific audience/resource check is not a new MCP-RE binding mechanism and not a new artifact type. Parsing the token to compare `aud` or `resource` is authorization-server/resource-server policy work; MCP-RE binds the presented credential and enforces its own existing `AudienceTuple` check through [verify.rs](/Users/mats/dev/mcp-re/mcp-re-http-profile/src/verify.rs), which already maps mismatch to `mcp-re.invalid_audience` via [error.rs](/Users/mats/dev/mcp-re/mcp-re-http-profile/src/error.rs). That preserves the boundary: MCP-RE binds, the OAuth/MCP authorization layer interprets.

---

## E2 — Branch E — Mode 2 / who interprets

### Question (griller)

```text
QUESTION (Branch E — EMA composition, Q2): E1's answer leaves a hole. Who interprets, in Mode 2?

The pre-existing (now stale) design note `docs/spec/ema-composition.md` defines TWO composition modes, and its "EMA twice" rule says exactly one component enforces EMA per call:
- **Mode 1 — EMA binding mode** (for EMA-native MCP servers): the backend performs the authorization decision; MCP-RE does NOT re-decide, it BINDS the artifact so it cannot be swapped/forged/replayed/detached. This mode is fully consistent with E1: nobody needs MCP-RE to interpret anything.
- **Mode 2 — EMA enforcement mode** (ONLY for private backends fully behind MCP-RE): "the MCP-RE delegated-authorization layer enforces the EMA-derived grant BEFORE dispatch (deny-before-dispatch), because nothing downstream will."

THE PROBLEM: if MCP-RE never interprets the access token (E1), then in Mode 2 **NOBODY** checks that the token is valid, unexpired, issued by the right enterprise IdP, or scoped to THIS resource. MCP-RE's own `AudienceTuple` check proves the REQUEST was addressed to this verifier — it proves nothing about the TOKEN. A stolen-but-correctly-bound token, or a token issued for a different MCP resource entirely, would bind perfectly and pass. Mode 2 as written cannot exist under E1's boundary.

THE CANDIDATE RESOLUTION — the seam already exists. Per `CONTEXT.md`: "**Authorization binding (bind-not-interpret)** — Core binds `authorization_hash`; the configured **AuthorizationProfile** (ADR-MCPS-013) interprets it and decides allow/deny. Core never validates artifact contents, provides RBAC, or emits a 'mismatch'." And ADR-MCPS-013 is titled "Delegated Authorization — AuthorizationProfile Abstraction and the Reference Signed Authorization Profile". So the architecture ALREADY has the place where interpretation legitimately happens: a configured profile OUTSIDE core.

ANSWER DECISIVELY:
(1) Is the correct answer that an **EMA AuthorizationProfile** (an ADR-MCPS-013 profile instance) is what validates the access token in Mode 2 — signature against the AS/IdP JWKS, `exp`, `iss`, and `aud`/`resource` == this MCP resource — while `mcp-re-core` still only binds? If so, is that profile IN SCOPE for this PRD, or is it a reference/example profile, or explicitly a deployer's responsibility?
(2) Does Mode 2 survive AT ALL in this PRD, or is it CUT? Consider seriously: Mode 2 means MCP-RE becomes an OAuth resource server — it must fetch JWKS, cache keys, handle rotation, validate claims, possibly introspect for revocation. That is an entire authorization stack, and the project's stated non-claim is explicitly "universal enterprise authorization (MCP-RE binds authorization decisions; it does not interpret or replace an enterprise authz system)" and "an EMA (enterprise-managed authorization) implementation". Is shipping Mode 2 a boundary violation that contradicts a published non-claim, or is it legitimate BECAUSE it lives in a pluggable profile outside core? Recall the project ALREADY deleted things rather than keep an unblessed second path (stdio, direct-root, JCS) — but Mats also ruled in Branch B that there is "no deletion without architectural or maintenance cause".
(3) If Mode 2 is cut, what happens to a private/non-EMA-aware backend behind MCP-RE — is the honest answer "MCP-RE composes with EMA only in Mode 1; a private backend must front an EMA-aware authorization server itself, or accept that MCP-RE binds but nothing enforces"? Is a documented, tested limitation the right S14-style move here (the int53 precedent: strictest honest domain + documented limitation beats widening the highest-risk surface)?
(4) What EXACTLY is the shippable EMA workstream now, given E1 collapsed the binding work to zero? List it concretely, and say whether the hermetic IdP→ID-JAG→AS→token→client-proxy→server-proxy conformance lane is still worth building if MCP-RE binds an opaque token and never interprets it — i.e. does that lane test MCP-RE, or does it mostly test a fake IdP we wrote ourselves? (S8: evidence must be anti-gameable and must actually test OUR code.)
```

### Answer (Codex)

Mode 2 is cut from this PRD. If EMA enforcement ever exists, the interpreter is an ADR-MCPS-013 `AuthorizationProfile`, never `mcp-re-core`; the repo already says core binds only while the profile interprets ([CONTEXT.md](/Users/mats/dev/mcp-re/CONTEXT.md:52), [mcp-re-policy/src/lib.rs](/Users/mats/dev/mcp-re/mcp-re-policy/src/lib.rs:1)), and the current HTTP policy path is explicitly not rebuilt yet ([mcp-re-policy/src/lib.rs](/Users/mats/dev/mcp-re/mcp-re-policy/src/lib.rs:23)).

I am not shipping an EMA `AuthorizationProfile` here, reference or otherwise, because validating JWTs/JWKS/issuer/audience/expiry/rotation/revocation is an OAuth resource-server implementation, and that contradicts the published non-claim that MCP-RE is not universal enterprise authorization or an EMA implementation ([docs/PROJECT_STATUS.md](/Users/mats/dev/mcp-re/docs/PROJECT_STATUS.md:137), [docs/MCP-RE-IN-ONE-PAGE.md](/Users/mats/dev/mcp-re/docs/MCP-RE-IN-ONE-PAGE.md:53)). The stale `docs/spec/ema-composition.md` Mode 2 text is therefore superseded, not repaired; private non-EMA-aware backends must sit behind an EMA-aware authorization server/resource-server adapter, or they only get MCP-RE binding with no EMA enforcement claim. That is the stricter honest domain: Mode 1 only, documented and tested, rather than widening MCP-RE into the highest-risk authorization surface.

The shippable EMA workstream is: replace the stale EMA composition note with an HTTP-only Mode 1 binding profile; state ID-JAG is not a runtime artifact; use existing `oauth-dpop` / `oauth-mtls` plus `opaque-digest`; define policy-required presence/fail-closed behavior; add positive and negative artifact-binding vectors for token swap, detach, wrong type, missing required binding, and replay/splice; update boundary/claim docs only after the mapped tests are green. I would not build a hermetic fake IdP-to-ID-JAG-to-AS lane as evidence, because if MCP-RE never interprets the token, that lane mostly tests our fake authorization stack. The anti-gameable lane is black-box MCP-RE: present opaque bearer material through the HTTP profile, assert the exact binding behavior and failures, and leave real EMA/OAuth validation to the component that actually owns that decision.

---

## F1 — Branch F — independent verifier + conformance vectors

### Question (griller)

```text
QUESTION (Branch F — Ecosystem readiness, Q1): the independent verifier, and what actually gates it.

CONTEXT — three things just converged on the SAME requirement:
1. **C0 (settled)** already makes "golden vectors + an independent NON-RUST verifier" MANDATORY for the re-based JWS `TrustAnchorManifest`.
2. **S15** already requires cross-verification against an independent authoritative implementation for all security/crypto/wire-interop code, and the v0.11 HTTP profile already does this: CI verifies through a pinned third-party RFC 9421 implementation plus RFC worked-example known-answer tests, and the delegation credential has 22 golden vectors (d01–d22) plus a python-cryptography JOSE cross-verify gate in BOTH directions.
3. The stated ecosystem goal is that MCP-RE be **implementable without importing the Rust code**.

So an independent non-Rust verification capability partly EXISTS already (the python JOSE cross-verify gate, the pinned third-party RFC 9421 impl). What does NOT exist is a single, versioned, standalone artifact a third party can consume.

ANSWER DECISIVELY:
(1) Is the deliverable a **standalone versioned conformance-vector package** (vectors + expected results + a spec of the preimages, published independently of the repo, with its OWN version line because others depend on it), or is it **an independent non-Rust verifier implementation**, or both? If both, which one gates the other? Note the honest test of "implementable without the Rust code" is: could someone build a verifier from the PUBLISHED SPEC + VECTORS alone, with no access to this repo? Say whether today's spec actually supports that — the C0 finding proved it did NOT for the trust manifest (its preimage was "whatever serde does to a Rust struct").
(2) Is growing the EXISTING python-cryptography cross-verify gate into the independent verifier the right move, or does reusing our own test harness defeat the purpose? Consider S8 anti-gaming carefully: a verifier WE wrote, in a second language, still encodes OUR reading of the spec — it catches Rust-specific bugs and serialization accidents, but it does NOT catch a spec that is ambiguous or wrong, because the same author resolved both ambiguities the same way. Is a same-author second-language verifier honest evidence of independent implementability, or is it self-certification wearing a costume? If it is not sufficient, what IS — and is that achievable by a solo project at all, or is the honest position a documented limitation (the S14/int53 pattern) until a genuine third party implements?
(3) Given (2), what is the honest CLAIM wording for conformance? Remember the settled rules: claim exactly what is proven, never the category; and qualified-only phrases must be grammatically bound. Draft the exact sentence MCP-RE may say about independent implementability today, and the one it may NOT.
```

### Answer (Codex)

The deliverable is both, but the **standalone versioned conformance-vector package gates everything else**: published spec, preimages, vectors, expected failures, and its own version line. The non-Rust verifier is only valid if it consumes that package and the published spec, not repo internals; today the trust manifest fails that test because C0 proved its signature preimage was a Rust serializer accident, not an independently implementable protocol. Growing the existing Python gate is still the right internal move, but it is **not** independent implementability evidence; same-author second-language verification catches Rust bugs, not spec ambiguity.

So the honest bar is: package first, our Python verifier second, genuine third-party implementation before any ecosystem claim. A solo project can produce excellent anti-regression evidence, but it cannot self-certify independent implementability; until an outside implementation passes the public vectors, that limitation is documented, not papered over.

Allowed sentence: **“MCP-RE currently has machine-checked Rust/non-Rust cross-verification for selected wire and credential surfaces, and full independent implementability remains unclaimed until a standalone conformance-vector package is consumed successfully by a genuine third-party verifier.”**

Forbidden sentence: **“MCP-RE is independently implementable without importing the Rust code.”**

---
