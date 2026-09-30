# THM-0126 sealing repair, and the THM-0076 correction-chain link — 2026-09-30

Prepared for the owner's authorization. **This packet and the correction record it backs
record no approval.** A correction record is a delta on a claim the owner reviewed; it makes
the merge gate accept a moved claim and does not make any specification review fresh
(`tools/verification/_claim_corrections.py`). The reviews this needs are listed in section 5
and are not recorded.

Ruling (owner, 2026-09-30): repair THM-0126's sealing sentence now, stating that sealing the
verified-response chain has no owning verification unit today and is outside this claim; do
not approve the inaccurate wording or defer the repair. The ruling covers preparing THM-0076's
correction-chain link, preserving the existing history, and states that a correction record
must not substitute for a required specification review.

## 1. The resulting text

THM-0126's `statement` and `security_consequence` are untouched. `scope` now reads, in full:

> COMPOSITION, not classification and not trust. The three-way discriminator itself is
> `client.execution_contract`'s under THM-0061; whether the bytes are genuine and answer this
> request is `client.response_signer_authorization`'s and
> `client.response_binding_disposition`'s under THM-0076. What is established here is that
> the shipped proxy composes those answers without adding a reading of its own — in particular
> that it does not ask the classification question a second time over the raw body, which is
> how two readers of one message come to disagree about what it says.
>
> It establishes nothing about what the server's result MEANS beyond its classification, and
> nothing about replies that never verified: those do not reach this composition at all.
>
> Executable, class V0, measured in the default Bazel lane (`bazel test //...`). Every control performs a real
> delegated signing round trip and takes its `VerifiedDelegatedResponse` from
> `verify_delegated_response`; none assembles one.
>
> That is a property of the CONTROLS and of the tree — `verify_delegated_response` is the only
> producer in the workspace — and NOT of the type. `VerifiedDelegatedResponse` and the profile's
> verified-response types carry `pub` fields deliberately, for the prover, and
> `VerifiedMcpResponse::from_block` says so in its own words: a convenience, not a seal. A caller
> outside this workspace could assemble one, and nothing here claims otherwise. Sealing that
> chain has no owning verification unit today and is not this claim's.

Exact difference from the approved text, in three separate parts:

```diff
# pre-branch, origin/main 28394a14 (ADR-069 renames)
-request is `client.response_acceptance`'s under THM-0076. What is established here is that
+request is `client.response_signer_authorization`'s and
+`client.response_binding_disposition`'s under THM-0076. What is established here is that
-chain is `client.response_acceptance`'s question, not this claim's.
+chain is `client.response_signer_authorization`'s question, not this claim's.
# this branch, 77be06f2 (Cargo to Bazel wording)
-Executable, class V0, measured in the default cargo lane. Every control performs a real
+Executable, class V0, measured in the default Bazel lane (`bazel test //...`). Every control performs a real
# this branch, this repair
-chain is `client.response_signer_authorization`'s question, not this claim's.
+chain has no owning verification unit today and is not this claim's.
```

| THM-0126 | fingerprint | claim digest |
|---|---|---|
| reviewed (2026-09-07) | `sha256:732c25f445a1c6fc07cb516f1d6a4e96e4ca39acb66eb4dc939a65a8eadcddf9` | `sha256:40e9c621501ac0637d7ca5d4857e76589a78a889b078c21d10d58f70a07305d4` |
| before this repair | `sha256:18e4a265ba7b324faeb00842b4432c23d723cc1a368064f1053e5c09a9e452b6` | `sha256:8b15a618377467bd5f483c401723113c81ca6e47c02783977115dc107708f65f` |
| **now** | `sha256:465251d621d39408d78111762bbb166cfa187ad95ce3fac919ea652eed42f0de` | `sha256:3b3cd1847d59e13d3ac1d0d7e12452277a72ca538a54eebace3995e788e9fe31` |

## 2. Why the old sentence was wrong

It said sealing the verified-response chain is `client.response_signer_authorization`'s
question. That unit's description and its 15 registered tests cover which signer a client may
accept (chain to a root, pin, revocation, expiry). No unit description and no theorem other
than THM-0126 mentions `VerifiedDelegatedResponse`, whose fields are still `pub`
(`mcp-re-client-core/src/response.rs:90`).

The sentence was not made wrong by the split: the pre-split unit `client.response_acceptance`
(checked at `6d28b76d^`) did not mention sealing either, and none of its 20 registered tests
concerns it. So the approved text attributed sealing to a unit that never owned it, and
repairing it removes a sentence that was never supported rather than restoring a lost owner.
The claim itself is unchanged: it already said the control that matters is a property of the
controls and of the tree, "and NOT of the type", and that a caller outside the workspace
could assemble the value.

## 3. THM-0076: the correction-chain link

THM-0076 is a published root and depends on THM-0126. The repair moves exactly one premise
digest in its closure and nothing else:

| | before | after |
|---|---|---|
| THM-0126 claim digest (premise) | `sha256:8b15a618377467bd5f483c401723113c81ca6e47c02783977115dc107708f65f` | `sha256:3b3cd1847d59e13d3ac1d0d7e12452277a72ca538a54eebace3995e788e9fe31` |
| THM-0076 claim digest (own text) | `sha256:ca9f67566bbe6c733aeba9afb46fea496d8af415b36624f9dde8f91a926e6269` | identical |
| THM-0076 fingerprint | `sha256:e684fc966ea8ddbabf8ee5fdca8f76727f68e2678532509e065ee67030e6bfa3` | `sha256:ab7915a1b9965a67fb7e4bfdeb6b6445537a0191339c17a8b67201f3f59bc442` |

The chain is extended, not rewritten. Existing records are untouched and the new one starts
where the last ended:

| link | authority | from | to |
|---|---|---|---|
| `THM-0076-prose-2026-09-18.json` (C1-C3) | adr-068-phase1 | `e0b19a03…` (the owner's review) | `07db1d02…` |
| `THM-0076-bazel-lane-wording-2026-09-29.json` (C1-C4) | bazel-lane-wording-2026-09-29 | `07db1d02…` | `e684fc96…` |
| **`THM-0076-sealing-attribution-2026-09-30.json` (C1)** | adr-068-phase1, under the owner's 2026-09-30 ruling | `e684fc96…` | `ab7915a1…` |

**Must THM-0076's statement, scope or justification change? No.** Its statement is about the
SHIPPED `ClientProxy` path: a response returned as verified was verified against the request
that proxy sent and under a signer the trust configuration authorizes. Its scope says the
system root is that path and "not an arbitrary caller of the low-level verifier", and the only
sealing it discusses is the INPUT side (`ResponseExpectation::new` stays public for bindings,
"sealing past that seam would be theatre"). It never claims the verified-response output types
are unconstructible, and THM-0126 after the repair says the same thing about them. The claim
digest of THM-0076 is byte-identical before and after, which is the measurement of that. The
record asserts `root_consequence_unchanged` and `product_behavior_unchanged`, which the module
requires, and I believe both; they are the owner's to confirm on authorizing it.

## 4. What the record does not do

The record lets the claim-surface gate accept THM-0076's moved fingerprint. THM-0076's
specification review is `STALE_DEPENDENCY_CLAIM` and stays so; the module states that the
release path still asks for the human.

## 5. The THM-0076 specification review this leaves to the owner

Review record `verification/reviews/specification/THM-0076.json` is a dependency-only
re-affirmation of 2026-09-07 (commit `1c0ea161`, which reproduces its reviewed fingerprint
`sha256:e0b19a03b8812fc204bc29d49268ae71cb1fe492d20fb34485ace86eec5173d3`). Its closure has
the same 16 premises today; 11 are identical and five moved:

| premise | current review state | what moved since the review |
|---|---|---|
| THM-0084 | **STALE_CLAIM** (own claim moved) | scope pointer `client.response_acceptance` to `client.response_binding_disposition` |
| THM-0120 | REVIEWED | lane wording |
| THM-0121 | REVIEWED | lane wording |
| THM-0126 | **STALE_CLAIM** (one of the five) | renames, lane wording, this repair |
| THM-0127 | **STALE_CLAIM** (one of the five) | scope correction (`client.config_lattice` never existed), lane wording |

The exact text changes, from the reviewed text to today:

```diff
### THM-0084 | The shipped client proxy verifies against the request it sent
[scope]
-them takes the PAIRING as given, and `client.response_acceptance`'s scope says so explicitly —
+them takes the PAIRING as given, and `client.response_binding_disposition`'s scope says so explicitly —

### THM-0120 | A client that cannot establish current anchors publishes none, rather than servi
[scope]
-Executable, class V0, measured in the default cargo lane.
+Executable, class V0, measured in the default Bazel lane (`bazel test //...`).

### THM-0121 | The rollback floor only rises, and a floor that has been pushed too high stops t
[scope]
-Executable, class V0, measured in the default cargo lane.
+Executable, class V0, measured in the default Bazel lane (`bazel test //...`).

### THM-0126 | A verified reply is not a completed call
[scope]
-request is `client.response_acceptance`'s under THM-0076. What is established here is that
+request is `client.response_signer_authorization`'s and
+`client.response_binding_disposition`'s under THM-0076. What is established here is that
-Executable, class V0, measured in the default cargo lane. Every control performs a real
+Executable, class V0, measured in the default Bazel lane (`bazel test //...`). Every control performs a real
-chain is `client.response_acceptance`'s question, not this claim's.
+chain has no owning verification unit today and is not this claim's.

### THM-0127 | The deployable's serving path always runs an anchor refresher
[scope]
-that bound is `client.config_lattice`'s.
+that bound is `client.local_leg_declaration`'s.
-Executable, class V0, measured in the default cargo lane over the shipped
+Executable, class V0, measured in the default Bazel lane (`bazel test //...`) over the shipped
```

**Order matters.** THM-0076's review cannot be meaningful until THM-0126 and THM-0127 are
decided (they are in the evidence packet), and THM-0084 is a third unreviewed premise that is
not among the five, is not enforced by this PR's gate, and is pre-existing debt. The owner
question for THM-0076 is whether its dependency-only re-affirmation still holds over these
five movements, every one of which is an exclusion pointer or lane sentence; no premise's
proposition changed.
