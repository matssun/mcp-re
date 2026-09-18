<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-MCPRE-068 Phase 1 — THM-0075 "No unearned response attribution", decomposed

`critical`, 5 declared dependencies, a 16-theorem closure, 15 distinct semantic owners.
Decomposed downward from the consequence. **The root survived falsification: no claim
correction is proposed here, and that is the result rather than the absence of one.**

## 1. The consequence, stated precisely

If THM-0075 is false, a relying party receives signed evidence it attributes to this
deployment which the deployment did not earn the right to produce. The registered consequence
names four distinct attacks:

| # | the attack | which proposition below fails |
|---|---|---|
| A | attributed to the trust root DIRECTLY | S2 |
| B | signed by a credential the deployment does not hold, or no longer holds | S1 |
| C | advertising validity its credential does not authorize | S5 |
| D | unbound evidence verifying through the bound-response path | S4 |

It is explicitly the PRODUCER side. The consequence says so in terms, and names THM-0076 as
the other side of the same exchange.

## 2. Falsifying the root statement: four attempts, four failures

**Attempt 1 — does "under the supported delegation model" quantify over a set nothing pins?**
This is the defect found one root earlier in THM-0074, where "selected by the validated
deployment" named no determinate set. It does not recur here, and the reason is structural
rather than lucky: `ResponseSigningRequest` carries ONE field, `source`. There is no mode
selector, so there is no second delegation model for a deployment to be talked into. The
phrase names a constant, not a selection, and the governing decision behind it — direct-root
response signing deleted from the runtime — is why the field does not exist.

**Attempt 2 — is attack A owned by anything?** Nothing in the closure states "no direct-root
attribution" in terms, which looked like a gap. It is not one, but it is a CONJUNCTION rather
than a single owner, and that is worth recording: THM-0062 says a response-signing credential
exists only from a successful rotation, and THM-0082 says the composition root installs the
signing plane from the materialized source and "constructs no key source of its own". Neither
alone excludes a direct-root signature; together they do. A future edit that weakened either
would leave attack A defended by the other, which is exactly the situation a reader would
otherwise have to rediscover.

**Attempt 3 — does attack D reach across the exchange into THM-0076's territory?** The
statement's last clause is "cannot be interpreted as bound", which reads as a claim about a
verifier while the consequence declares itself producer-side. Examined and rejected as a
defect: the clause is about the ARTIFACT's form, and THM-0021/THM-0022 — the two distinct
verification outcomes — are how a producer-side claim about that form is measured. THM-0022
is already in `depends_on`, so the registry was never silent about it.

**Attempt 4 — does the claim cover refusal evidence, which it names?** Yes, by name.
THM-0063: "The same owner opens every window this deployment signs under, reply and refusal
alike, and a refusal signs under the snapshot its own exchange took." The scope's carve-out
for an unsigned last-resort receipt agrees with THM-0063's own scope rather than contradicting
it.

## 3. The propositions

### S1 — PROVENANCE. The signing capability is the one materialization produced for this deployment.
* owners: `proxy.signing_credential_provenance` (THM-0082), `proxy.delegated_signing_credential` (THM-0062)
* THM-0082 is the composition half THM-0073's seal cannot reach: none of the credential
  theorems says the root USED the materializer, and that is the proposition.

### S2 — NO DIRECT ROOT. See attempt 2. A conjunction of THM-0062 and THM-0082.

### S3 — BINDING. Bound evidence binds the exact request it answers.
* owner: `http_profile.response_emission_binding` (THM-0065)

### S4 — UNBOUND STAYS UNBOUND. Evidence produced before a request can be established is
explicitly unbound.
* owner: `http_profile.verifier_results` (THM-0021, THM-0022)

### S5 — NO OVER-ADVERTISEMENT. A window never claims validity the credential does not authorize.
* owner: `proxy.response_signing` (THM-0063)
* carrier: `SigningWindow` keeps `expires` private and no constructor accepts one — the
  window is DERIVED, with saturating arithmetic so an absurd configured TTL cannot wrap past
  the credential's own `exp`. That is a structural fact about a sealed value, measured as
  `tested`; see §4.

## 4. Honest evidence classes, and the debt this root sits on

Fifteen owners. Seven carry a registered falsifier. **Eight do not, and one of them is this
root's own owner.**

```
proxy.response_signing                 DEBT eff=critical   <- the root's owner
http_profile.response_emission_binding DEBT eff=critical   <- S3, the binding leaf
proxy.signing_credential_provenance    DEBT eff=critical   <- S1
proxy.signing_role_separation          DEBT eff=critical
proxy.custody_exposure                 DEBT eff=critical
proxy.kms_endpoint_authority           DEBT eff=critical
proxy.aws_kms_adapter                  DEBT eff=critical
proxy.cross_machine_legality           DEBT eff=critical
```

Every one is already a registered N1 obligation, so this decomposition manufactured no debt
and uncovered none. But the shape is worth stating plainly rather than leaving in a table:
**THM-0075 is a `critical` root three of whose five propositions — S1, S3 and S5 — rest on
owners that no falsifier attacks.** The batteries are green; nothing has shown that any check
in them is load-bearing.

That is not a finding against the code. It is the measurement this phase exists to produce,
and it is why "the evidence class follows the proposition, not the URI" matters: all three
are honestly `tested`, and `tested` without a falsifier is exactly what N1 counts.

`http_profile.freshness_window` is `proved` (Verus, THM-0001) and was not reclassified.

## 5. Premises, boundaries and review obligations

* **EXTERNAL BOUNDARY** — the KMS/STS endpoint reached by the text that names it (THM-0089)
  and the AWS adapter (THM-0116) sit at the provider boundary. Both are in the closure and
  both are registered debt; neither is discharged here.
* **ASSUMED** — S5's carrier is a sealed value (`expires` private, no constructor accepts
  one), which is structural in effect. `proxy.response_signing` also carries THM-0075 itself,
  and a unit takes one evidence class, so it stays `tested`. Recorded as residue of one owner
  holding two carriers — the same shape recorded for `proxy.dispatch_commitment` under
  THM-0074, and the second instance of it in this phase.
* **REVIEW OBLIGATION** — none new.

## 6. What was NOT done here

Nothing discharged; eight open obligations remain open. No unit split: question 2 was asked of
all fifteen owners and none answered with a second independently describable authority its
theorem layer did not already separate. No claim correction: the statement says what
production establishes.
