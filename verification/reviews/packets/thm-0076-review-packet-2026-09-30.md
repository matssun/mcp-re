# THM-0084 and THM-0076: specification review packet, 2026-09-30

Awaiting the owner's specification authorization, THM-0084 first, then THM-0076. Nothing in
this packet is an approval, and the correction link it accompanies
(`verification/claim-corrections/THM-0076-pairing-attribution-2026-09-30.json`) is not one.

This packet supersedes sections 6 to 8 of
`thm-0126-sealing-repair-and-thm-0076-chain-2026-09-30.md`, which stays as the record of the
THM-0126 repair and of the earlier chain link.

## 1. The other five authorized fingerprints

Recomputed after the THM-0084 repair, on the same tree:

| theorem | authorized | recomputed | |
|---|---|---|---|
| THM-0082 | `sha256:807d622eec73915f60ab7dd4663f8babbb53d197413ce2fdcdf739f8859d8fca` | `sha256:807d622eec73915f60ab7dd4663f8babbb53d197413ce2fdcdf739f8859d8fca` | unchanged |
| THM-0119 | `sha256:12aa5efb105e02eda8fceef30e1d60c20cfb6efb31525db16737731f4abb6d60` | `sha256:12aa5efb105e02eda8fceef30e1d60c20cfb6efb31525db16737731f4abb6d60` | unchanged |
| THM-0123 | `sha256:1c134a5776c22b04caa0ecd8fe53f9907427a6c8efa273be8187677812690f05` | `sha256:1c134a5776c22b04caa0ecd8fe53f9907427a6c8efa273be8187677812690f05` | unchanged |
| THM-0126 | `sha256:465251d621d39408d78111762bbb166cfa187ad95ce3fac919ea652eed42f0de` | `sha256:465251d621d39408d78111762bbb166cfa187ad95ce3fac919ea652eed42f0de` | unchanged |
| THM-0127 | `sha256:41d895d991ca84466ae5b3bacc78405d98a2a18d5602e24046d2117b64d4763b` | `sha256:41d895d991ca84466ae5b3bacc78405d98a2a18d5602e24046d2117b64d4763b` | unchanged |

## 2. Does the constructor documentation support the attribution?

Not before this change. `ResponseExpectation::new` documented only who it is for ("For the FFI
bindings, which rebuild the request from scalars and have no `SignedRequest` to take.
In-process callers hold that owner and should take it: see `Self::for_signed`"). It did not
state the obligation, so the ruled sentence would have pointed at documentation that did not
say what the sentence claims. The owner authorized this contract clarification on 2026-09-30.
It is the only source change, comment only, in
`mcp-re-client-core/src/response_expectation.rs`:

```diff
@@ impl ResponseExpectation, pub fn new
     /// [`SignedRequest`] to take. In-process callers hold that owner and should take it:
     /// see [`Self::for_signed`].
+    ///
+    /// Nothing here can check that `request` is the request that was actually sent: the
+    /// pairing of an expectation with the request it describes is ASSUMED, and it is the
+    /// caller's obligation. [`Self::for_signed`] takes the owner of the sent request, so a
+    /// caller that holds it does not have to supply that pairing by hand.
```

The documentation states the assumption and whose obligation it is, and says nothing more. An
earlier draft also said the pairing is "established only" where one owner sends the request
and derives the expectation; the owner ruled that out, since documentation is not proof of
that correspondence. What the shipped `ClientProxy` path does is THM-0084's claim, and it is
supported only by the tests named in section 3, not by this comment.
`bazel test //mcp-re-client-core:mcp_re_client_core_test` passes on the edited tree.

**The theorem fingerprint does not cover source documentation.** It digests a theorem's
statement, consequence, scope, premise-closure claim digests, id and review requirement. This
comment changes none of those, so no fingerprint in this packet moved for it. An unchanged
fingerprint therefore does not show that the supporting evidence is unchanged; that is
established by the tests in section 3 and by CI on the final head, not by the digest.

## 3. THM-0084, full repaired text

Owner `client.proxy_request_correspondence`, review requirement "Owner security-specification
review", `depends_on = []`.

**Statement**

In the production `ClientProxy` request/reply path, the `SignedRequest` handed to
`RemoteTransport::round_trip` is the same signed-request owner from which the
`ResponseExpectation` passed to response verification is derived; on the notification path
the acknowledgement verifier receives `signed.request()` from that same owner directly. The
response is therefore verified against the request that this proxy sent.

**Security consequence**

A server cannot have an answer accepted by pairing a well-formed response with an expectation
describing a request the proxy never sent. The expectation and the sent request are not two
values that happen to agree — there is only one, so there is nothing for them to disagree
about.

**Scope**

The SHIPPED path, and that is the whole point of registering it. THM-0057 through THM-0061
establish what the client-core verifier does with an expectation and a response; every one of
them takes the PAIRING as given: pairing an expectation with the request it describes is the
caller's obligation, stated on `ResponseExpectation::new`.

For a raw FFI caller that is the honest boundary and it stays there: `ResponseExpectation::new`
is public precisely so a binding that rebuilt the request from scalars can supply one, and
nothing here narrows that. What this claim says is that the SYSTEM ROOT is not an arbitrary
caller — it is `ClientProxy::handle`, and there the obligation is DISCHARGED rather than
delegated. Raw FFI and low-level reconstruction remain outside the guarantee.

Evidence, not unconstructibility. Both halves take `&SignedRequest`, so no signature can
force them to be the same value; what is measured is that `handle` builds one, forwards it,
and derives from it, and that the shipped path reconstructs no second request. Deleting the
battery leaves the wrong composition compiling.

It establishes nothing about whether the response is TRUSTWORTHY — that the signer is
authorized, the credential current, the receipt bound — which is THM-0058 through THM-0061.

### Exact diff (statement and consequence unchanged; scope only)

```diff
--- reviewed-scope (HEAD)
+++ repaired-scope
@@ -2,4 +2,4 @@
 establish what the client-core verifier does with an expectation and a response; every one of
-them takes the PAIRING as given, and `client.response_binding_disposition`'s scope says so explicitly —
-pairing an expectation with the request it describes is the caller's obligation.
+them takes the PAIRING as given: pairing an expectation with the request it describes is the
+caller's obligation, stated on `ResponseExpectation::new`.
 
```

### Fingerprints

| | fingerprint | claim digest |
|---|---|---|
| reviewed, 2026-08-31 | `sha256:235ff94049d233ca2bfd995b24a3219d23ab2a1b720469fa90a8dd8c5c163d4c` | `sha256:6e2056c9c9a85ee5c42e9cd7c60711115968db07dcd422c9a98109c6d3ac9900` |
| before this repair (#998 pointer) | `sha256:a0f65e42f8df1cf907dd6beb1c7c9b80f844373b53329f334717402a9ee74b4b` | `sha256:1e8ec26fd8da705b50acf94d44ef1f28e287f8886deb1f2c24d53ab497d32fad` |
| **new** | `sha256:0645e05383a9a48cf8582e102f17bcb49240d7024c32ea716e34884cf6d292f9` | `sha256:1edbe9ee47fa8ef7b0608382c36e9888733d5e1a88c36ce694679f449dc77702` |

Net change from what you reviewed in August: two scope edits, the #998 unit rename and this
repair. The proposition, consequence and the evidence-not-unconstructibility paragraph are the
reviewed text.

### Evidence

Unit `client.proxy_request_correspondence` (V0, tested, critical), four tests, all Bazel
labelled, run on this branch and passing: `the_proxy_sends_the_one_request_it_signed`,
`both_verification_paths_take_the_signed_request_owner`,
`the_shipped_path_reconstructs_no_second_request`,
`the_correspondence_rules_would_catch_each_regression`. Evidence ids
`test://client/proxy/request_correspondence` and `mutation://client/proxy/request_correspondence`.
These are source-structure controls; the scope says so ("Evidence, not unconstructibility").
Constructor documentation: section 2 (a clarification of the assumption, not evidence of correspondence).

## 4. THM-0076, full current text

Owner-reviewed 2026-09-07 as a dependency-only re-affirmation at
`sha256:e0b19a03b8812fc204bc29d49268ae71cb1fe492d20fb34485ace86eec5173d3`. Root system claim.

**Statement**

If the shipped MCP-RE client proxy returns a remote response as verified for a call, that
response was verified against the request THAT PROXY SENT (THM-0084) and under a signer this
client's current trust configuration authorizes in the Response slot; a response that could
not be bound is never reported as a success; and what the client may conclude about whether
the work ran is what the receipt states, never what its silence might be read as.

**Security consequence**

An application cannot be handed, as this call's answer, a response from another exchange,
from another signer, from a signer whose authorization has been retired, or one that verified
only in the unbound form — and cannot be led to repeat a side effect by reading silence as
*it did not run*.

**Scope**

The consumer side, kept apart from THM-0075 because a deployment may run either side alone
and producer attribution and consumer acceptance are different propositions.

The system root is the SHIPPED `ClientProxy` path, not an arbitrary caller of the low-level
verifier — and the two used to say different things. The statement claimed the response
resolved against "the request this client sent" while the scope said the pairing was a caller
obligation, which is a contradiction rather than a boundary. THM-0084 removes it by
establishing the pairing where the shipped path owns it: `handle` builds one `SignedRequest`,
forwards it, and derives the expectation from that same owner.

The FFI boundary is unchanged and stays outside. `ResponseExpectation::new` remains public
for bindings that rebuilt the request from scalars and hold no `SignedRequest`, and sealing
past that seam would be theatre; what THM-0084 says is that the shipped path does not use it.
Raw FFI and low-level reconstruction remain outside this system-root guarantee.

It does not establish that the deployment was right to trust an anchor.

### Fingerprint

| | fingerprint |
|---|---|
| reviewed | `sha256:e0b19a03b8812fc204bc29d49268ae71cb1fe492d20fb34485ace86eec5173d3` |
| after the sealing link | `sha256:ab7915a1b9965a67fb7e4bfdeb6b6445537a0191339c17a8b67201f3f59bc442` |
| **new** | `sha256:c31e87374af20b541166eab1c6de5a119578852b9e40ef3db51f57e9e5c6204c` |

Its claim digest is `sha256:ca9f6756…a926e6269`, byte-identical at every point in the chain.
Its correction chain is now four links: `e0b19a03` to `07db1d02` (prose, 2026-09-18), to
`e684fc96` (Bazel lane wording, 2026-09-29), to `ab7915a1` (sealing attribution, 2026-09-30),
to the new fingerprint (pairing attribution, 2026-09-30). All earlier records are untouched.

## 5. The composition argument, all five moved premises

Closure: 16 premises; 11 byte-identical to the reviewed record. The five that moved, with
their exact text changes, are in section 5 of the earlier packet. In summary:

| premise | change | proposition changed? | state |
|---|---|---|---|
| THM-0084 | scope pointer, then this repair | no | awaiting your review (section 3) |
| THM-0120 | "cargo lane" to "Bazel lane" | no | reviewed |
| THM-0121 | same | no | reviewed |
| THM-0126 | exclusion pointers, lane wording, sealing repair | no | owner-reviewed 2026-09-30 at `sha256:465251d6…f0de` |
| THM-0127 | `client.config_lattice` pointer, lane wording | no | owner-reviewed 2026-09-30 at `sha256:41d895d9…764b` |

The argument. THM-0076 says that what the shipped client proxy returns as a verified answer
was verified against the request that proxy sent, under a signer its trust configuration
authorizes. It is the conjunction of: the verifier semantics (THM-0057 to THM-0061, none of
which moved); the pairing on the shipped path (THM-0084); the step from a verified response to a
terminal, continuation or refusal outcome (THM-0126); and the deployable actually maintaining
the trust configuration those semantics assume (THM-0127, resting on THM-0120 and THM-0121).
Each premise's statement and security consequence are byte-identical to the versions that were
ratified. The movements are lane sentences, exclusion pointers, one sealing exclusion made
accurate, and one pointer to where the pairing obligation is stated. None of them adds or
removes a case the root relies on: THM-0084's assumed/established line is where the root's
scope already drew it ("Raw FFI and low-level reconstruction remain outside the guarantee").
So the composition establishes the same conclusion it did when you ratified it.

Why the root consequence and product behavior are unchanged. THM-0076's text is
byte-identical, so the promise is. The only source change in this link is a doc comment; the
earlier link changed none either. Product behavior is unchanged because no executable line
moved.

What this argument does not establish: it is an argument from the text and the tests named
here. Local unit evidence prints UNKNOWN for want of attestations, which is not a measurement;
fresh evidence is the CI verification run on the final head.

## 6. What I am asking for

1. Authorize THM-0084 at `sha256:0645e05383a9a48cf8582e102f17bcb49240d7024c32ea716e34884cf6d292f9`, or return it.
2. Then authorize THM-0076 at `sha256:c31e87374af20b541166eab1c6de5a119578852b9e40ef3db51f57e9e5c6204c`, as a dependency-only re-affirmation over
   the five movements, or return it.

## 7. Separate review debt, not gating

THM-0091 stays stale and is tracked in
`thm-0091-stale-review-tracking-2026-09-30.md`. It is not part of THM-0076 or #1074.
