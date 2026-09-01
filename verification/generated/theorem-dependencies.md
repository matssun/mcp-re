<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with: tools/verification/generate-views
     Gated by:        tools/verification/check-generated
     Derived from:
       verification/policy/theorems.toml
       verification/policy/verification.toml
       verification/policy/assumptions.toml
-->

# Theorem dependency graph

Which claims rest on which — `depends_on` is logical implication, never a call
or a build edge. Rendered as one diagram per connected component: a single global
diagram is unreadable at the size where it would matter. Declared system roots are
marked; a component containing none is not yet attached to a system promise.

## Component 1

```mermaid
graph BT
    THM_0001["THM-0001<br/>Admitted request parameters imply a current freshness window"]
    THM_0003["THM-0003<br/>Admission verdict integrity"]
    THM_0004["THM-0004<br/>Admission anti-rollback"]
    THM_0005["THM-0005<br/>Degraded admission requires deployment opt-in"]
    THM_0006["THM-0006<br/>Presenter binding"]
    THM_0007["THM-0007<br/>A typed artifact verifier admits only its own type"]
    THM_0008["THM-0008<br/>No untyped artifact binding leaves the verifier as verified"]
    THM_0009["THM-0009<br/>A presented continuation cannot bypass verification"]
    THM_0010["THM-0010<br/>Continuation handles match their presented inputs in role"]
    THM_0013["THM-0013<br/>No validated deployment enables online OCSP client-certificate revocation"]
    THM_0014["THM-0014<br/>A successful request-floor verification establishes the cryptographic floor"]
    THM_0015["THM-0015<br/>A successful full-profile request verification establishes audience and artifact binding"]
    THM_0016["THM-0016<br/>A successful bound response-floor verification establishes trust-seam authorization of the signer"]
    THM_0017["THM-0017<br/>A successful unbound response-floor verification establishes trust-seam authorization and no request binding"]
    THM_0018["THM-0018<br/>A successful full bound response verification establishes block agreement with the expected handle"]
    THM_0019["THM-0019<br/>A successful delegated bound response verification establishes an accepted credential chain"]
    THM_0020["THM-0020<br/>A successful delegated unbound response verification establishes a chain and never a binding"]
    THM_0021["THM-0021<br/>A successful bound-response verification establishes the shared cryptographic and request-binding facts"]
    THM_0022["THM-0022<br/>A successful unbound-response verification establishes the shared facts and no request binding at all"]
    THM_0023["THM-0023<br/>Every peer identity value is well-formed, whatever evidence produced it"]
    THM_0024["THM-0024<br/>Certificate identity interpretation reads the configured field and refuses rather than falling back"]
    THM_0025["THM-0025<br/>Every canonical Ed25519 public key value is the canonical RFC 8410 encoding of its own point"]
    THM_0026["THM-0026<br/>Credential/key correspondence relates two independently interpreted keys and attributes every refusal to the side that failed"]
    THM_0027["THM-0027<br/>A delegated resolver's existence proves its credential and signer corresponded"]
    THM_0028["THM-0028<br/>Channel-associated certificate credential evidence originates only from an established relationship's mechanism report"]
    THM_0029["THM-0029<br/>A channel-associated peer identity is interpreted from the leaf of that relationship's own credential"]
    THM_0030["THM-0030<br/>Verified-credential evidence records the mechanism's own acceptance and the path it was reached on"]
    THM_0031["THM-0031<br/>An authenticated relationship peer's identity is read from the leaf of the very credential the mechanism accepted for that relationship"]
    THM_0032["THM-0032<br/>Per-request credential currency is decided from the credential the mechanism accepted, and reports which of its five facts refused"]
    THM_0033["THM-0033<br/>A current authenticated peer's currency is evaluated against the credential that same peer authenticated with"]
    THM_0034["THM-0034<br/>A request is bound to its relationship by relating the authenticated peer to the resolved actor's SUBJECT, never to the composite actor id"]
    THM_0035["THM-0035<br/>A successfully classified trust-revocation state carries the witnesses its own state form requires"]
    THM_0036["THM-0036<br/>A networked trust-epoch source is handed over as a paired locator and key, or not at all"]
    THM_0037["THM-0037<br/>A trust plan's reload cadence is a projection of the revocation posture, never a second value"]
    THM_0038["THM-0038<br/>The composition root consumes trust as owner projections and re-reads no trust field from the request"]
    THM_0039["THM-0039<br/>An accepted PDP decision was authenticated under a key the trust seam resolved"]
    THM_0040["THM-0040<br/>An authorized request was permitted by a decision about that very request"]
    THM_0043["THM-0043<br/>The exchange relation is decided everywhere and the execution threshold partitions it"]
    THM_0044["THM-0044<br/>An exchange's retry consequence never under-reports what may have happened"]
    THM_0045["THM-0045<br/>The backend is reached only by consuming a fully assembled pre-dispatch commitment"]
    THM_0046["THM-0046<br/>A refusal carries which authority reached it, over a closed set, unrendered"]
    THM_0047["THM-0047<br/>The verifier's assurance products are not substitutable"]
    THM_0048["THM-0048<br/>Every listener obtains its whole security posture through one listener state"]
    THM_0049["THM-0049<br/>Every illegal cross-owner configuration combination is refused at layer A"]
    THM_0050["THM-0050<br/>Distinct verification keys cannot feasibly be made to share a keyid"]
    THM_0051["THM-0051<br/>The pipeline holds, at dispatch, the verification product of this very exchange"]
    THM_0052["THM-0052<br/>A dispatched body was released by the decision a configured policy produced"]
    THM_0053["THM-0053<br/>A presented admission assertion is authentic, in its window, and for this audience"]
    THM_0054["THM-0054<br/>Every production listener denies unknown client revocation status"]
    THM_0055["THM-0055<br/>The keyid derivation introduces no collisions of its own"]
    THM_0056["THM-0056<br/>The posture that claims nothing is produced only where no policy is configured"]
    THM_0057["THM-0057<br/>A client's trust anchors are the ones the current signed manifest published"]
    THM_0058["THM-0058<br/>A client accepts a response only under a signer its trust configuration authorizes"]
    THM_0059["THM-0059<br/>An unbound receipt is never a success and never another request's answer"]
    THM_0060["THM-0060<br/>The client's clock skew is bounded at construction and read once"]
    THM_0061["THM-0061<br/>A receipt that says nothing is not a receipt that says nothing ran"]
    THM_0062["THM-0062<br/>A response-signing credential exists only while a valid delegated key does"]
    THM_0063["THM-0063<br/>A signed response never advertises validity its credential does not authorize"]
    THM_0064["THM-0064<br/>A non-exporting custody selection keeps the private key off this process"]
    THM_0065["THM-0065<br/>An emitted bound response signature binds the request it answers"]
    THM_0066["THM-0066<br/>The serving PEP resolves actors through the deployment's materialized trust authority"]
    THM_0067["THM-0067<br/>The composition root re-reads no owner's security semantics from the request"]
    THM_0069["THM-0069<br/>A security record states each authority's outcome in that authority's own coordinate"]
    THM_0070["THM-0070<br/>The record stream is honest about what reached it"]
    THM_0071["ROOT — THM-0071<br/>Every reachable in-exchange refusal has a typed provenance that reaches the record"]
    THM_0073["THM-0073<br/>Serving materialization refuses a deployment whose two signing roles are one key"]
    THM_0074["ROOT — THM-0074<br/>No unearned dispatch"]
    THM_0075["ROOT — THM-0075<br/>No unearned response attribution"]
    THM_0076["ROOT — THM-0076<br/>A client accepts only an answer to its own request, under a signer it trusts"]
    THM_0077["ROOT — THM-0077<br/>No deployment serves a posture nobody selected"]
    THM_0078["ROOT — THM-0078<br/>Refusal is terminal, and no refusal-side effect reads as success"]
    THM_0079["THM-0079<br/>Distinct signed exchanges have distinct replay keys"]
    THM_0080["THM-0080<br/>Serving derives peer identity only from the credential the mechanism accepted"]
    THM_0081["THM-0081<br/>Every production refusal is inside the exchange lifecycle"]
    THM_0082["THM-0082<br/>The serving path signs under the credential source materialization produced"]
    THM_0083["THM-0083<br/>What a request is, is decided once, before anything reads it for meaning"]
    THM_0084["THM-0084<br/>The shipped client proxy verifies against the request it sent"]
    THM_0085["THM-0085<br/>Every exchange-owned refusal reaches the audit boundary, typed, before it is answered"]
    THM_0086["THM-0086<br/>The established replay tier is the selected one, and never a weaker substitute"]
    THM_0088["THM-0088<br/>A retention artefact reads as a crossing only for an exchange that crossed"]
    THM_0007 --> THM_0008
    THM_0010 --> THM_0009
    THM_0001 --> THM_0014
    THM_0007 --> THM_0015
    THM_0008 --> THM_0015
    THM_0014 --> THM_0015
    THM_0021 --> THM_0016
    THM_0022 --> THM_0017
    THM_0016 --> THM_0018
    THM_0021 --> THM_0019
    THM_0022 --> THM_0020
    THM_0001 --> THM_0021
    THM_0001 --> THM_0022
    THM_0023 --> THM_0024
    THM_0025 --> THM_0026
    THM_0026 --> THM_0027
    THM_0024 --> THM_0029
    THM_0028 --> THM_0029
    THM_0028 --> THM_0030
    THM_0029 --> THM_0031
    THM_0030 --> THM_0031
    THM_0028 --> THM_0032
    THM_0030 --> THM_0032
    THM_0031 --> THM_0033
    THM_0032 --> THM_0033
    THM_0031 --> THM_0034
    THM_0033 --> THM_0034
    THM_0035 --> THM_0036
    THM_0035 --> THM_0037
    THM_0035 --> THM_0038
    THM_0037 --> THM_0038
    THM_0039 --> THM_0040
    THM_0043 --> THM_0044
    THM_0040 --> THM_0045
    THM_0055 --> THM_0050
    THM_0015 --> THM_0051
    THM_0047 --> THM_0051
    THM_0040 --> THM_0052
    THM_0045 --> THM_0052
    THM_0056 --> THM_0052
    THM_0048 --> THM_0054
    THM_0016 --> THM_0058
    THM_0019 --> THM_0058
    THM_0057 --> THM_0058
    THM_0020 --> THM_0059
    THM_0022 --> THM_0059
    THM_0062 --> THM_0063
    THM_0021 --> THM_0065
    THM_0022 --> THM_0065
    THM_0037 --> THM_0066
    THM_0046 --> THM_0069
    THM_0046 --> THM_0071
    THM_0069 --> THM_0071
    THM_0070 --> THM_0071
    THM_0081 --> THM_0071
    THM_0085 --> THM_0071
    THM_0025 --> THM_0073
    THM_0027 --> THM_0073
    THM_0049 --> THM_0073
    THM_0003 --> THM_0074
    THM_0004 --> THM_0074
    THM_0005 --> THM_0074
    THM_0006 --> THM_0074
    THM_0009 --> THM_0074
    THM_0015 --> THM_0074
    THM_0034 --> THM_0074
    THM_0040 --> THM_0074
    THM_0043 --> THM_0074
    THM_0045 --> THM_0074
    THM_0050 --> THM_0074
    THM_0051 --> THM_0074
    THM_0052 --> THM_0074
    THM_0053 --> THM_0074
    THM_0066 --> THM_0074
    THM_0079 --> THM_0074
    THM_0080 --> THM_0074
    THM_0083 --> THM_0074
    THM_0022 --> THM_0075
    THM_0062 --> THM_0075
    THM_0063 --> THM_0075
    THM_0065 --> THM_0075
    THM_0082 --> THM_0075
    THM_0057 --> THM_0076
    THM_0058 --> THM_0076
    THM_0059 --> THM_0076
    THM_0060 --> THM_0076
    THM_0061 --> THM_0076
    THM_0084 --> THM_0076
    THM_0005 --> THM_0077
    THM_0013 --> THM_0077
    THM_0036 --> THM_0077
    THM_0038 --> THM_0077
    THM_0048 --> THM_0077
    THM_0049 --> THM_0077
    THM_0054 --> THM_0077
    THM_0064 --> THM_0077
    THM_0066 --> THM_0077
    THM_0067 --> THM_0077
    THM_0073 --> THM_0077
    THM_0086 --> THM_0077
    THM_0043 --> THM_0078
    THM_0044 --> THM_0078
    THM_0045 --> THM_0078
    THM_0046 --> THM_0078
    THM_0063 --> THM_0078
    THM_0069 --> THM_0078
    THM_0081 --> THM_0078
    THM_0088 --> THM_0078
    THM_0031 --> THM_0080
    THM_0033 --> THM_0080
    THM_0043 --> THM_0081
    THM_0046 --> THM_0081
    THM_0062 --> THM_0082
    THM_0064 --> THM_0082
    THM_0073 --> THM_0082
    THM_0046 --> THM_0085
    THM_0069 --> THM_0085
    THM_0081 --> THM_0085
    classDef root stroke-width:3px;
    class THM_0071,THM_0074,THM_0075,THM_0076,THM_0077,THM_0078 root;
```

## Component 2

```mermaid
graph BT
    THM_0002["THM-0002<br/>RFC 3339 parsing is total and range-bounded"]
```

## Component 3

```mermaid
graph BT
    THM_0012["ROOT — THM-0012<br/>The lifecycle record cannot claim a shutdown that did not happen"]
    classDef root stroke-width:3px;
    class THM_0012 root;
```

## Component 4

```mermaid
graph BT
    THM_0041["THM-0041<br/>An offline-verified receipt proves registration, and its root was never supplied"]
    THM_0068["THM-0068<br/>A pinned transparency service is one operator-reviewed document, or it is not a pin"]
    THM_0072["ROOT — THM-0072<br/>A verified receipt proves registration on the service this deployment pinned"]
    THM_0041 --> THM_0072
    THM_0068 --> THM_0072
    classDef root stroke-width:3px;
    class THM_0072 root;
```

## Component 5

```mermaid
graph BT
    THM_0042["ROOT — THM-0042<br/>Retained evidence is the evidence the statement was made about"]
    classDef root stroke-width:3px;
    class THM_0042 root;
```

## Component 6

```mermaid
graph BT
    THM_0087["THM-0087<br/>A continuation entry is reachable only by the actor the verifier resolved"]
```
