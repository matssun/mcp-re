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
    THM_0007["THM-0007<br/>A typed artifact verifier admits only its own type"]
    THM_0008["THM-0008<br/>No untyped artifact binding leaves the verifier as verified"]
    THM_0014["THM-0014<br/>A successful request-floor verification establishes the cryptographic floor"]
    THM_0015["THM-0015<br/>A successful full-profile request verification establishes audience and artifact binding"]
    THM_0016["THM-0016<br/>A successful bound response-floor verification establishes trust-seam authorization of the signer"]
    THM_0017["THM-0017<br/>A successful unbound response-floor verification establishes trust-seam authorization and no request binding"]
    THM_0018["THM-0018<br/>A successful full bound response verification establishes block agreement with the expected handle"]
    THM_0019["THM-0019<br/>A successful delegated bound response verification establishes an accepted credential chain"]
    THM_0020["THM-0020<br/>A successful delegated unbound response verification establishes a chain and never a binding"]
    THM_0021["THM-0021<br/>A successful bound-response verification establishes the shared cryptographic and request-binding facts"]
    THM_0022["THM-0022<br/>A successful unbound-response verification establishes the shared facts and no request binding at all"]
    THM_0047["THM-0047<br/>The verifier's assurance products are not substitutable"]
    THM_0051["THM-0051<br/>The pipeline holds, at dispatch, the verification product of this very exchange"]
    THM_0057["THM-0057<br/>A client's trust anchors are the ones the current signed manifest published"]
    THM_0058["THM-0058<br/>A client accepts a response only under a signer its trust configuration authorizes"]
    THM_0059["THM-0059<br/>An unbound receipt is never a success and never another request's answer"]
    THM_0065["THM-0065<br/>An emitted bound response signature binds the request it answers"]
    THM_0007 --> THM_0008
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
    THM_0015 --> THM_0051
    THM_0047 --> THM_0051
    THM_0016 --> THM_0058
    THM_0019 --> THM_0058
    THM_0057 --> THM_0058
    THM_0020 --> THM_0059
    THM_0022 --> THM_0059
    THM_0021 --> THM_0065
    THM_0022 --> THM_0065
```

## Component 2

```mermaid
graph BT
    THM_0002["THM-0002<br/>RFC 3339 parsing is total and range-bounded"]
```

## Component 3

```mermaid
graph BT
    THM_0003["THM-0003<br/>Admission verdict integrity"]
```

## Component 4

```mermaid
graph BT
    THM_0004["THM-0004<br/>Admission anti-rollback"]
```

## Component 5

```mermaid
graph BT
    THM_0005["THM-0005<br/>Degraded admission requires deployment opt-in"]
```

## Component 6

```mermaid
graph BT
    THM_0006["THM-0006<br/>Presenter binding"]
```

## Component 7

```mermaid
graph BT
    THM_0009["THM-0009<br/>A presented continuation cannot bypass verification"]
    THM_0010["THM-0010<br/>Continuation handles match their presented inputs in role"]
    THM_0010 --> THM_0009
```

## Component 8

```mermaid
graph BT
    THM_0012["THM-0012<br/>The lifecycle record cannot claim a shutdown that did not happen"]
```

## Component 9

```mermaid
graph BT
    THM_0013["THM-0013<br/>No validated deployment enables online OCSP client-certificate revocation"]
```

## Component 10

```mermaid
graph BT
    THM_0023["THM-0023<br/>Every peer identity value is well-formed, whatever evidence produced it"]
    THM_0024["THM-0024<br/>Certificate identity interpretation reads the configured field and refuses rather than falling back"]
    THM_0028["THM-0028<br/>Channel-associated certificate credential evidence originates only from an established relationship's mechanism report"]
    THM_0029["THM-0029<br/>A channel-associated peer identity is interpreted from the leaf of that relationship's own credential"]
    THM_0030["THM-0030<br/>Verified-credential evidence records the mechanism's own acceptance and the path it was reached on"]
    THM_0031["THM-0031<br/>An authenticated relationship peer's identity is read from the leaf of the very credential the mechanism accepted for that relationship"]
    THM_0032["THM-0032<br/>Per-request credential currency is decided from the credential the mechanism accepted, and reports which of its five facts refused"]
    THM_0033["THM-0033<br/>A current authenticated peer's currency is evaluated against the credential that same peer authenticated with"]
    THM_0034["THM-0034<br/>A request is bound to its relationship by relating the authenticated peer to the resolved actor's SUBJECT, never to the composite actor id"]
    THM_0023 --> THM_0024
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
```

## Component 11

```mermaid
graph BT
    THM_0025["THM-0025<br/>Every canonical Ed25519 public key value is the canonical RFC 8410 encoding of its own point"]
    THM_0026["THM-0026<br/>Credential/key correspondence relates two independently interpreted keys and attributes every refusal to the side that failed"]
    THM_0027["THM-0027<br/>A delegated resolver's existence proves its credential and signer corresponded"]
    THM_0025 --> THM_0026
    THM_0026 --> THM_0027
```

## Component 12

```mermaid
graph BT
    THM_0035["THM-0035<br/>A successfully classified trust-revocation state carries the witnesses its own state form requires"]
    THM_0036["THM-0036<br/>A networked trust-epoch source is handed over as a paired locator and key, or not at all"]
    THM_0037["THM-0037<br/>A trust plan's reload cadence is a projection of the revocation posture, never a second value"]
    THM_0038["THM-0038<br/>The composition root consumes trust as owner projections and re-reads no trust field from the request"]
    THM_0035 --> THM_0036
    THM_0035 --> THM_0037
    THM_0035 --> THM_0038
    THM_0037 --> THM_0038
```

## Component 13

```mermaid
graph BT
    THM_0039["THM-0039<br/>An accepted PDP decision was authenticated under a key the trust seam resolved"]
    THM_0040["THM-0040<br/>An authorized request was permitted by a decision about that very request"]
    THM_0045["THM-0045<br/>The backend is reached only by consuming a fully assembled pre-dispatch commitment"]
    THM_0052["THM-0052<br/>A dispatched body was released by the decision a configured policy produced"]
    THM_0056["THM-0056<br/>The posture that claims nothing is produced only where no policy is configured"]
    THM_0039 --> THM_0040
    THM_0040 --> THM_0045
    THM_0040 --> THM_0052
    THM_0045 --> THM_0052
    THM_0056 --> THM_0052
```

## Component 14

```mermaid
graph BT
    THM_0041["THM-0041<br/>An offline-verified receipt proves registration, and its root was never supplied"]
```

## Component 15

```mermaid
graph BT
    THM_0042["THM-0042<br/>Retained evidence is the evidence the statement was made about"]
```

## Component 16

```mermaid
graph BT
    THM_0043["THM-0043<br/>The exchange relation is decided everywhere and the execution threshold partitions it"]
    THM_0044["THM-0044<br/>An exchange's retry consequence never under-reports what may have happened"]
    THM_0043 --> THM_0044
```

## Component 17

```mermaid
graph BT
    THM_0046["THM-0046<br/>A refusal carries which authority reached it, over a closed set, unrendered"]
```

## Component 18

```mermaid
graph BT
    THM_0048["THM-0048<br/>Every listener obtains its whole security posture through one listener state"]
    THM_0054["THM-0054<br/>Every production listener denies unknown client revocation status"]
    THM_0048 --> THM_0054
```

## Component 19

```mermaid
graph BT
    THM_0049["THM-0049<br/>Every illegal cross-owner configuration combination is refused at layer A"]
```

## Component 20

```mermaid
graph BT
    THM_0050["THM-0050<br/>Distinct verification keys have distinct keyids"]
    THM_0055["THM-0055<br/>The keyid derivation introduces no collisions of its own"]
    THM_0055 --> THM_0050
```

## Component 21

```mermaid
graph BT
    THM_0053["THM-0053<br/>A presented admission assertion is authentic, in its window, and for this audience"]
```

## Component 22

```mermaid
graph BT
    THM_0060["THM-0060<br/>The client's clock skew is bounded at construction and read once"]
```

## Component 23

```mermaid
graph BT
    THM_0061["THM-0061<br/>A receipt that says nothing is not a receipt that says nothing ran"]
```

## Component 24

```mermaid
graph BT
    THM_0062["THM-0062<br/>A response-signing credential exists only while a valid delegated key does"]
    THM_0063["THM-0063<br/>A signed response never advertises validity its credential does not authorize"]
    THM_0062 --> THM_0063
```

## Component 25

```mermaid
graph BT
    THM_0064["THM-0064<br/>A non-exporting custody selection keeps the private key off this process"]
```
