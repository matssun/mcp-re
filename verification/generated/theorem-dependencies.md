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

Which claims rest on which. Rendered as one diagram per connected component —
a single global diagram is unreadable at the size where it would matter.

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
    THM_0023 --> THM_0024
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
    THM_0028["THM-0028<br/>Channel-associated certificate credential evidence originates only from an established relationship's mechanism report"]
```
