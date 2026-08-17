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
    THM_0007["THM-0007<br/>A typed artifact verifier admits only its own type"]
    THM_0008["THM-0008<br/>No untyped artifact binding leaves the verifier as verified"]
    THM_0007 --> THM_0008
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
