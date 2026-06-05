<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-MCPS-009: Fail-Closed Message Constraints — Batch, Notification, Unknown-Field Rejection

## Status

Accepted

## Context

Derived from PRD. MCP-S Core aims for a narrow, deterministic, fail-closed surface. JSON-RPC permits batch messages and notifications, and the MCP-S envelope could carry unknown fields; each is a potential ambiguity or downgrade vector (open decision #18.2). These constraints together define which message shapes Core will accept.

## Decision

MCP-S Core rejects all JSON-RPC batch messages (`mcps.batch_forbidden`), forbids security-relevant notifications — requiring any operation with security consequences (tool execution, resource/prompt access, state mutation, security-relevant context expansion) to use an id-bearing JSON-RPC request (`mcps.notification_forbidden`) — and rejects unknown fields inside the MCP-S envelope (`mcps.unknown_envelope_field`), all fail-closed.

## Rationale

Batch signing/verification semantics are undefined and are deferred to a future profile. Notifications have no `id`, so a verification failure cannot be returned deterministically; security-consequential operations must therefore be requests. Rejecting unknown envelope fields prevents silent extension and downgrade; a reserved `extensions: {}` object is the sanctioned future growth point so that genuine extensions are explicit rather than smuggled.

## Alternatives Considered

- **Allow batches now**: rejected — signing semantics for batches are not defined in Core.
- **Allow unknown envelope fields**: rejected — enables silent downgrade and cross-implementation ambiguity.
- **Permit security-relevant notifications**: rejected — no deterministic way to return a verification failure without an `id`.

## Consequences

### Positive
- A deterministic, narrow, fail-closed accepted-message surface.

### Negative
- Deployments that rely on batching must wait for a future Batch profile.

### Neutral
- Non-mutating notifications remain permissible where local policy allows; `extensions: {}` is reserved for negotiated future fields.

## Compliance and Enforcement

Conformance batch-rejection, notification-rejection, and unknown-envelope-field vectors. Fail-closed verification path.

## Related

- PRD: (author's private monorepo)
- Siblings: ADR-MCPS-007 (error taxonomy additions), ADR-MCPS-005 (fail-closed canonicalization)
