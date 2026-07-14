# Root-Authority (Master Key) Rotation (ADR-MCPRE-052 §H/§I)

A root key is not just key material — it is a **trust anchor**. Rotating it is a rare,
high-authority operation, unlike the frequent, automatic **delegated**-key rotation on
the hot path. This document separates the two mechanisms and records what is BUILT vs
what is DESIGN.

## Two rotations — do not conflate

| | Delegated response-signing key | Root / issuer / master key |
|---|---|---|
| Frequency | every ~5 min | rare (scheduled / break-glass) |
| Authority | signed by the root | signed by the org/admin manifest key |
| On the hot path | yes (signs each response) | no (issues credentials only) |
| Automation | fully automatic (rotor) | automated **but governed** |
| Status | built + proven (delegated-serving lanes) | verifier + manifest + tests BUILT; production controller DESIGN (below) |

## The trust-anchor set + signed manifest — BUILT

Root rotation has two jobs: select new key material (a KMS concern) and **distribute
trust in the new issuer safely**. The second is the hard one, and is done at the
verifier by two building blocks that are implemented and tested:

- [`TrustedIssuerSet`](../../mcp-re-client-core/src/response.rs) — the verifier's
  four-state trust anchor: **current** / **retiring** (accepted only until
  `valid_until`) / **revoked** (`delegation_revoked` immediately, before exp) /
  **unknown** (`delegation_issuer_untrusted`). Wired at the existing resolver seam;
  the pure credential verifier is unchanged. (§H, `root_key_lifecycle_test`.)
- [`TrustAnchorManifest`](../../mcp-re-client-core/src/trust_manifest.rs) — the
  **signed, versioned** document that distributes that set: `profile`,
  `manifest_version`, `current_issuers`, `retiring_issuers[valid_until]`,
  `revoked_issuers`, `issued_at`, `expires_at`. Signed by a pinned **org/admin**
  manifest-signing key (a higher authority than the issuer roots it lists), so an
  ordinary serving proxy cannot mint a new root authority. `load_signed_manifest`
  rejects an untrusted signer, a bad signature, an **expired** manifest (fail closed),
  and a **rollback** to a version below the highest already accepted; on success it
  yields a `TrustedIssuerSet`. (§I, `root_authority_manifest_test` +
  `trust_manifest.rs` unit tests.)

## Automated test provisioning — BUILT + fenced

Live tests must not require a human to create a KMS key per run. The
`TestRootAuthorityProvider` mints disposable roots (in-memory for CI); the live lane
provisions two **disposable** Cloud KMS Ed25519 key versions and runs the identical
rotation scenario against real KMS, via
[`docs/security/gcp-kms-root-rotation.sh`](../security/gcp-kms-root-rotation.sh). The
fence IS the governance for tests — the runner refuses unless
`MCP_RE_LIVE_KMS_TESTS=1` and `MCP_RE_ALLOW_TEST_KMS_CREATE=1`, the project is in an
allowlist, the keyring matches `mcps-test-*`, and the disposable key carries the
`mcps-live-test-*` prefix; a cleanup trap schedules the versions for destruction. It
NEVER touches the shared long-lived test root (`mcps-ed25519-object`). (GCP KMS keys /
keyrings cannot be deleted, only key VERSIONS destroyed after a 24h minimum — so the
disposable, empty key object remains, inert and unbilled.)

## Production governed controller — DESIGN (not built)

The mechanics of production root rotation should be automated, but the **authority
change** must have a control point — not a manual console ceremony, and not something an
ambient serving proxy can trigger. The intended controller:

```
mcp-re-admin rotate-root \
  --provider gcp-kms --keyring <ring> \
  --old-issuer-kid root-a --new-issuer-kid root-b --overlap 24h
```

1. create / select the new KMS root key (a **distinct `issuer_kid`**, even if the
   provider models it as a new version under one key);
2. fetch its public key;
3. publish a new **signed** `TrustAnchorManifest` (version bumped): new root
   `current`, old root `retiring` with `valid_until = now + overlap`;
4. switch the server's issuer to the new root (rotor issues under it);
5. keep clients accepting both roots through the overlap;
6. after `valid_until`, publish a manifest that drops the old root;
7. optionally schedule destruction/disable of the old key later.

Governance (design, not built):
- **scheduled** rotation → one explicit admin command / CI release approval;
- **emergency** compromise → break-glass command that immediately publishes a manifest
  with the old issuer `revoked` (the decisive action — invalidates all descendants at
  once), optionally two-person approval;
- every rotation is **audited** (who, when, old→new, overlap);
- the manifest signer (org/admin key) is itself high-value custody — offline root,
  threshold/admin approval, or a dedicated KMS key.

Distribution of the signed manifest starts as a **static file / config channel** and can
later move to a **signed remote feed / resolver** without changing the verifier — it
already consumes a `SignedTrustAnchorManifest`.

## Pre-GKE gate

The verifier trust-anchor lifecycle (§H) and the signed-manifest rotation with
auto-provisioned roots (§I) are green locally — hermetically on every push, and live
against real Cloud KMS via the fenced runner. That is the precondition the root-key
layer adds before a GKE run is treated as production validation. GKE then re-runs the
live cross-KMS rotation at fleet scale; it does not re-prove the protocol correctness,
which is this layer's job and is done locally. The production governed **controller**
(above) is the remaining DESIGN item and is deliberately not ambient-built — a
production authority change stays governed.
