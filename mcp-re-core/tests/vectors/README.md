# MCP-RE conformance vectors (MCPS-002)

These JSON files are the **executable specification** for the MCP-RE security
profile. They are regenerated against the **frozen** wire vocabulary (MCP_RE_SPEC
§2) with **real Ed25519 crypto** — the stale planning-brief field names
(`actor` / `capability_hash` / `server_actor` / `trust_label`) are NOT used.

## Fixed, documented test keypairs (NEVER random — vectors are reproducible)

| Role   | Seed (32 bytes) | `key_id`       | signer identity            |
| ------ | --------------- | -------------- | -------------------------- |
| Client | `[1u8; 32]`     | `key-1`        | `did:example:agent-1`      |
| Server | `[2u8; 32]`     | `server-key-1` | `did:example:server-1`     |

Other fixed envelope fields:

- `audience`      = `did:example:server-1`
- `on_behalf_of`  = `did:example:user-1`
- `nonce`         = `Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA`
- `issued_at` / `expires_at` (valid window) = `2026-05-28T20:00:00Z` / `...20:05:00Z`
- response `issued_at` = `2026-05-28T20:00:01Z`
- `authorization_hash` = `sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o`

The resolver public keys (Base64URL-no-pad) are recorded in each OK fixture's
`resolver.public_key_b64url` and are derived deterministically from the seeds.

## Fixture schema

Each file records:

- `name`              — vector name.
- `kind`              — `request` | `response` | `raw`.
- `message`           — the canonical JSON-RPC object (for `request`/`response`).
- `raw_text`          — raw JSON string (for UTF-8 `raw` cases, e.g. JCS-01..06/08).
- `raw_bytes_b64url`  — Base64URL-no-pad raw bytes (for non-UTF-8 `raw`, e.g. JCS-07).
- `expected`          — `verify_ok` or an exact `mcp-re.*` error token (MCP_RE_SPEC §8).
- `resolver`          — `{ signer_key: "signer#key_id", public_key_b64url }` where relevant.
- `requires_pipeline` — `true` when asserting the OUTCOME needs the full verify
  pipeline (MCPS-008, Phase 2). Phase-1 tests only structurally validate these;
  MCPS-008 / MCPS-010 consume them for outcome assertions.

`manifest.json` lists every fixture in THIS directory (`name`, `file`, `kind`,
`expected`, `requires_pipeline`). The cross-component conformance corpus (these
Core vectors + the Phase 5 authorization vectors) and the full set of
`//...` Bazel test targets are enumerated, with derived counts,
in `mcp-re-conformance/conformance_manifest.json` — the single
source of truth, drift-guarded by
`//mcp-re-conformance:drift_guard_test` (MCPS-031). Do not quote a
fixed vector/target count in prose; cite the manifest.

## Regenerating

The generator + all assertions live in `../vectors_test.rs`. The `golden_*`
tests fail CI on any drift between the committed files and the regenerated
vectors. To intentionally regenerate (the only writer), run locally:

```
cargo test -p mcp-re-core --test vectors_test write_fixtures -- --ignored --exact
```

The canonical gate is `bazel test //...` (the Bazel test embeds
these files at compile time via `include_str!`).

## `requires_pipeline` (deferred to MCPS-008)

These fixtures are created now with the correct `expected` token but their
outcome is asserted by the Phase-2 pipeline, not here:
`v4b_signed_wrong_hash_response`, `replay_request`, `expired_request`,
`wrong_audience_request`, `missing_envelope_request`, `batch`,
`security_notification`, `unknown_envelope_field`.
