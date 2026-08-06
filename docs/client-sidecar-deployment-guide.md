# MCP-RE Client Sidecar Deployment Guide

**Audience:** an operator deploying `mcp-re-client`, the client-side ambassador — the
process that lets an ordinary MCP client speak the MCP-RE profile without implementing
any of it.

```text
local MCP client  --plain MCP/HTTP-->  mcp-re-client  --RFC 9421 + 9530 over mTLS-->  mcp-re-proxy
                  <--plain MCP--------                <--delegated-signed reply------
```

The pipeline is `mcp-re-client-proxy`'s and the mTLS leg is `mcp-re-transport`'s. What
the binary adds is the part a library cannot hold: process-lifetime state, and the
wiring that makes the ADR-MCPRE-052 trust-anchor lifecycle real in a deployment.

## Why a binary exists at all

`FileManifestFloor` and `load_signed_manifest_with_floor` had no caller outside tests.
The floor is the highest trust-anchor manifest version this verifier has ever accepted,
and its whole purpose is to survive a restart — so a library can *offer* one and only a
deployable can *keep* one. "Restart-durable rollback protection" was therefore a
property the test suite demonstrated and no deployment had.

Running this binary is what turns it on.

## Running it

```sh
mcp-re-client --config /etc/mcp-re/client.json     # serve
mcp-re-client --config /etc/mcp-re/client.json --check   # load config + anchors, then exit
```

`--check` performs the full startup path — configuration validation, the manifest load
against the floor, the mTLS material — and exits. Use it in a readiness probe or a
deploy gate; a client that cannot establish which roots it trusts must not take traffic.

The local listen port comes from [`config/ports.toml`](../config/ports.toml)
(`services.mcp_re_client`), never a retyped literal.

## The configuration document

One JSON file rather than a flag surface: a route carries an audience tuple, a list of
artifact bindings and a header set, and flattening that into repeated flags produces a
shape where one route's bindings can silently attach to another.

```json
{
  "local": {
    "bind": "127.0.0.1:8640",
    "default_route": "primary",
    "request_lifetime_secs": 60,
    "max_in_flight": 64
  },
  "identity": {
    "key_id": "did:example:agent#key-1",
    "signing_key_seed_path": "/etc/mcp-re/client.seed"
  },
  "remote": {
    "addr": "10.0.0.5:8600",
    "expected_server_name": "proxy.internal",
    "client_cert_path": "/etc/mcp-re/client.crt",
    "client_key_path": "/etc/mcp-re/client.key",
    "server_ca_path": "/etc/mcp-re/server-ca.crt"
  },
  "trust": {
    "manifest_path": "/etc/mcp-re/trust-anchors.json",
    "profile": "mcp-re-http-v1",
    "org_keys": [{ "kid": "org-admin-1", "public_key": "<base64url>" }],
    "floor": { "kind": "durable", "dir": "/var/lib/mcp-re/anchor-floor", "bootstrap_version": 7, "ceiling_version": 500 },
    "reload_secs": 300
  },
  "delegation": {
    "verifier_audiences": ["verifier-1"],
    "expected_audience_hash": "verifier-1",
    "accepted_epochs": ["epoch-1"],
    "max_clock_skew": 60
  },
  "routes": [
    {
      "route_id": "primary",
      "target_uri": "https://mcp.example.com/mcp?route=a",
      "audience": {
        "audience_id": "verifier-1",
        "target_uri": "https://mcp.example.com/mcp?route=a",
        "route": "a"
      },
      "extra_headers": [{ "name": "Authorization", "value": "Bearer <token>" }],
      "artifact_bindings": [
        { "artifact_type": "oauth-dpop", "source": { "kind": "header", "name": "Authorization" } }
      ]
    }
  ]
}
```

Unknown fields are a startup failure, not a silent default. A misspelled security switch
must never read as "off" while the operator believes it is on.

## Four defaults worth knowing

**The bind is loopback, and refusing is the default.** The local leg is unauthenticated
by construction — that is the point of a sidecar, the local client holds no key. So
anything that can reach the socket gets requests signed with this client's key, under
this client's identity, against every configured route. On loopback that set is
"processes on this host"; on `0.0.0.0` it is the network. Set
`local.allow_non_loopback` only where a deployment genuinely fronts this with its own
authenticated hop.

**A binding names a header rather than restating its value.** An OAuth-DPoP binding
whose digest covers one token while the `Authorization` header carries another is a
binding to nothing, and restating the value in two config fields is exactly how that
happens. `{"kind": "header", "name": "Authorization"}` digests the bytes the request
will actually carry; a route that binds a header it does not send is refused at startup.

**The floor has to be named.** `{"kind": "durable", "dir": ...}` keeps the accepted
version across restarts; `{"kind": "ephemeral"}` explicitly does not. Choosing is a
decision, not what you get by forgetting to choose — a client that silently got the
ephemeral floor would report the same posture as one with a durable floor while
providing none of it across the restart that matters.

Set `bootstrap_version` wherever the floor directory is not both persistent and better
protected than the manifest itself. It is a floor under the floor: whatever the
filesystem says, no manifest below it is ever accepted. Unlinking a directory is a
cheaper capability than corrupting a file, and an ephemeral volume loses it on every
restart, so without a bootstrap "the floor is gone" and "nothing has been accepted yet"
are indistinguishable to the code and very different in fact.

Set `ceiling_version` for the opposite direction. The markers are unauthenticated by
construction, so whoever can write the floor directory can create `18446744073709551615`
and pin the floor at `u64::MAX`, after which every later manifest — including a
break-glass revocation — is refused as stale. That is the TUF fast-forward attack, and
it is reachable by the cheapest write capability in the deployment.

A stored floor above the ceiling **stops the client** at
`FloorAboveCeiling { floor, ceiling }`. It does not clamp the floor down to the ceiling,
and it must not: that would lower a floor on the say-so of the storage that just proved
untrustworthy, silently re-opening the rollback window and letting the attacker choose
which versions come back by picking how far to overshoot.

Two consequences worth stating plainly. The ceiling is worth only the trust domain it
comes from — read from a file the floor-directory writer can also edit, it bounds
nothing, so it belongs wherever the org keys do. And it buys detection, not availability:
a malicious fast-forward still stops the client. It stops it at a named error an operator
can act on, instead of quietly withdrawing every anchor once the loaded manifest expires.

**A refresh keeps the last good anchors — except on expiry.** A truncated file or a
briefly-absent volume must not withdraw trust; dropping the anchors would turn a
transient read error into a total outage. An EXPIRED manifest is the one exception:
`load_signed_manifest` fails closed on expiry precisely so a stale trust picture is
never used, and "keep serving under the document that expired yesterday" is that same
stale picture reached by a different route. Past `expires_at` with nothing newer
accepted, the anchors are **withdrawn** — every response fails closed, the refresh keeps
retrying, and the log says so:

```text
trust-anchor manifest expired at 1700000100 and no newer one loaded — ANCHORS
WITHDRAWN, every response now fails closed
```

Publishing a fresh manifest restores service in place, with no restart.

## What revocation looks like in practice

The org publishes a manifest listing a compromised root under `revoked_issuers` and
bumps `manifest_version`. Within `reload_secs` the running client accepts it, swaps the
snapshot, and the next request fails closed with `mcp-re.delegation_revoked` — one
decisive action invalidating every descendant delegated credential, with no per-key
denylist entry and no restart.

Re-serving the older document does not undo it: the floor has already recorded the newer
version, so the rollback is refused and the anchors in force are kept.

## The local HTTP surface

`POST` and `Content-Length`, one exchange per connection, and nothing else. Chunked
bodies are refused rather than parsed, and a repeated `Content-Length` is rejected: this
socket is the trust boundary's inner face, and a framing bug here would let one local
caller's body be read as another's.

Address a route with `POST /route/<route_id>`, or configure `local.default_route` for
clients that POST to a fixed path.

Every reply carries `Mcp-Re-Verified-Kind`:

| Value | Meaning |
| --- | --- |
| `success` | a verified terminal success |
| `input-required` | a verified NON-terminal reply awaiting a signed answer leg |
| `accepted-notification` | a verified signed 202 — the boundary accepted a one-way message |
| `verified-rejection` | the server provably denied the request |

`input-required` is not a finished result. Reporting it as one is how an elicitation — a
human-approval round trip — reaches an application as a completed tool call, and the
application then acts on an approval nobody gave.

An **unverifiable** response is not a server verdict at all: the channel is compromised
or misconfigured, so it comes back as HTTP 502 with the frozen `mcp-re.*` reason under
`error.data.mcp_re_error.wire_code`, never as a result.

## Proofs

`//mcp-re-client:mcp_re_client_test` (config validation, the anchor loader and
refresher) and `//mcp-re-client:local_leg_e2e_test` — the shipped listener driven over a
real loopback socket against a real delegated-required server, including a published
revocation reaching an already-running listener and a replayed older manifest failing to
restore service.
