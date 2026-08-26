// SPDX-License-Identifier: Apache-2.0
//! The selector vocabulary a deployment request is written in.
//!
//! Each enum names the alternatives for one deployment question — where key material is
//! kept, whether admission is enforced, what the transport binds. They are the request's
//! own vocabulary rather than the CLI's: an option spelling maps ONTO one of these, and
//! nothing here knows that a command line exists. That is what lets the configuration
//! state model read a request without depending on the parser that usually builds one.
//!
//! Not every variant is a deployment a `ValidatedDeployment` can be in. [`BindingKind`]
//! has three the boundary refuses outright; they are input forms the model must be able to
//! REPRESENT in order to refuse, which is a different thing from admitting them.

/// Where key material is read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySourceKind {
    /// Files on disk (locations are paths).
    File,
    /// Environment variables (locations are variable names).
    Env,
    /// PKCS#11 token (issue #4034): the Ed25519 response-signing key lives on a
    /// hardware/software token and is exercised only via `C_Sign` — it never
    /// leaves the device. The TLS cert/key/CA still come from files in this
    /// build. Honored ONLY in a build with the `pkcs11_keysource` feature; a
    /// default build parses it but FAILS CLOSED at construction (mirrors `Env`).
    Pkcs11,
    /// AWS KMS (ADR-MCPS-028 §B): the Ed25519 response-signing key lives in AWS KMS
    /// and is exercised only via `Sign` — it never leaves KMS. The TLS cert/key/CA
    /// still come from files in this build (`--signing-key-seed` is accepted but
    /// UNUSED, as with `Pkcs11`). Credentials come from the standard AWS env vars.
    /// Honored ONLY in a build with the `aws_kms_keysource` feature; a default build
    /// parses it but FAILS CLOSED at construction (mirrors `Pkcs11`).
    AwsKms,
    /// GCP Cloud KMS (ADR-MCPS-028 §C): the Ed25519 response-signing key lives in
    /// Cloud KMS and is exercised only via `asymmetricSign`. TLS material is from
    /// files (`--signing-key-seed` accepted but UNUSED). The OAuth2 bearer comes
    /// from `MCP_RE_GCP_ACCESS_TOKEN` or the metadata server (`--gcp-kms-use-metadata`).
    /// Honored ONLY in a build with the `gcp_kms_keysource` feature; a default build
    /// parses it but FAILS CLOSED at construction.
    GcpKms,
}

/// Replay-cache backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionKind {
    /// Admission is not enforced. A call's admission binding, if it carries one, is
    /// verified evidence that decides nothing — the pre-MCPRE-493 behaviour.
    Off,
    /// Enforced when present. For a rollout that has not reached every client yet.
    Optional,
    /// Enforced always: a call with no admission evidence is refused. The only
    /// setting under which "every served call acted under a current admission" is a
    /// true statement about this deployment.
    Required,
}

/// Where the ADR-MCPS-035 per-request security record goes.
///
/// The record is the deployment's only per-request attribution surface: which actor
/// was admitted, which calls were refused and under exactly which frozen `mcp-re.*`
/// wire code. It is therefore ON unless a deployment names the opposite — the absent
/// case must not be the one that leaves an incident unreconstructable — and the
/// startup line states which posture is in force either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSinkKind {
    /// No per-request security record is emitted.
    None,
    /// One structured `key=value` line per decision on the proxy's stderr diagnostic
    /// channel — the same channel the startup lines and rotation warnings use.
    Stderr,
}

/// Whether the PEP writes its own verified context into the body forwarded to the
/// inner server (#415 rev 2 §10).
///
/// The caller-supplied reserved key is stripped either way; this selects only
/// whether the PEP's own context is then written in its place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedContextKind {
    /// Forward the stripped body with no verified context. The inner server makes no
    /// authorization decision on PEP-resolved identity.
    Disabled,
    /// Write the PEP's verified context into the forwarded body. Selecting this
    /// ASSERTS that nothing but this PEP can reach the inner server — the carrier is
    /// unsigned, so the channel is the only thing making it trustworthy, and no check
    /// here can confirm that property.
    Trusted,
}

/// Transport-binding policy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingKind {
    /// No transport binding (the mTLS identity is ignored).
    None,
    /// Exact match: request `signer` must equal the verified transport identity.
    Exact,
    /// ADR-MCPS-023 Tier 3 (issue #71): the verified transport identity comes from
    /// an LB-signed, request-bound ingress assertion (the node cryptographically
    /// verifies the LB tied the asserted client identity to THIS request hash),
    /// then binds exactly to the request signer. Honestly downgraded — NOT
    /// `end_to_end_mtls`. Requires at least one `--ingress-lb-key`.
    LbAssertion,
    /// ADR-MCPS-023 §C (v0.10) Mode C **attested ingress**: the verified transport
    /// identity comes from a controlled ingress attestor's request-bound
    /// `mcp-re/lb-ingress-assertion/v2` assertion, verified over the pinned
    /// attestor→node channel, then bound exactly to the request signer. Unlike
    /// `LbAssertion` (Mode B, strict-rejected) this is a strict-ADMITTED, explicit-
    /// opt-in posture — but it is *attested delegation*, NOT `end_to_end_mtls`: the
    /// load balancer witnesses proof-of-possession and stays in the trusted
    /// computing base. Requires `--ingress-attestor-key`, `--ingress-identity`,
    /// `--ingress-audience`, and the explicit `--ingress-pinned-mtls` acknowledgement.
    AttestedIngress,
}

/// ONLINE client-cert OCSP revocation selection (#4030). The online sibling of
/// the offline `--client-crl` posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspKind {
    /// No online OCSP check (the default). Revocation, if any, comes only from
    /// the offline `--client-crl` set.
    Off,
    /// Require an online OCSP check at connection time. A verified client leaf is
    /// rejected on `Revoked` (always) and, failing closed, on
    /// `Unknown`/unreachable/timeout/parse error too (there is no soft-fail
    /// relaxation). Honored ONLY in a build with the `online_ocsp` feature; a
    /// default build parses it but FAILS CLOSED at construction (mirrors the
    /// env-keysource / shared-replay gates).
    Require,
}

/// Authorization-policy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzKind {
    /// No authorization policy.
    Off,
    /// The reference signed-authorization profile.
    ///
    /// Retained and refused rather than deleted: it names the profile ADR-MCPRE-050's
    /// carrier change retired, and an operator who set it needs to be told that rather
    /// than told the flag is a typo.
    Reference,
    /// The carried PDP decision (ADR-MCPRE-065 §8) — the production authority.
    ///
    /// Selecting it is a claim that authorization is an ACTIVE control here, so a request
    /// carrying no applicable decision is refused (§7.1: `NoPolicyConfigured` is not
    /// available to a deployment that configured an authority). There is deliberately no
    /// permissive variant; a migration posture would be a separately named deployment
    /// posture with its own audit semantics, not a weaker reading of this one.
    PdpDecision,
}
