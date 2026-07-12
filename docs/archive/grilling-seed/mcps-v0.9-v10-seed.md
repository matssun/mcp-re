# MCP-S v0.9/v0.10 hardening grill input: enterprise ingress, KMS/HSM custody, revocation, signed tool manifests

## Purpose

MCP-S v0.8 has established the core runtime-evidence profile: signed request, freshness, audience binding, authorization-evidence binding, signed response, request-hash binding, continuation evidence, fail-closed behavior, and conformance vectors.

The next question is not “add more MCP features.” The next question is whether MCP-S can offer a credible enterprise deployment profile without overclaiming the lean/default build.

## This document defines the gaps to grill before v0.9/v0.10

Enterprise reverse-proxy mTLS ingress hardening.
HSM/KMS-backed non-exportable key custody.
CRL/OCSP or equivalent certificate revocation checking.
Signed tool-manifest enforcement.

## Priority 1 items are deployment hardening. Priority 2 is protocol/product hardening

Google Cloud should be used as the first concrete test target because it has relevant managed primitives: Load Balancer mTLS, Cloud KMS / Cloud HSM, and Certificate Authority Service CRL publication. Google Cloud’s Application Load Balancer supports mTLS client authentication with REJECT_INVALID mode and can forward mTLS certificate details to a backend via custom headers. Cloud KMS supports asymmetric signing and public-key retrieval, including Ed25519 (EC_SIGN_ED25519), and keys have protection levels including software, HSM, and external key managers. Cloud HSM is fronted by Cloud KMS and uses FIPS 140-2 Level 3 certified HSM clusters. Google Certificate Authority Service supports CRL publication and publishes a new CRL daily plus within 15 minutes after a new certificate revocation.

## Executive decision to grill

The likely v0.9/v0.10 split should be:

v0.9:
  enterprise reverse-proxy mTLS ingress profile
  Google Cloud KMS / Cloud HSM signer profile
  signer lifecycle and trust-bundle revocation semantics

v0.10:
  certificate revocation profile if not completed in v0.9
  signed tool-manifest enforcement

The key question is whether certificate revocation can be delivered cleanly in v0.9 or whether it must be split. Google CA Service clearly supports CRLs, but we must verify where revocation checking actually happens: load balancer, MCP-S proxy, sidecar, or custom verifier. The Google mTLS docs show trust-chain validation and forwarded certificate metadata, but they do not, from the cited material alone, establish that the load balancer performs CRL/OCSP revocation checks for private CA certificates. That must be tested, not assumed.

### 1. Enterprise reverse-proxy mTLS ingress hardening

Problem

The lean MCP-S default must not claim enterprise ingress hardening. In enterprise deployments, MCP-S will often sit behind a reverse proxy, cloud load balancer, service mesh, or API gateway that terminates TLS/mTLS and forwards identity to the MCP-S backend.

The security risk is that forwarded identity becomes a spoofable header unless MCP-S knows:

- which ingress component is trusted;
- how the client certificate was validated;
- which identity fields were extracted;
- whether the backend connection from ingress to MCP-S is protected;
- whether MCP-S binds the forwarded identity into its evidence/policy path.

Google Cloud’s Load Balancer mTLS path is a good concrete test because it can reject invalid/missing client certificates using REJECT_INVALID, and it can pass certificate information to backend services through custom mTLS headers. The backend can receive fields such as certificate-present, chain-verified, certificate error, fingerprint, serial number, URI SANs, DNS SANs, issuer, subject, and certificate chain in forwarded headers.

Required design decision

MCP-S should define an Ingress Identity Profile:

Direct mode:
  MCP-S terminates mTLS itself and extracts peer identity.

Forwarded identity mode:
  trusted ingress terminates mTLS;
  ingress forwards verified certificate identity;
  MCP-S accepts forwarded identity only from configured trusted ingress;
  MCP-S binds forwarded identity into verification/audit/policy context.

Invalid mode:
  arbitrary X-Forwarded-* / custom identity headers from untrusted source are ignored/fail closed.
Questions for grilling
What exact headers or metadata does MCP-S accept in forwarded-identity mode?
How does MCP-S prove the request came from trusted ingress and not directly from a client spoofing headers?
Is the ingress-to-backend hop protected by mTLS, private network, signed headers, or all of these?
Is client_cert_chain_verified=true mandatory?
Is REJECT_INVALID mandatory for strict mode?
What identity is canonical: URI SAN, SPIFFE ID, DNS SAN, subject DN, fingerprint, or configured mapping?
Does the forwarded identity become part of the MCP-S signed preimage, authorization binding, audit record, or all three?
What happens if forwarded certificate metadata is missing, contradictory, or malformed?
What are the fail-closed error codes?
Can this be tested locally without Google Cloud, and then proven live with Google Cloud?
Proposed acceptance criteria

- Requests without trusted ingress provenance fail closed.
- Requests with spoofed identity headers fail closed.
- Requests with client_cert_chain_verified=false fail closed under strict profile.
- Requests with missing URI SAN / configured identity fail closed.
- Valid Google Cloud mTLS ingress forwards identity and MCP-S binds it into verified context.
- Audit log records ingress identity source, client certificate fingerprint, serial, URI SAN, trust mode, and route.
Google Cloud test plan

1. Create private CA / CA pool.
2. Issue client certificate with URI SAN.
3. Configure Google Cloud Application Load Balancer mTLS with TrustConfig.
4. Set client validation mode to REJECT_INVALID.
5. Forward selected mTLS custom headers to MCP-S backend.
6. Ensure direct backend access is impossible or rejected.
7. Send valid client cert: request accepted and identity bound.
8. Send missing cert: rejected by load balancer or MCP-S.
9. Send invalid cert: rejected.
10. Send spoofed forwarded headers directly to backend: rejected.
11. HSM/KMS-backed non-exportable key custody
Problem

The lean MCP-S default may use local/dev/file keys. That is acceptable for conformance and demos, but not for high-assurance production.

For enterprise deployment, private signing keys should not be raw files sitting beside the process. Signing should be delegated to a KMS/HSM-backed signer, and verifiers should use explicit trusted-signer / trusted-key-version policy.

Google Cloud is a strong target because Cloud KMS supports asymmetric signing and public-key retrieval, including Ed25519, and Cloud HSM can provide HSM-backed cryptographic operations through the Cloud KMS interface.

Required design decision

MCP-S should define a Key Custody Profile:

lean/dev:
  local software keys allowed;
  no high-assurance custody claim.

production baseline:
  configured signer identity;
  key rotation supported;
  trust bundle explicit;
  no TOFU under require_mcps.

high assurance:
  KMS/HSM-backed signing;
  private key non-exportable from application perspective;
  signer key version appears in evidence;
  IAM limits who/what may sign;
  key disable/destroy tested;
  verifier trust policy rejects revoked or unknown signer versions.
Important distinction

KMS prevents new signatures after key disable/destroy. It does not automatically make every verifier reject already cached public keys or already signed evidence. Google Cloud KMS key versions can be enabled, disabled, scheduled for destruction, or destroyed; disabled versions cannot be used, destroyed signing keys cannot create new signatures, and public keys for destroyed asymmetric versions are no longer available for download.

Therefore MCP-S still needs verifier-side policy:

- allowed signer ids;
- allowed key versions;
- revoked signer versions;
- max evidence age;
- rotation overlap window;
- fail-closed behavior when signer status cannot be resolved.
Questions for grilling
Does MCP-S evidence identify the KMS key version precisely enough?
Is key_id a stable MCP-S id, a KMS resource name, or a mapping?
Should verifiers call KMS live to fetch public keys/status, or use pinned trust bundles?
How do we avoid availability dependency on KMS for verification?
What is the rotation model?
What happens to evidence signed before key disable?
What happens to evidence signed after key disable?
How is emergency signer revocation distributed?
Should MCP-S support both Google Cloud KMS software and Cloud HSM protection levels?
Is Ed25519 the canonical Google Cloud profile, or should we also support P-256 because Google recommends P-256 generally for elliptic-curve signing? Google documents both Ed25519 and P-256, while listing P-256 as recommended in its general algorithm recommendations.
Proposed acceptance criteria
- MCP-S can sign request/response evidence using Google Cloud KMS.
- MCP-S can retrieve and pin the corresponding public key.
- Evidence includes signer id and key version.
- Disabling a KMS key version prevents new signatures.
- Verifier rejects evidence from a signer/key version removed from trust policy.
- Rotation works with old and new key versions during configured overlap.
- Unknown key version fails closed.
- KMS unavailable during signing fails closed.
- KMS unavailable during verification does not break if verifier has pinned trust bundle and status is fresh enough by policy.
Google Cloud test plan

1. Create Cloud KMS asymmetric signing key, initially software protection.
2. Repeat with HSM protection if region/quotas allow.
3. Wire MCP-S signer to call asymmetricSign.
4. Retrieve public key and configure verifier trust bundle.
5. Run ordinary four-hop signed request/response.
6. Rotate key version and verify overlap.
7. Disable old key version and assert new signatures fail with old version.
8. Remove old key version from MCP-S trust bundle and assert verifier rejects it.
9. Re-enable if needed for cleanup, then schedule destruction in a non-production test project.
10. Capture Cloud Audit Logs for KMS signing operations as supporting evidence.
11. Certificate revocation checking: CRL/OCSP or equivalent
Problem

This is separate from MCP-S message-signing key lifecycle.

There are two revocation domains:

MCP-S signing-key revocation:
  handled through KMS key-version lifecycle plus MCP-S trust policy.

mTLS certificate revocation:
  handled through PKI / CA / CRL / OCSP / short-lived certificates / ingress validation.

Google Certificate Authority Service supports certificate revocation and CRL publication. It can publish CRLs daily and within 15 minutes after a revocation, and revoked certificates appear in future CRLs until expiry.

But the key unresolved question is where revocation is checked in a Google Cloud mTLS deployment.

Required design decision

MCP-S should define a Certificate Revocation Profile with explicit modes:

none:
  certificate chain validation only; no revocation claim.

short-lived-cert mode:
  revocation risk bounded by certificate lifetime;
  no CRL/OCSP claim.

CRL mode:
  revocation checked against current CRL;
  stale/unavailable CRL policy explicit.

OCSP mode:
  revocation checked through OCSP/stapled OCSP if the deployment provides it.

delegated-ingress mode:
  ingress performs revocation checking;
  MCP-S records verified revocation status from trusted ingress.

backend-verifier mode:
  MCP-S or sidecar performs CRL/OCSP check itself.
Questions for grilling
Does Google Cloud Load Balancer mTLS validate CRLs from CA Service automatically, or only certificate chain/trust config?
If the load balancer does not check revocation, should MCP-S implement CRL checking itself?
Should revocation checking happen in MCP-S core, an ingress sidecar, or deployment glue?
What is strict behavior if CRL fetch fails?
Is fail-open ever acceptable? Probably only degraded mode.
What CRL freshness window is allowed?
Can we use short-lived certificates instead of CRL/OCSP for v0.9?
Is OCSP actually available in the Google Cloud private CA path, or should the Google profile be CRL-only?
How is revocation status captured in audit evidence?
How do we test revoked-certificate rejection end-to-end?
Proposed acceptance criteria

- A certificate revoked in CA Service is rejected by the chosen revocation-checking layer.
- A stale CRL fails closed under strict profile.
- Revocation-check unavailable fails closed under strict profile.
- Revocation status and CRL timestamp are audited.
- The README clearly states whether the Google profile is CRL-based, OCSP-based, short-lived-cert-based, or delegated to ingress.
Google Cloud test plan

1. Enable CRL publication before issuing test certificates.
2. Issue valid client certificate.
3. Confirm valid mTLS request succeeds.
4. Revoke certificate in CA Service.
5. Wait for out-of-band CRL publication window.
6. Test whether Google Cloud Load Balancer rejects the revoked cert.
7. If not, implement backend/sidecar CRL check using forwarded serial/fingerprint/cert chain.
8. Assert revoked cert fails under strict mode.
9. Assert stale/unavailable CRL fails closed.
10. Document exact Google behavior, not assumed behavior.
11. Signed tool-manifest enforcement
Problem

MCP-S currently proves that a concrete call happened with signed runtime evidence. It does not necessarily prove that the tool surface itself was approved.

Without signed manifests, an attacker or compromised server could potentially expose a changed tool list/schema. MCP-S may still secure the runtime call, but the policy engine may have made decisions against a different assumed tool surface.

This is not a v0.8 blocker, but it is a natural v0.10 hardening item.

Required design decision

MCP-S should define a Tool Manifest Binding Profile:

Tool manifest:
  tool names;
  schemas;
  descriptions if policy-relevant;
  version;
  server identity;
  route/audience;
  manifest issuer;
  digest;
  signature.

Runtime call:
  binds to manifest digest or approved tool identity;
  verifier/policy checks that tool call is covered by an approved manifest.
Questions for grilling
What exactly is signed: raw MCP tools/list output, normalized manifest, or operator-authored manifest?
Do descriptions count as security-relevant?
How do we avoid reopening the canonicalization/preimage problem?
Is this another binding artifact like authorization binding?
Who signs manifests: server developer, operator, MCP-S proxy, or policy authority?
Does runtime evidence include tool_manifest_digest?
How are manifest rotations handled?
What happens if the server exposes a tool not in the signed manifest?
What happens if schema changes but name stays the same?
How does this compose with dynamic tools?
Proposed acceptance criteria

- A tool call can be bound to an approved signed manifest digest.
- Tool not present in manifest fails closed under manifest-enforced route policy.
- Tool schema mismatch fails closed.
- Manifest signer is distinct from runtime server signer if needed.
- Manifest digest appears in audit record.
- Dynamic tools require either explicit degraded mode or a dynamic-manifest profile.
Suggested design stance

Do not make MCP-S interpret tool semantics.

Use the same principle as authorization binding:

MCP-S binds the manifest artifact.
Policy decides whether the manifest authorizes the tool surface.

If the manifest is opaque bytes, hash the exact bytes. If it has a native digest/reference, bind that. If MCP-S is expected to hash a structured tool manifest itself, create an explicit manifest canonicalization profile.

Proposed v0.9/v0.10 sequencing
v0.9 candidate
ADR-MCPS-048: Enterprise Ingress Identity Profile
ADR-MCPS-049: KMS/HSM Key Custody and Signer Lifecycle Profile
Google Cloud live proof:
  Load Balancer mTLS
  forwarded identity binding
  Cloud KMS / Cloud HSM signing
  key rotation/disable test

This gives the strongest enterprise story quickly.

v0.10 candidate
ADR-MCPS-050: Certificate Revocation Profile
ADR-MCPS-051: Signed Tool Manifest Binding

Certificate revocation may move into v0.9 if the Google Cloud test proves it is straightforward. Signed tool manifests should probably stay v0.10 because it is closer to protocol/policy design and risks reopening canonicalization questions.
