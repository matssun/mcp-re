//! The production `mcp-re-proxy` command line: argv to a [`DeploymentRequest`].
//!
//! One authority lives here — reading an argument list — and it is three collaborating
//! parts, in pipeline order:
//!
//! - [`Flags`], the accumulator, and its routing table: each flag is dispatched to the one
//!   family that owns its meaning. The families are the `cli::*_flags` children.
//! - [`refused_or_unknown`], the answer for a flag no family owns, including the one
//!   spelling recognised only to refuse it.
//! - [`parse_args`], which composes the families' products into a request and hands it to
//!   the layer-A boundary.
//!
//! Nothing here decides deployment legality. Whether the deployment a coherent command line
//! describes may RUN is
//! [`crate::config_state::validation::ValidatedDeployment`]'s, and materializing a
//! validated deployment into runtime capabilities belongs to each capability's owner
//! (ADR-MCPRE-067 Phase 8) — so any other way of building a request reaches the same
//! answer.
//!
//! The request model itself is [`crate::deployment_request`], deliberately outside this
//! module: the configuration state machines read a request without depending on the parser.

mod admission_flags;
mod audit_flags;
mod authorization_flags;
mod channel_flags;
mod currency_flags;
mod delegated_signing_flags;
mod identity_flags;
mod peer_identity_flags;
mod protocol_flags;
mod revocation_flags;
mod runtime_flags;
mod serving_flags;
mod signing_source_flags;
mod storage_flags;

use crate::deployment_request::DeploymentRequest;

/// Every flag family this parser knows, accumulating across one argument list.
///
/// The CLI is an adapter (ADR-MCPRE-067 §16): a command line is flat, and each family reads
/// the flat spelling its operator types and hands back one typed semantic value. Nothing
/// here decides legality beyond argv coherence — whether the deployment a coherent command
/// line describes may RUN is the configuration boundary's, and the answer is the same
/// however the request was built.
#[derive(Default)]
struct Flags {
    identity: identity_flags::IdentityFlags,
    protocol: protocol_flags::ProtocolFlags,
    serving: serving_flags::ServingFlags,
    runtime: runtime_flags::RuntimeFlags,
    channel: channel_flags::ChannelFlags,
    signing_source: signing_source_flags::SigningSourceFlags,
    peer_identity: peer_identity_flags::PeerIdentityFlags,
    revocation: revocation_flags::RevocationFlags,
    storage: storage_flags::StorageFlags,
    currency: currency_flags::CurrencyFlags,
    admission: admission_flags::AdmissionFlags,
    authorization: authorization_flags::AuthorizationFlags,
    audit: audit_flags::AuditFlags,
    delegated_signing: delegated_signing_flags::DelegatedSigningFlags,
}

impl Flags {
    /// Route one valueless flag to the family that owns it, reporting whether one did.
    fn take_switch(&mut self, flag: &str) -> bool {
        self.signing_source.take_switch(flag)
            || self.serving.take_switch(flag)
            || self.peer_identity.take_switch(flag)
    }

    /// Route one value-taking flag to the family that owns it.
    ///
    /// One line per family, and the families are disjoint: a flag belongs to exactly one,
    /// so this is a routing table and not a decision.
    fn take(&mut self, flag: &str, value: &str) -> Result<(), String> {
        if identity_flags::IdentityFlags::owns(flag) {
            self.identity.take(flag, value);
        } else if serving_flags::ServingFlags::owns(flag) {
            self.serving.take(flag, value);
        } else if protocol_flags::ProtocolFlags::owns(flag) {
            self.protocol.take(flag, value)?;
        } else if runtime_flags::RuntimeFlags::owns(flag) {
            self.runtime.take(flag, value)?;
        } else if channel_flags::ChannelFlags::owns(flag) {
            self.channel.take(flag, value)?;
        } else if signing_source_flags::SigningSourceFlags::owns(flag) {
            self.signing_source.take(flag, value)?;
        } else if peer_identity_flags::PeerIdentityFlags::owns(flag) {
            self.peer_identity.take(flag, value)?;
        } else if revocation_flags::RevocationFlags::owns(flag) {
            self.revocation.take(flag, value)?;
        } else if storage_flags::StorageFlags::owns(flag) {
            self.storage.take(flag, value)?;
        } else if currency_flags::CurrencyFlags::owns(flag) {
            self.currency.take(flag, value)?;
        } else if admission_flags::AdmissionFlags::owns(flag) {
            self.admission.take(flag, value)?;
        } else if authorization_flags::AuthorizationFlags::owns(flag) {
            self.authorization.take(flag, value)?;
        } else if audit_flags::AuditFlags::owns(flag) {
            self.audit.take(flag, value)?;
        } else if delegated_signing_flags::DelegatedSigningFlags::owns(flag) {
            self.delegated_signing.take(flag, value)?;
        } else {
            return Err(refused_or_unknown(flag));
        }
        Ok(())
    }

    /// The request this command line describes.
    ///
    /// One line per semantic field. Each family answered its own question already, so this
    /// composes products rather than reading values — there is no decision here to hide in
    /// a large literal, because every decision was made one layer down.
    fn finish(self) -> Result<DeploymentRequest, String> {
        let identity = self.identity.finish()?;
        let protocol = self
            .protocol
            .finish(mcp_re_http_profile::VerifierPolicy::DEFAULT_MAX_CLOCK_SKEW)?;
        let serving = self.serving.finish()?;
        let runtime = self.runtime.finish();
        let mut currency = self.currency;
        let storage = self.storage.finish()?;
        currency.take_epoch(storage.trust_epoch);
        // #59/#60/#61: which custody holds the channel key is one tagged value, and the
        // signing-source family assembles it — including the argv contradiction of naming
        // both arms, which no request can carry any more.
        let (response_signing, channel_key) = self.signing_source.finish()?;
        let channel = self.channel.finish(
            channel_key,
            Some(crate::config_state::transport::MAX_CLIENT_CERT_LIFETIME),
        )?;
        let audit = self.audit.finish();
        Ok(DeploymentRequest {
            bind: serving.bind,
            audience: identity.audience,
            server_signer: identity.server_signer,
            server_key_id: identity.server_key_id,
            max_clock_skew: protocol.max_clock_skew,
            mcp_protocol_versions: protocol.versions,
            target_uri: protocol.target_uri,
            trust_domain: identity.trust_domain,
            route: serving.route,
            response_signing,
            channel_credential: channel.credential,
            peer_trust_anchors: channel.peer_trust_anchors,
            max_client_cert_lifetime: channel.max_client_cert_lifetime,
            peer_revocation: self.revocation.finish()?,
            peer_identity: self.peer_identity.finish()?,
            trust_path: serving.trust_path,
            inner_http_urls: serving.inner_http_urls,
            fleet: serving.fleet,
            allow_group_readable_key_files: serving.allow_group_readable_key_files,
            cores: runtime.cores,
            workers_per_shard: runtime.workers_per_shard,
            in_flight_limit: runtime.in_flight_limit,
            limits: runtime.limits,
            replay: storage.replay,
            continuation_control: storage.continuation,
            request_signer_currency: currency.finish()?,
            admission: self.admission.finish()?,
            authorization: self.authorization.finish(),
            audit_sink: audit.sink,
            retained_evidence_dir: audit.retained_evidence_dir,
            verified_context: audit.verified_context,
            delegated_signing: self.delegated_signing.finish(
                crate::config_state::delegated_signing::DEFAULT_DELEGATED_TTL_SECS,
                crate::config_state::delegated_signing::DEFAULT_DELEGATED_OVERLAP_SECS,
            ),
        })
    }
}

/// A flag no family owns.
///
/// One spelling is recognised only to REFUSE it with the reason and the replacement.
/// Falling through to "unknown flag" would be a worse error for the one operator who most
/// needs to understand what changed — and worse, it would report a secret-handling decision
/// as a typo.
fn refused_or_unknown(flag: &str) -> String {
    if flag == "--pkcs11-pin" {
        // The PIN has already been exposed at this point (it is in this process's argv,
        // which is world-readable): the refusal is about not making it a standing exposure,
        // and the operator should treat that PIN as compromised and change it.
        return "--pkcs11-pin is refused: a process command line is world-readable \
                (ps, /proc/<pid>/cmdline), so the PIN unlocking the token that holds the \
                signing keys would be published to every local user for the lifetime of the \
                process. Use --pkcs11-pin-file <path> with a 0600 file. Treat any PIN \
                previously passed this way as compromised."
            .to_string();
    }
    format!("unknown flag {flag}")
}

/// A required value, or the flag that would have supplied it.
fn require(value: Option<String>, flag: &str) -> Result<String, String> {
    value.ok_or_else(|| format!("missing required {flag}"))
}

/// Parse CLI arguments (excluding argv[0]) into a [`DeploymentRequest`]. Returns a
/// human-readable error string on any missing/invalid argument.
///
/// Orchestration: read the argument list into the flag families, then ask them for the
/// request they describe. Both halves are one line each, because every flag's grammar lives
/// with the family that owns its meaning (ADR-MCPRE-067 §16, Phase 7).
pub fn parse_args(args: &[String]) -> Result<DeploymentRequest, String> {
    let mut flags = Flags::default();
    let mut i = 0usize;
    #[allow(clippy::arithmetic_side_effects)] // class C: every read of `args` is a `get`
    while let Some(flag) = args.get(i).map(String::as_str) {
        if flags.take_switch(flag) {
            i += 1;
            continue;
        }
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("flag {flag} requires a value"))?;
        flags.take(flag, value)?;
        i += 2;
    }
    // Whether the deployment this argument list describes is one that may run is not the
    // parser's question, and the answer is the same however the request was built. Every
    // violation is reported, not the first — a command line missing four things is worth
    // one pass, not four.
    crate::config_state::validation::ValidatedDeployment::try_from(flags.finish()?)
        .map(crate::config_state::validation::ValidatedDeployment::into_inner)
}

#[cfg(test)]
mod tests {
    use super::parse_args;
    use super::DeploymentRequest;
    use crate::config_state::validation::unsafe_config_violations;
    use crate::deployment_request::AuditSinkKind;
    use crate::deployment_request::AuthzKind;
    use crate::deployment_request::{
        AwsKmsSigningSourceRequest, GcpKmsSigningSourceRequest, Pkcs11SigningSourceRequest,
        SigningSourceRequest,
    };
    use crate::transport::IdentityPolicy;

    /// The full, valid set of Mode-C flags (attestor key + ingress identity +
    /// audience + pinned-mTLS ack). Prepend `--strict`/etc. as needed.
    fn attested_ingress_flags() -> Vec<String> {
        args(&[
            "--transport-binding",
            "attested-ingress",
            "--ingress-attestor-key",
            &format!("attestor-1:{}", attestor_pub_b64()),
            "--ingress-identity",
            "spiffe://example.org/ingress-1",
            "--ingress-audience",
            "did:example:server-1",
            "--ingress-pinned-mtls",
        ])
    }
    /// A distinct valid Ed25519 public key for `--ingress-attestor-key`.
    fn attestor_pub_b64() -> String {
        mcp_re_core::SigningKey::from_seed_bytes(&[9u8; 32])
            .public_key()
            .to_b64url()
    }
    /// A Mode-C form over the standard fixture attestor. A literal rather than a helper on
    /// the request type: the pinned-channel acknowledgement is the point, and a constructor
    /// that supplied it silently would hide what the form rests on.
    fn mode_c_form(
        identities: Vec<String>,
        audience: String,
    ) -> crate::deployment_request::PeerIdentityEvidenceRequest {
        crate::deployment_request::PeerIdentityEvidenceRequest::AttestedIngress(
            crate::deployment_request::AttestedIngressRequest {
                asserted_identity_kind: IdentityPolicy::UriSan,
                attestor_keys: vec![("attestor-1".to_string(), attestor_pub_b64())],
                identities,
                audience,
                pinned_channel:
                    crate::deployment_request::PinnedChannelAcknowledgement::acknowledged(),
            },
        )
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// The PKCS#11 payload a parse produced, or a panic naming what it produced instead.
    ///
    /// Reading the selection through a match rather than through a `key_source` field
    /// beside it IS the property under test: the mechanism and its material are one value.
    fn token_payload(config: &DeploymentRequest) -> &Pkcs11SigningSourceRequest {
        match &config.response_signing.source {
            SigningSourceRequest::Pkcs11(token) => token,
            other => panic!("expected a PKCS#11 selection, got {other:?}"),
        }
    }

    /// The AWS KMS payload a parse produced.
    fn aws_payload(config: &DeploymentRequest) -> &AwsKmsSigningSourceRequest {
        match &config.response_signing.source {
            SigningSourceRequest::AwsKms(kms) => kms,
            other => panic!("expected an AWS KMS selection, got {other:?}"),
        }
    }

    /// The GCP Cloud KMS payload a parse produced.
    fn gcp_payload(config: &DeploymentRequest) -> &GcpKmsSigningSourceRequest {
        match &config.response_signing.source {
            SigningSourceRequest::GcpKms(kms) => kms,
            other => panic!("expected a GCP Cloud KMS selection, got {other:?}"),
        }
    }

    /// The delegated channel key object a parse produced, if any.
    fn channel_key(
        config: &DeploymentRequest,
    ) -> Option<&crate::deployment_request::DelegatedChannelKeyRequest> {
        match &config.channel_credential.key {
            crate::deployment_request::ChannelKeyRequest::Delegated(delegated) => Some(delegated),
            crate::deployment_request::ChannelKeyRequest::ExportedFile(_) => None,
        }
    }

    /// The admission-limit request holds `NonZeroUsize`, because both flags refuse 0.
    fn nz(v: usize) -> std::num::NonZeroUsize {
        std::num::NonZeroUsize::new(v).expect("the fixture states a non-zero limit")
    }

    // ---- KMS endpoint override validation (C054) --------------------------

    /// Parse `minimal()` plus one KMS endpoint override.
    fn with_kms_endpoint(flag: &str, endpoint: &str) -> Result<super::DeploymentRequest, String> {
        let mut a = minimal();
        // `minimal()` omits --replay-cache, which `unsafe_config_violations` refuses; that
        // refusal is unrelated to endpoint validation and would mask an accept case.
        a.extend(args(&[
            "--replay-redis-url",
            "redis://127.0.0.1:6379",
            "--replay-durability-tier",
            "redis-wait-quorum:1:100",
        ]));
        a.push(flag.to_string());
        a.push(endpoint.to_string());
        parse_args(&a)
    }

    #[test]
    fn an_https_kms_endpoint_is_accepted() {
        for flag in ["--aws-kms-endpoint", "--gcp-kms-endpoint"] {
            let r = with_kms_endpoint(flag, "https://kms.example.internal");
            assert!(r.is_ok(), "{flag} must accept https, got {:?}", r.err());
        }
    }

    /// The emulator lane (LocalStack et al.) must keep working: plaintext to LOOPBACK
    /// cannot carry a credential off the machine.
    #[test]
    fn a_loopback_http_kms_endpoint_is_accepted_for_emulators() {
        for endpoint in [
            "http://localhost:4566",
            "http://127.0.0.1:4566/",
            "http://[::1]:4566",
        ] {
            assert!(
                with_kms_endpoint("--aws-kms-endpoint", endpoint).is_ok(),
                "{endpoint} is a loopback emulator and must be accepted"
            );
        }
    }

    /// The finding: plaintext to a NON-loopback host hands a live GCP workload-identity
    /// bearer token to that host and lets it serve the root verify key the whole
    /// verify-before-return guardrail is measured against.
    #[test]
    fn a_plaintext_kms_endpoint_to_a_remote_host_is_refused() {
        for flag in ["--aws-kms-endpoint", "--gcp-kms-endpoint"] {
            let err = with_kms_endpoint(flag, "http://kms.attacker.test")
                .expect_err("plaintext to a remote host must be refused");
            assert!(
                err.contains("loopback"),
                "the refusal must name the loopback exception, got {err:?}"
            );
        }
    }

    #[test]
    fn a_non_http_kms_endpoint_scheme_is_refused() {
        for endpoint in ["file:///etc/passwd", "kms.example.internal", "ftp://x.test"] {
            assert!(
                with_kms_endpoint("--gcp-kms-endpoint", endpoint).is_err(),
                "{endpoint} is not an absolute http(s) URL and must be refused"
            );
        }
    }

    #[test]
    fn a_kms_endpoint_with_no_host_is_refused() {
        for endpoint in ["https://", "http:///v1", "https:///"] {
            assert!(
                with_kms_endpoint("--aws-kms-endpoint", endpoint).is_err(),
                "{endpoint} has no authority and must be refused"
            );
        }
    }

    /// The same property one layer out: a host that is not a LITERAL name or address is
    /// read by a URL parser as some other host than the text shows — IDNA punycodes it,
    /// percent-encoding decodes it, a backslash or a stripped tab moves where the authority
    /// ends.
    #[test]
    fn a_kms_endpoint_host_that_is_not_a_literal_is_refused() {
        for endpoint in [
            // url 2.5.8 punycodes this to xn--example-4fg.com (the 'а' is Cyrillic).
            "https://exa\u{0430}mple.com",
            "https://cloudkms.googleapis.com%40evil.example.com",
            "https://cloudkms.googleapis.com\\@evil.example.com",
            "https://cloudkms.googleapis.com\t@evil.example.com",
            // A FULLWIDTH digit three: not a port any parser will read as 443.
            "https://cloudkms.googleapis.com:44\u{FF13}",
            "https://cloudkms.googleapis.com:notaport",
            "https://cloudkms.googleapis.com?x=1",
            "https://cloudkms.googleapis.com#frag",
        ] {
            assert!(
                with_kms_endpoint("--gcp-kms-endpoint", endpoint).is_err(),
                "{endpoint:?} does not name a literal host and must be refused"
            );
        }
    }

    /// `minimal()` with the exported channel key removed, for a command line that names a
    /// DELEGATED one. The two are the arms of one tagged value now, so naming both is an
    /// argv contradiction the parser answers before any boundary relation is asked.
    fn minimal_delegating_the_channel_key() -> Vec<String> {
        let mut a = minimal();
        let at = a
            .iter()
            .position(|v| v == "--tls-key")
            .expect("minimal names one");
        a.drain(at..at + 2);
        a
    }

    fn minimal() -> Vec<String> {
        args(&[
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "server-key-1",
            "--signing-key-seed",
            "/seed",
            "--tls-cert",
            "/cert",
            "--tls-key",
            "/key",
            "--client-ca",
            "/ca",
            "--trust",
            "/trust.json",
            "--inner-http-url",
            "http://127.0.0.1:8080/mcp",
            // The RFC 9421 @target-uri this deployment binds to. Required and
            // non-empty: an empty target makes the audience/target conjunction a
            // tautology, so it is refused at parse.
            "--target-uri",
            "https://mcp.example.com/mcp",
            // Delegated-signing is the only response mode; the trust epoch is required
            // for every config (ADR-MCPRE-052 §7).
            "--delegated-trust-epoch",
            "epoch-min",
            // Required: it used to default to the `example.com` placeholder the Helm
            // chart refuses, so the binary accepted the one value the chart exists to
            // reject.
            "--trust-domain",
            "mcp.example.com",
        ])
    }

    /// The same required flags as `minimal()` but WITHOUT any inner-server selection,
    /// so a test can supply `--inner-http-url` itself (or assert the missing-inner
    /// error).
    fn minimal_without_inner_command() -> Vec<String> {
        args(&[
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "server-key-1",
            "--signing-key-seed",
            "/seed",
            "--tls-cert",
            "/cert",
            "--tls-key",
            "/key",
            "--client-ca",
            "/ca",
            "--trust",
            "/trust.json",
            "--target-uri",
            "https://mcp.example.com/mcp",
            "--delegated-trust-epoch",
            "epoch-min",
            "--trust-domain",
            "mcp.example.com",
        ])
    }

    /// A durable single-node replay selection (`--replay-cache file --replay-path
    /// <p>`). The DEFAULT replay backend is the non-durable in-memory cache, which
    /// is a production violation (#90, ADR-MCPS-014/020): a restart forgets admitted
    /// nonces and re-opens a replay window. The proxy always runs the strict/
    /// production posture, so ANY config that must parse SUCCESSFULLY has to declare
    /// a durable backend — tests splice these flags into `minimal()`.
    fn durable_replay() -> Vec<String> {
        args(&[
            "--replay-redis-url",
            "redis://127.0.0.1:6379",
            "--replay-durability-tier",
            "redis-wait-quorum:1:100",
        ])
    }

    /// `minimal()` plus a replay backend that is a legal deployment state — the smallest
    /// config that both parses and validates. Success tests that do not exercise replay
    /// selection build on this.
    ///
    /// It named `--replay-cache file` until CF-01: the in-memory default was refused and
    /// `file` was what the refusal recommended, so the canonical fixture was a state no
    /// build could materialize. That it went unnoticed is the finding — a whole suite of
    /// success tests asserted things about a deployment that could not start.
    fn minimal_durable() -> Vec<String> {
        let mut a = minimal();
        a.splice(0..0, durable_replay());
        a
    }

    /// [`minimal_durable`] with one flag and its value removed.
    ///
    /// A test about ONE absent flag has to supply every other required one, or the
    /// refusal it reads is the parser reporting a different absence. Removing from a
    /// complete list says which flag the test is about; restating the list by hand says
    /// it only until the next required flag is added.
    fn minimal_durable_without(flag: &str) -> Vec<String> {
        let mut a = minimal_durable();
        let at = a
            .iter()
            .position(|arg| arg == flag)
            .expect("the flag being removed is in the complete list");
        a.drain(at..at + 2);
        a
    }

    /// A command line wrong in three ways is answered about all three, in one pass.
    ///
    /// This is what the parser exchanged its early returns for. It used to hold three
    /// clause groups of its own and return at the first, so an operator fixed one thing,
    /// re-ran, and met the next; the groups' relative order was the whole contract, and it
    /// was a property of `parse_args` rather than of the deployment. Legality is now
    /// decided once, for every route into the runtime, and the CLI reads the same list any
    /// other caller gets.
    ///
    /// The ORDER of that list is pinned by
    /// `tests/integration/config_refusal_precedence_test.rs`, over the boundary rather
    /// than over a command line. What is pinned here is the completeness a
    /// `.contains()` assertion cannot see when it is one of three: all three appear.
    #[test]
    fn a_command_line_wrong_three_ways_is_answered_about_all_three() {
        // A shared replay store with no durability tier, a PKCS#11 channel key on a source
        // that is not PKCS#11, and an lb-assertion form the boundary refuses.
        //
        // The third wrong used to be a dangling `--ingress-lb-key`. It is a parser refusal
        // now — the form owns its own keys, so after assembly there is no dangling value to
        // report — and the third is the form itself, which is still boundary-shaped.
        let mut a = minimal_delegating_the_channel_key();
        a.splice(
            0..0,
            args(&[
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--pkcs11-tls-key-label",
                "tls-on-token",
                "--transport-binding",
                "lb-assertion",
                "--ingress-lb-key",
                "lb-1:1i8Bah79Hk_feT60LNhEceG6nwzwTRKHtcxx9hYofLg",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        for expected in [
            "--replay-durability-tier",
            "--pkcs11-tls-key-label",
            "--transport-binding lb-assertion",
        ] {
            assert!(err.contains(expected), "missing {expected} in: {err}");
        }
    }

    // --- MCPRE-493 admission currency ----------------------------------------

    /// The full set an enforcing deployment must supply.
    fn admission_args(mode: &str) -> Vec<String> {
        args(&[
            "--admission",
            mode,
            "--admission-authority-kid",
            "admission-root-1",
            "--admission-authority-pubkey",
            "1i8Bah79Hk_feT60LNhEceG6nwzwTRKHtcxx9hYofLg",
            "--admission-redis-url",
            "redis://127.0.0.1:6379",
        ])
    }

    // The two programmatic degraded cases that used to be here are gone, and their
    // absence is the result. One set a zero-width window on an enabled gate; the other set
    // one beside `--admission off`. ADR-MCPRE-067 Phase 6 made the availability a tagged
    // value whose window is a `NonZeroU64` carried by the arm that opens one, and moved the
    // gate's inputs inside the enforcing forms — so neither mutation compiles. The argv
    // forms survive and `cli::admission_flags` refuses both, naming the clock-skew term.

    /// The refusal has to tell the operator the skew term widens the window. It moved to
    /// the parser with the state it refuses — the request cannot hold a zero-width window
    /// any more — so this asks the command line, which is where the pair is still statable.
    #[test]
    fn the_degraded_window_refusal_names_the_clock_skew_term() {
        let mut a = minimal_durable();
        a.splice(0..0, admission_args("required"));
        a.push("--admission-allow-degraded".into());
        a.push("true".into());
        let refusal = parse_args(&a).expect_err("a zero-width degraded window is refused");
        assert!(
            refusal.contains("--max-clock-skew"),
            "the operator has to be told the skew term widens the window, got: {refusal}"
        );
    }

    /// An authority key that cannot decode is a property of the CONFIGURATION, so the
    /// boundary owns it. It used to be caught only where the verifier was built, which
    /// left a programmatic config reaching materialization with an unusable issuer.
    #[test]
    fn a_programmatic_config_cannot_carry_an_undecodable_admission_authority_key() {
        let mut config = parse_args(&minimal_durable()).expect("the base config parses");
        config.admission = crate::deployment_request::AdmissionRequest::Required(
            crate::deployment_request::AdmissionGateRequest {
                authority_kid: "admission-root-1".to_string(),
                authority_pubkey_b64url: "not-a-key".to_string(),
                store: crate::deployment_request::SharedStoreRequest::redis(
                    "redis://127.0.0.1:6379",
                ),
                availability: crate::deployment_request::AdmissionAvailabilityRequest::FailClosed,
            },
        );
        let violations = unsafe_config_violations(&config);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("--admission-authority-pubkey")),
            "an undecodable authority key must be refused at the boundary, got {violations:?}"
        );
    }

    /// A complete admission configuration must NOT be refused — otherwise the checks
    /// above would pass against a predicate that simply refuses everything.
    #[test]
    fn a_complete_admission_configuration_raises_no_violation() {
        let mut a = minimal_durable();
        a.splice(0..0, admission_args("required"));
        let config = parse_args(&a).expect("a complete admission config parses");
        assert!(
            unsafe_config_violations(&config).is_empty(),
            "a complete admission configuration must be admissible: {:?}",
            unsafe_config_violations(&config)
        );
    }

    #[test]
    fn admission_is_off_by_default() {
        // A deployment that has not asked for admission must not get a gate it did
        // not configure — and, more importantly, must not believe it has one.
        let config = parse_args(&minimal_durable()).expect("parses");
        assert_eq!(
            config.admission,
            crate::deployment_request::AdmissionRequest::NotEnforced
        );
    }

    #[test]
    fn enforcing_admission_parses_with_an_authority_and_a_source() {
        for mode in ["optional", "required"] {
            let mut a = minimal_durable();
            a.splice(0..0, admission_args(mode));
            let config =
                parse_args(&a).unwrap_or_else(|e| panic!("--admission {mode} must parse: {e}"));
            assert!(config.admission.is_enforced());
            assert!(config
                .admission
                .gate()
                .is_some_and(|gate| gate.store.locator().contains("://")));
        }
    }

    #[test]
    fn enforcing_admission_without_an_authority_is_refused() {
        // The worst of the three states: a gate that looks enabled and verifies
        // nothing, because no issuer is trusted to have said anything.
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&[
                "--admission",
                "required",
                "--admission-redis-url",
                "redis://127.0.0.1:6379",
            ]),
        );
        let err = parse_args(&a).expect_err("an authority is required");
        assert!(err.contains("--admission-authority-kid"), "got: {err}");
    }

    #[test]
    fn enforcing_admission_without_a_source_is_refused() {
        // Currency is a comparison; with nothing to compare against, every call would
        // fail closed on an unreachable authority and the deployment would look broken
        // rather than misconfigured.
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&[
                "--admission",
                "required",
                "--admission-authority-kid",
                "admission-root-1",
                "--admission-authority-pubkey",
                "1i8Bah79Hk_feT60LNhEceG6nwzwTRKHtcxx9hYofLg",
            ]),
        );
        let err = parse_args(&a).expect_err("a source is required");
        assert!(err.contains("--admission-redis-url"), "got: {err}");
    }

    #[test]
    fn a_dangling_admission_setting_is_refused() {
        // It reads as "admission is configured" to anyone auditing the command line,
        // while nothing is enforced.
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&["--admission-redis-url", "redis://127.0.0.1:6379"]),
        );
        let err = parse_args(&a).expect_err("a dangling admission setting is refused");
        assert!(err.contains("--admission is off"), "got: {err}");
    }

    #[test]
    fn degraded_mode_requires_a_positive_bound() {
        // Degraded mode is a BOUNDED window. Zero is not a window — it would fail
        // closed on every unreachable-authority call while claiming one exists.
        let mut a = minimal_durable();
        a.splice(0..0, admission_args("required"));
        a.push("--admission-allow-degraded".into());
        a.push("true".into());
        let err = parse_args(&a).expect_err("P must be positive");
        assert!(
            err.contains("--admission-degraded-bound-secs"),
            "got: {err}"
        );

        a.push("--admission-degraded-bound-secs".into());
        a.push("120".into());
        let config = parse_args(&a).expect("a bounded degraded window parses");
        assert_eq!(
            config
                .admission
                .gate()
                .map(|gate| gate.availability.bound_secs()),
            Some(Some(120))
        );
    }

    #[test]
    fn an_unknown_admission_mode_is_refused() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--admission", "sometimes"]));
        let err = parse_args(&a).expect_err("the mode set is closed");
        assert!(err.contains("off|optional|required"), "got: {err}");
    }

    // --- §5.1 bounded skew / §4.1 MCP transport contract ----------------------

    #[test]
    fn max_clock_skew_is_accepted_across_the_whole_bound() {
        for skew in [
            0,
            1,
            30,
            299,
            mcp_re_http_profile::VerifierPolicy::MAX_CLOCK_SKEW_BOUND,
        ] {
            let mut a = minimal_durable();
            a.push("--max-clock-skew".into());
            a.push(skew.to_string());
            let config = parse_args(&a).unwrap_or_else(|e| panic!("skew {skew} must parse: {e}"));
            assert_eq!(config.max_clock_skew, skew);
        }
    }

    /// A skew the freshness gate would refuse must be refused at the command line —
    /// not accepted and then silently applied to replay retention alone.
    #[test]
    fn out_of_bounds_max_clock_skew_is_refused_at_parse() {
        for skew in [-1, -30, 301, 3600] {
            let mut a = minimal_durable();
            a.push("--max-clock-skew".into());
            a.push(skew.to_string());
            let err = parse_args(&a)
                .err()
                .unwrap_or_else(|| panic!("skew {skew} must be refused"));
            assert!(err.contains("--max-clock-skew must be"), "got: {err}");
        }
    }

    /// An empty `--target-uri` would make the audience/target conjunction compare
    /// `"" == ""` on every request. Refused at parse rather than served.
    #[test]
    fn empty_or_missing_target_uri_is_refused() {
        let base: Vec<String> = minimal_durable().into_iter().collect::<Vec<_>>();
        // The helper supplies --target-uri; drop it to prove it is required.
        let mut without = Vec::new();
        let mut skip = false;
        for a in &base {
            if skip {
                skip = false;
                continue;
            }
            if a == "--target-uri" {
                skip = true;
                continue;
            }
            without.push(a.clone());
        }
        let err = parse_args(&without).expect_err("--target-uri must be required");
        assert!(err.contains("--target-uri"), "got: {err}");

        for empty in ["", "   "] {
            let mut a = without.clone();
            a.push("--target-uri".into());
            a.push(empty.into());
            let err = parse_args(&a).expect_err("an empty --target-uri must be refused");
            assert!(err.contains("must not be empty"), "got: {err}");
        }
    }

    /// MCPRE-114: the bounded-admission ceiling exists in `async_serve`/`async_fleet`
    /// but had NO CLI flag, so no shipped configuration could enable it — the proxy
    /// always ran unbounded in-flight. Each knob must reach the config, and the no-flags
    /// case must be BOUNDED: unbounded in-flight is attacker-controlled buffering ahead of
    /// the verify gate.
    ///
    /// The REQUEST is asserted, not the runtime field: `Unspecified` is a third thing, and
    /// keeping it distinguishable from a value equal to the default is the point.
    #[test]
    fn admission_ceilings_are_configurable_and_bounded_by_default() {
        use crate::config_state::InFlightLimitRequest;

        let config = parse_args(&minimal_durable()).expect("parse");
        assert_eq!(
            config.in_flight_limit,
            InFlightLimitRequest::Unspecified,
            "no flag states no limit — the bounded default is the boundary's answer, not the \
             parser's"
        );
        assert_eq!(
            crate::config_state::in_flight_limit::classify(&config),
            crate::config_state::InFlightLimitBasis::PerCore {
                requests: nz(crate::config_state::in_flight_limit::DEFAULT_PER_CORE_IN_FLIGHT)
            },
            "a per-core ceiling applies with no flags at all"
        );

        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-in-flight", "32"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.in_flight_limit,
            InFlightLimitRequest::PerCore(nz(32))
        );
        assert!(unsafe_config_violations(&config).is_empty());

        let mut b = minimal_durable();
        b.splice(0..0, args(&["--max-in-flight-total", "256"]));
        let config = parse_args(&b).expect("parse");
        assert_eq!(
            config.in_flight_limit,
            InFlightLimitRequest::FleetTotal(nz(256))
        );
        assert!(unsafe_config_violations(&config).is_empty());
    }

    /// An explicit value EQUAL to the default is not the same request as no value at all.
    ///
    /// This is the distinction the parser used to destroy. `ServerLimits` carries a
    /// fail-safe 256, so `Some(256)` meant either "the operator chose 256 per core" or "the
    /// operator said nothing" — and once a fleet-wide target had to out-rank the default
    /// but not an explicit value, the parser reconstructed the difference and encoded it by
    /// writing `None` over the field.
    #[test]
    fn an_explicit_ceiling_equal_to_the_default_is_not_an_absent_one() {
        use crate::config_state::InFlightLimitRequest;

        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&[
                "--max-in-flight",
                &crate::config_state::in_flight_limit::DEFAULT_PER_CORE_IN_FLIGHT.to_string(),
            ]),
        );
        let stated = parse_args(&a).expect("parse").in_flight_limit;
        let unstated = parse_args(&minimal_durable())
            .expect("parse")
            .in_flight_limit;

        assert_eq!(
            stated,
            InFlightLimitRequest::PerCore(nz(
                crate::config_state::in_flight_limit::DEFAULT_PER_CORE_IN_FLIGHT
            ))
        );
        assert_eq!(unstated, InFlightLimitRequest::Unspecified);
        assert_ne!(stated, unstated, "the request must keep the two apart");
    }

    /// The two flags are ALTERNATIVE ways to state one admission limit, so naming both is
    /// refused rather than resolved by precedence.
    ///
    /// This replaces a contract: the per-core value used to win silently, which left the
    /// operator's other explicit instruction doing nothing and saying nothing. The chart
    /// already refused the pair (`_helpers.tpl`), so the two deployment surfaces disagreed
    /// about whether the configuration was legal at all.
    ///
    /// The refusal is the PARSER's because the request type holds one limit: a `DeploymentRequest`
    /// naming both cannot be built, so the boundary has no such state left to refuse.
    /// Reading an argument list is the only place the combination still appears, and
    /// without this the second flag would silently overwrite the first.
    #[test]
    fn naming_both_admission_limits_is_refused() {
        for pair in [
            ["--max-in-flight", "32", "--max-in-flight-total", "256"],
            ["--max-in-flight-total", "256", "--max-in-flight", "32"],
            // No "they happen to agree" exemption: whether a total is equivalent to a
            // per-core ceiling depends on the resolved core count, a property of the host.
            ["--max-in-flight", "256", "--max-in-flight-total", "256"],
            // The same flag twice is the same mistake.
            ["--max-in-flight", "32", "--max-in-flight", "64"],
        ] {
            let mut a = minimal_durable();
            a.splice(0..0, args(&pair));
            let refusal =
                parse_args(&a).expect_err("a second admission limit must be refused: {pair:?}");
            assert!(
                refusal.contains("already states the admission limit"),
                "the refusal must say which instruction is being overwritten: {refusal}"
            );
        }
    }

    /// A fleet-wide target survives on its own, WITHOUT the parser clearing the per-core
    /// default to make room for it. That erasure is gone: absence is now representable, so
    /// the request says "fleet total" and the boundary resolves it.
    ///
    /// The case that was broken: an embedder assembling a `DeploymentRequest` from
    /// `ServerLimits::default()` plus a fleet-wide target got the default 256 per core and
    /// no diagnostic, because the provenance rule lived in the parser alone.
    #[test]
    fn a_fleet_wide_target_survives_without_erasing_the_per_core_default() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-in-flight-total", "256"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.in_flight_limit,
            crate::config_state::InFlightLimitRequest::FleetTotal(nz(256))
        );

        let basis = crate::config_state::in_flight_limit::classify(&config);
        assert_eq!(basis.fleet_total(), Some(256));
        assert_eq!(
            basis.per_core(),
            None,
            "a fleet-wide basis has no per-core answer until the core count is resolved"
        );

        // Assembled in code, which meets no parser: the same basis, for the same reason.
        let mut built = parse_args(&minimal_durable()).expect("parse");
        built.limits = crate::tls::ServerLimits::default();
        built.in_flight_limit = crate::config_state::InFlightLimitRequest::FleetTotal(nz(1000));
        assert_eq!(
            crate::config_state::in_flight_limit::classify(&built).fleet_total(),
            Some(1000),
            "the fail-safe default in ServerLimits must not out-rank a stated fleet target"
        );
    }

    /// The connection-age bound is what re-checks a client certificate against an
    /// expiry or a reloaded CRL; disabling it is an unsafe configuration.
    #[test]
    fn the_connection_age_bound_is_defaulted_and_zero_is_refused() {
        let config = parse_args(&minimal_durable()).expect("parse");
        assert_eq!(
            config.limits.max_connection_age,
            Some(std::time::Duration::from_secs(300))
        );
        assert!(unsafe_config_violations(&config).is_empty());

        // `parse_args` applies `unsafe_config_violations` unconditionally, so
        // disabling the bound never produces a DeploymentRequest at all.
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-connection-age-secs", "0"]));
        let err = parse_args(&a).expect_err("a disabled connection-age bound is refused");
        assert!(err.contains("--max-connection-age-secs"), "got: {err}");
    }

    /// Zero would silently mean "admit nothing"; refuse it rather than serve a proxy
    /// that 503s every request.
    #[test]
    fn zero_admission_ceiling_is_refused() {
        for flag in ["--max-in-flight", "--max-in-flight-total"] {
            let mut a = minimal_durable();
            a.splice(0..0, args(&[flag, "0"]));
            let err = parse_args(&a).expect_err("zero must be refused");
            assert!(err.contains("must be > 0"), "got: {err}");
        }
    }

    #[test]
    fn mcp_protocol_version_is_repeatable_and_absent_by_default() {
        let mut a = minimal_durable();
        a.push("--mcp-protocol-version".into());
        a.push("2026-07-28".into());
        a.push("--mcp-protocol-version".into());
        a.push("2025-06-18".into());
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.mcp_protocol_versions,
            vec!["2026-07-28", "2025-06-18"]
        );
    }

    // --- ADR-MCPRE-052 (MCPRE-122) delegated-signing (the only mode) -----------

    #[test]
    fn delegated_signing_parses_with_defaults() {
        // `minimal()` already supplies the required --delegated-trust-epoch.
        let config = parse_args(&minimal_durable()).expect("parse delegated-signing");
        assert_eq!(
            config.delegated_signing.trust_epoch.as_deref(),
            Some("epoch-min")
        );
        // Defaults: T=300, O=60; issuer kid / audience hash default at build time.
        assert_eq!(config.delegated_signing.ttl_secs, 300);
        assert_eq!(config.delegated_signing.overlap_secs, 60);
        assert_eq!(config.delegated_signing.issuer_kid, None);
        assert_eq!(config.delegated_signing.audience_hash, None);
    }

    #[test]
    fn missing_trust_epoch_is_rejected() {
        // A config complete but for the required trust epoch fails closed — the epoch is
        // mandatory for every deployment.
        let a = minimal_durable_without("--delegated-trust-epoch");
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--delegated-trust-epoch"), "got: {err}");
    }

    #[test]
    fn delegated_overlap_not_less_than_ttl_is_rejected() {
        let mut a = minimal_durable();
        a.extend(args(&[
            "--delegated-ttl-secs",
            "100",
            "--delegated-overlap-secs",
            "100",
        ]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("0 < overlap < ttl"), "got: {err}");
    }

    #[test]
    fn parses_a_minimal_config_with_defaults() {
        // The bare in-memory replay default is a strict/production violation (#90),
        // and the proxy always runs strict, so a minimal PARSEABLE config declares a
        // durable replay backend; every other value here is a plain default.
        let config = parse_args(&minimal_durable()).expect("parse");
        assert_eq!(config.bind, "127.0.0.1:8443");
        assert_eq!(config.audience, "did:example:server-1");
        // The default skew is the profile's own, so the freshness gate the verifier
        // runs and the retention the replay tier applies cannot drift apart.
        assert_eq!(
            config.max_clock_skew,
            mcp_re_http_profile::VerifierPolicy::DEFAULT_MAX_CLOCK_SKEW
        );
        assert!(config.mcp_protocol_versions.is_empty());
        assert!(matches!(
            config.response_signing.source,
            SigningSourceRequest::File(_)
        ));
        assert_eq!(config.peer_identity.flag_value(), "exact");
        // Safe defaults: URI SAN identity, bounded resources.
        assert_eq!(
            config.peer_identity.credential_identity_field(),
            Some(IdentityPolicy::UriSan)
        );
        assert_eq!(config.authorization.kind, AuthzKind::Off);
        assert_eq!(config.limits.max_header_bytes, 64 * 1024);
        assert_eq!(config.limits.max_body_bytes, 16 * 1024 * 1024);
        assert_eq!(config.limits.max_concurrent_connections, 256);
        assert!(config.limits.read_timeout.is_some());
        // Aggregate read-phase wall-clock deadline (slow-loris defense) defaults on.
        assert_eq!(
            config.limits.request_deadline,
            Some(std::time::Duration::from_secs(30))
        );
        // v1 revocation posture: enforced 1-hour client-cert lifetime by default.
        assert_eq!(
            config.max_client_cert_lifetime,
            Some(std::time::Duration::from_secs(3600))
        );
        assert_eq!(
            config.inner_http_urls,
            vec!["http://127.0.0.1:8080/mcp".to_string()]
        );
    }

    #[test]
    fn parses_client_cert_lifetime_forms() {
        // Only lifetimes at/below the strict ceiling parse (the proxy always runs
        // strict): `none`/`0` (disabled) and over-ceiling values are hard errors,
        // covered by the strict_rejects_* cert-lifetime tests.
        //
        // Each case also names a connection age it can carry. This is a SPELLING test —
        // does `90s` mean ninety seconds — and a spelling is not a deployment: the
        // boundary refuses a connection that would outlive the credential, so a short
        // lifetime beside the default 300s age is refused for a reason this test is not
        // about.
        let cases = [("30m", 1800), ("60m", 3600), ("90s", 90), ("45", 45)];
        for (input, expected) in cases {
            let mut a = minimal_durable();
            a.splice(
                0..0,
                args(&[
                    "--max-client-cert-lifetime",
                    input,
                    "--max-connection-age-secs",
                    "30",
                ]),
            );
            let got = parse_args(&a).expect("parse").max_client_cert_lifetime;
            assert_eq!(
                got,
                Some(std::time::Duration::from_secs(expected)),
                "input {input}"
            );
        }
    }

    /// A unit-suffixed lifetime whose product overflows `u64` is refused, not wrapped.
    ///
    /// `5124095576030432 * 3600` is congruent to 3584 mod 2^64, which is BELOW the
    /// ceiling — so a wrapping multiply would be accepted by every clause downstream and
    /// the deployment would enforce a lifetime bearing no relation to the argument. The
    /// same input panics a debug build, which is why neither half of the behaviour is
    /// acceptable.
    #[test]
    fn an_overflowing_client_cert_lifetime_is_refused_not_wrapped() {
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&["--max-client-cert-lifetime", "5124095576030432h"]),
        );
        let err = parse_args(&a).expect_err("an overflowing lifetime is not a lifetime");
        assert!(err.contains("--max-client-cert-lifetime"), "{err}");
    }

    #[test]
    fn unparseable_client_cert_lifetime_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "soon"]));
        assert!(parse_args(&a)
            .unwrap_err()
            .contains("max-client-cert-lifetime"));
    }

    #[test]
    fn parses_identity_source_selection() {
        // uri_san (default) and dns_san are the production-acceptable sources; the
        // deprecated cn_legacy is always rejected (strict_rejects_cn_legacy_...).
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--transport-identity-source", "uri_san"]));
        assert_eq!(
            parse_args(&a)
                .expect("parse")
                .peer_identity
                .credential_identity_field()
                .expect("the channel-credential form"),
            IdentityPolicy::UriSan
        );

        let mut a = minimal_durable();
        a.splice(0..0, args(&["--transport-identity-source", "dns_san"]));
        assert_eq!(
            parse_args(&a)
                .expect("parse")
                .peer_identity
                .credential_identity_field()
                .expect("the channel-credential form"),
            IdentityPolicy::DnsSan
        );
    }

    #[test]
    fn unknown_identity_source_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--transport-identity-source", "email_san"]));
        assert!(parse_args(&a).unwrap_err().contains("email_san"));
    }

    // ---- ADR-MCPS-023 Tier 3 (issue #71): LB-signed request-bound assertion ----

    /// A valid base64url-no-pad 32-byte Ed25519 public key for `--ingress-lb-key`.
    fn lb_pub_b64() -> String {
        mcp_re_core::SigningKey::from_seed_bytes(&[5u8; 32])
            .public_key()
            .to_b64url()
    }

    // NOTE: lb-assertion is always rejected under the unconditional strict/production
    // posture (see `strict_rejects_lb_assertion_binding`), so there is no
    // successful-parse test for it — only the parse-time argument guards below and
    // the strict rejection are exercised.

    #[test]
    fn lb_assertion_binding_requires_at_least_one_key() {
        // `lb-assertion` with no trusted LB key can never verify any assertion —
        // fail closed at parse time rather than reject every request.
        let mut a = minimal();
        a.splice(0..0, args(&["--transport-binding", "lb-assertion"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--ingress-lb-key"), "got: {err}");
    }

    #[test]
    fn ingress_lb_key_without_lb_assertion_binding_errors() {
        // A dangling `--ingress-lb-key` (without selecting the binding) would
        // silently do nothing — an illusion of request-bound ingress. Reject it.
        let mut a = minimal();
        a.splice(
            0..0,
            args(&["--ingress-lb-key", &format!("lb-1:{}", lb_pub_b64())]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("has no effect"), "got: {err}");
    }

    #[test]
    fn ingress_lb_key_malformed_value_errors() {
        // Missing the `:` separator.
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--transport-binding",
                "lb-assertion",
                "--ingress-lb-key",
                "no-colon-here",
            ]),
        );
        assert!(parse_args(&a).unwrap_err().contains("keyid"));
    }

    #[test]
    fn ingress_lb_key_invalid_public_key_errors() {
        // A syntactically-correct `<id>:<body>` whose body is NOT a valid Ed25519
        // public key fails closed at parse time.
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--transport-binding",
                "lb-assertion",
                "--ingress-lb-key",
                "lb-1:not-a-real-key",
            ]),
        );
        assert!(parse_args(&a).unwrap_err().contains("Ed25519 public key"));
    }

    #[test]
    fn duplicate_ingress_lb_key_id_errors() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--transport-binding",
                "lb-assertion",
                "--ingress-lb-key",
                &format!("lb-1:{}", lb_pub_b64()),
                "--ingress-lb-key",
                &format!("lb-1:{}", lb_pub_b64()),
            ]),
        );
        assert!(parse_args(&a).unwrap_err().contains("duplicate"));
    }

    #[test]
    fn strict_rejects_lb_assertion_binding() {
        // Tier 3 places the LB in the TCB (request-bound INGRESS assertion, NOT
        // end-to-end mTLS); the unconditional strict/production posture refuses it.
        // Durable replay isolates lb-assertion as the sole violation.
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&[
                "--transport-binding",
                "lb-assertion",
                "--ingress-lb-key",
                &format!("lb-1:{}", lb_pub_b64()),
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("lb-assertion") && err.contains("end-to-end"),
            "got: {err}"
        );
    }

    // ---------------------------------------------------------------------
    // ADR-MCPS-023 §C (v0.10) Mode C attested ingress (MCPS-61).
    // ---------------------------------------------------------------------

    #[test]
    fn a_fully_configured_mode_c_clears_every_completeness_check_and_is_still_refused() {
        // Mode-C is deliberately non-deployable in v0.16 (ADR-MCPRE-056 §Y6): refused, not
        // removed. This config is COMPLETE — attestor key, ingress identity, audience and
        // the pinned-mTLS acknowledgement are all present — so the refusal it receives must
        // be the MODE refusal and not a completeness diagnostic. That is what keeps the
        // completeness validation meaningful while the mode is unsupported: if one of those
        // checks broke, this test would start reporting its error instead.
        let mut a = minimal_durable();
        a.splice(0..0, attested_ingress_flags());
        let err = parse_args(&a).expect_err("Mode C is not a supported deployment mode");
        assert!(
            err.contains("attested-ingress is not a supported deployment mode"),
            "a complete Mode-C config must be refused for the MODE, not for its shape; \
             got: {err}"
        );
    }

    #[test]
    fn mode_c_is_refused_by_the_unsafe_configuration_guard_itself() {
        // Mode C is refused at the validation boundary, so the guard — not the composition
        // root — is what has to hold the refusal.
        //
        // Reached by mutating a parsed config rather than through `parse_args`, because
        // `parse_args` now ends at this same guard: going through it would prove only that
        // SOMETHING refused, not that this guard did.
        let mut config = parse_args(&minimal_durable()).expect("the base config parses");
        config.peer_identity = mode_c_form(
            vec!["spiffe://example.org/ingress-1".to_string()],
            "did:example:server-1".to_string(),
        );
        let violations = unsafe_config_violations(&config);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("attested-ingress is not a supported deployment mode")),
            "the unsafe-configuration guard must be what refuses Mode C, got {violations:?}"
        );
    }

    #[test]
    fn attested_ingress_without_pinned_mtls_fails_closed() {
        // §C2: the pinned attestor→node channel is load-bearing — absent the
        // explicit acknowledgement, attested ingress refuses to start.
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--transport-binding",
                "attested-ingress",
                "--ingress-attestor-key",
                &format!("attestor-1:{}", attestor_pub_b64()),
                "--ingress-identity",
                "spiffe://example.org/ingress-1",
                "--ingress-audience",
                "did:example:server-1",
                // no --ingress-pinned-mtls
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--ingress-pinned-mtls"), "got: {err}");
    }

    #[test]
    fn attested_ingress_requires_attestor_key_identity_and_audience() {
        // Each missing piece fails closed with a precise error.
        let base = args(&[
            "--transport-binding",
            "attested-ingress",
            "--ingress-pinned-mtls",
        ]);
        // Missing attestor key.
        let mut a = minimal();
        a.splice(0..0, base.clone());
        assert!(parse_args(&a)
            .unwrap_err()
            .contains("--ingress-attestor-key"));
        // Missing ingress identity.
        let mut a = minimal();
        let mut f = base.clone();
        f.extend(args(&[
            "--ingress-attestor-key",
            &format!("attestor-1:{}", attestor_pub_b64()),
        ]));
        a.splice(0..0, f);
        assert!(parse_args(&a).unwrap_err().contains("--ingress-identity"));
        // Missing audience.
        let mut a = minimal();
        let mut f = base.clone();
        f.extend(args(&[
            "--ingress-attestor-key",
            &format!("attestor-1:{}", attestor_pub_b64()),
            "--ingress-identity",
            "spiffe://example.org/ingress-1",
        ]));
        a.splice(0..0, f);
        assert!(parse_args(&a).unwrap_err().contains("--ingress-audience"));
    }

    #[test]
    fn attested_ingress_flags_dangle_without_binding() {
        // Each Mode-C flag has no effect outside attested-ingress → reject.
        for (flag, val) in [
            (
                "--ingress-attestor-key",
                format!("attestor-1:{}", attestor_pub_b64()),
            ),
            (
                "--ingress-identity",
                "spiffe://example.org/ingress-1".to_string(),
            ),
            ("--ingress-audience", "did:example:server-1".to_string()),
        ] {
            let mut a = minimal();
            a.splice(0..0, args(&[flag, &val]));
            let err = parse_args(&a).unwrap_err();
            assert!(err.contains("has no effect"), "flag {flag} → got: {err}");
        }
        // The pinned-mTLS boolean too.
        let mut a = minimal();
        a.splice(0..0, args(&["--ingress-pinned-mtls"]));
        assert!(parse_args(&a).unwrap_err().contains("has no effect"));
    }

    #[test]
    fn attested_ingress_invalid_attestor_key_errors() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--transport-binding",
                "attested-ingress",
                "--ingress-attestor-key",
                "attestor-1:not-a-real-key",
                "--ingress-identity",
                "spiffe://example.org/ingress-1",
                "--ingress-audience",
                "did:example:server-1",
                "--ingress-pinned-mtls",
            ]),
        );
        assert!(parse_args(&a).unwrap_err().contains("Ed25519 public key"));
    }

    // In a production build (no `dev_env_key_source` feature) the env key source does
    // not exist at all — `--key-source env` is an unknown value, not a togglable
    // downgrade. The dev feature is the ONLY way to compile it in.
    #[cfg(not(feature = "dev_env_key_source"))]
    #[test]
    fn env_key_source_rejected_in_production_build() {
        let mut a = minimal();
        a.splice(0..0, args(&["--key-source", "env"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("unknown --key-source"), "got: {err}");
        assert!(err.contains("env"), "got: {err}");
    }

    // NOTE: the env key source is never accepted (the `--allow-env-keysource`
    // opt-out qualifier is rejected and the unconditional strict posture refuses env
    // key material), so `--key-source env` cannot reach a built key source — the
    // `env_key_source_requires_explicit_opt_in` guard above is the operative gate.

    // --- #4034 PKCS#11 key source (CLI parsing + fail-closed gate) -----------

    /// The four pkcs11 flags that `--key-source pkcs11` requires.
    fn pkcs11_flags() -> Vec<String> {
        args(&[
            "--key-source",
            "pkcs11",
            "--pkcs11-module",
            "/opt/pkcs11/libmock_pkcs11.so",
            "--pkcs11-pin-file",
            "/etc/mcp-re/pkcs11-pin",
            "--pkcs11-token-label",
            "mcp-re-test",
            "--pkcs11-key-label",
            "mcp-re-response-signing",
        ])
    }

    #[test]
    fn parses_pkcs11_key_source_flags() {
        let mut a = minimal_durable();
        a.splice(0..0, pkcs11_flags());
        let config = parse_args(&a).expect("parse");
        let token = token_payload(&config);
        assert_eq!(
            token.module.as_deref(),
            Some("/opt/pkcs11/libmock_pkcs11.so")
        );
        assert_eq!(
            token.pin_file.as_deref(),
            Some("/etc/mcp-re/pkcs11-pin"),
            "the payload carries the PIN's PATH; the PIN itself is not a request field"
        );
        assert_eq!(token.token_label.as_deref(), Some("mcp-re-test"));
        assert_eq!(token.key_label.as_deref(), Some("mcp-re-response-signing"));
    }

    #[test]
    fn pkcs11_key_source_requires_each_flag() {
        // Drop one required flag at a time; each omission is a clear parse error
        // naming the missing flag. (File/env arms are unchanged: --signing-key-seed
        // and the TLS paths are supplied by `minimal()`.)
        for missing in [
            "--pkcs11-module",
            "--pkcs11-pin-file",
            "--pkcs11-token-label",
            "--pkcs11-key-label",
        ] {
            let mut flags = pkcs11_flags();
            // Remove the flag and its value.
            let idx = flags
                .iter()
                .position(|f| f == missing)
                .expect("flag present");
            flags.drain(idx..idx + 2);
            let mut a = minimal();
            a.splice(0..0, flags);
            let err = parse_args(&a).unwrap_err();
            assert!(
                err.contains(missing),
                "expected error to name {missing}; got: {err}"
            );
        }
    }

    #[test]
    fn argv_pkcs11_pin_is_refused_with_the_replacement_named() {
        // C048: argv is world-readable, so a PIN there is a standing exposure. The flag
        // is still recognised so the refusal explains WHY and what to use instead —
        // falling through to "unknown flag" would report a secret-handling decision as
        // a typo.
        let mut a = minimal_durable();
        a.splice(0..0, pkcs11_flags());
        a.extend(args(&["--pkcs11-pin", "1234"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--pkcs11-pin is refused"), "got: {err}");
        assert!(
            err.contains("--pkcs11-pin-file"),
            "the replacement must be named: {err}"
        );
        assert!(
            err.contains("compromised"),
            "the operator must be told the PIN already leaked: {err}"
        );
        assert!(
            !err.contains("1234"),
            "the refusal must not echo the secret it is refusing: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unknown_key_source_lists_pkcs11() {
        let mut a = minimal();
        a.splice(0..0, args(&["--key-source", "yubikey"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("file|pkcs11"), "got: {err}");
    }

    // In a DEFAULT build (no `pkcs11_keysource` feature) the PKCS#11 backend is
    // not compiled and `build_key_source` must FAIL CLOSED on
    // `KeySourceKind::Pkcs11` with a clear, actionable error — `--key-source
    // pkcs11` still parses so the message is precise, but no token-backed key is
    // built. Mirrors `default_build_rejects_env_key_source`.
    #[cfg(not(feature = "pkcs11_keysource"))]
    #[test]
    fn default_build_rejects_pkcs11_key_source() {
        let mut a = minimal_durable();
        a.splice(0..0, pkcs11_flags());
        let config = parse_args(&a).expect("parse");
        assert!(matches!(
            config.response_signing.source,
            SigningSourceRequest::Pkcs11(_)
        ));
        let err = key_source_from(&config)
            .err()
            .expect("default build must refuse a pkcs11 key source");
        let rendered = err.to_string();
        assert!(
            rendered.contains("pkcs11_keysource")
                && rendered.contains("not available in this build"),
            "expected a clear feature-rebuild message; got: {rendered}"
        );
    }

    /// Build the key source the way `run()` does — from the classified custody states
    /// rather than from the request, so a layer-B refusal is measured through the same
    /// path production takes.
    ///
    /// The materializer moved to `capability_materialization` in ADR-MCPRE-067 Phase 8;
    /// these cases stay here because what they measure is what a COMMAND LINE reaches, end
    /// to end. Its own properties are tested with it.
    fn key_source_from(
        config: &DeploymentRequest,
    ) -> Result<Box<dyn crate::key_source::KeySource + Send + Sync>, crate::key_source::KeyError>
    {
        let (custody, violations) = crate::config_state::custody::classify_and_validate(config);
        assert!(violations.is_empty(), "fixture refused: {violations:?}");
        let (channel_credential_custody, violations) =
            crate::config_state::channel_credential_custody::classify_and_validate(config);
        assert!(violations.is_empty(), "fixture refused: {violations:?}");
        crate::capability_materialization::build_key_source(
            &custody.expect("the fixture names a custody state"),
            &channel_credential_custody.expect("the fixture names a TLS custody state"),
            &config.channel_credential.credential_chain,
            &config.peer_trust_anchors,
        )
        .map(crate::capability_materialization::MaterializedSigningRoles::into_key_source)
    }

    // MCPS-076: the File key source is always constructible (default + dev builds).
    #[test]
    fn file_key_source_is_always_constructible() {
        let config = parse_args(&minimal_durable()).expect("parse");
        assert!(matches!(
            config.response_signing.source,
            SigningSourceRequest::File(_)
        ));
        assert!(key_source_from(&config).is_ok());
    }

    // ADR-MCPS-028 §B/§C: cloud-KMS key-source CLI wiring.
    fn aws_kms_flags() -> Vec<String> {
        args(&[
            "--key-source",
            "aws-kms",
            "--aws-kms-region",
            "us-east-1",
            "--aws-kms-key-id",
            "alias/mcp-re-response-signing",
        ])
    }

    fn gcp_kms_flags() -> Vec<String> {
        args(&[
            "--key-source",
            "gcp-kms",
            "--gcp-kms-key-version",
            "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        ])
    }

    #[test]
    fn parses_aws_kms_key_source_flags() {
        let mut a = minimal_durable();
        a.splice(0..0, aws_kms_flags());
        let config = parse_args(&a).expect("parse");
        let kms = aws_payload(&config);
        assert_eq!(kms.region.as_deref(), Some("us-east-1"));
        assert_eq!(kms.key_id.as_deref(), Some("alias/mcp-re-response-signing"));
    }

    #[test]
    fn aws_kms_requires_region_and_key_id() {
        for missing in ["--aws-kms-region", "--aws-kms-key-id"] {
            let mut flags = aws_kms_flags();
            let idx = flags
                .iter()
                .position(|f| f == missing)
                .expect("flag present");
            flags.drain(idx..idx + 2);
            let mut a = minimal();
            a.splice(0..0, flags);
            let err = parse_args(&a).unwrap_err();
            assert!(
                err.contains(missing),
                "expected error to name {missing}; got: {err}"
            );
        }
    }

    /// #60: `--aws-kms-tls-key-id` parses and is captured as the SECOND, distinct
    /// TLS KMS key id. On this delegated path `--tls-key` is forbidden and not
    /// required, so `minimal()`'s exported TLS key must be dropped first.
    /// AWS KMS leading flags WITHOUT `--tls-key` (delegated TLS path), `--inner-command`
    /// appended last so proxy flags land before the inner tail.
    fn aws_kms_lead_no_tls_key() -> Vec<String> {
        args(&[
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "server-key-1",
            "--key-source",
            "aws-kms",
            "--aws-kms-region",
            "us-east-1",
            "--aws-kms-key-id",
            "alias/mcp-re-response-signing",
            "--signing-key-seed",
            "/unused-seed",
            "--tls-cert",
            "/cert",
            "--client-ca",
            "/ca",
            "--trust",
            "/trust.json",
            "--target-uri",
            "https://mcp.example.com/mcp",
            "--delegated-trust-epoch",
            "epoch-min",
            "--trust-domain",
            "mcp.example.com",
        ])
    }

    #[test]
    fn parses_aws_kms_tls_key_id_flag() {
        let mut a = aws_kms_lead_no_tls_key();
        a.push("--aws-kms-tls-key-id".to_string());
        a.push("alias/mcp-re-tls-signing".to_string());
        a.push("--inner-http-url".to_string());
        a.push("http://127.0.0.1:8080/mcp".to_string());
        a.extend(durable_replay());
        let config = parse_args(&a).expect("delegated TLS path parses without --tls-key");
        let response_key_id = aws_payload(&config).key_id.clone();
        let Some(crate::deployment_request::DelegatedChannelKeyRequest::AwsKms(channel)) =
            channel_key(&config)
        else {
            panic!("an AWS channel key was named and must be recorded as one");
        };
        assert_eq!(channel.key_id, "alias/mcp-re-tls-signing");
        // Distinct credential: the channel key id differs from the response-signing one,
        // and they are now two values of two types rather than two sibling options.
        assert_ne!(Some(channel.key_id.clone()), response_key_id);
    }

    /// IRSA is OFF unless asked for. A deployment that did not name it must not get
    /// it by accident, and — more importantly — one that did name it must not
    /// silently get the static-key path instead.
    #[test]
    fn aws_kms_web_identity_is_off_by_default_and_on_when_named() {
        // A durable replay cache: `minimal()` omits it, and the unsafe-config guard
        // rejects the in-memory default before parsing gets this far.
        let durable = args(&[
            "--replay-redis-url",
            "redis://127.0.0.1:6379",
            "--replay-durability-tier",
            "redis-wait-quorum:1:100",
        ]);

        let mut a = minimal();
        a.splice(0..0, durable.clone());
        a.splice(0..0, aws_kms_flags());
        assert!(!aws_payload(&parse_args(&a).unwrap()).use_web_identity);

        let mut a = minimal();
        a.splice(0..0, durable);
        a.splice(0..0, aws_kms_flags());
        a.splice(0..0, args(&["--aws-kms-use-web-identity"]));
        assert!(aws_payload(&parse_args(&a).unwrap()).use_web_identity);
    }

    /// A dangling `--aws-kms-use-web-identity` on another key source would silently
    /// do nothing, leaving an operator believing the pod holds no static IAM key
    /// material while it does. Mirrors the `--gcp-kms-use-metadata` guard.
    #[test]
    fn aws_kms_use_web_identity_without_aws_kms_fails_closed() {
        let mut a = minimal();
        a.splice(0..0, args(&["--aws-kms-use-web-identity"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--aws-kms-use-web-identity"), "got: {err}");
    }

    /// The STS endpoint override only means anything on the web-identity path; on
    /// the static path it would be read as "this is where credentials come from"
    /// while nothing consulted it.
    #[test]
    fn aws_sts_endpoint_without_web_identity_fails_closed() {
        let mut a = minimal();
        a.splice(0..0, aws_kms_flags());
        a.splice(
            0..0,
            args(&["--aws-sts-endpoint", "https://sts.eu-north-1.amazonaws.com"]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--aws-sts-endpoint"), "got: {err}");
    }

    /// #60 / #58: `--aws-kms-tls-key-id` (delegated) PLUS an exported `--tls-key` is
    /// contradictory and must fail closed (the exclusivity guard).
    #[test]
    fn aws_kms_tls_key_id_plus_exported_tls_key_fails_closed() {
        // minimal() carries an exported `--tls-key`; adding a delegated TLS key id
        // alongside it must be rejected.
        let mut a = minimal();
        a.splice(0..0, aws_kms_flags());
        a.splice(0..0, args(&["--aws-kms-tls-key-id", "alias/mcp-re-tls"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("delegated") || err.contains("--tls-key"),
            "expected an exclusivity error, got: {err}"
        );
    }

    /// #60: a dangling `--aws-kms-tls-key-id` on a non-AWS source would silently do
    /// nothing (a false belief the TLS key is KMS-resident), so it must fail closed.
    #[test]
    fn aws_kms_tls_key_id_without_aws_kms_fails_closed() {
        let mut a = minimal_delegating_the_channel_key();
        a.splice(0..0, args(&["--aws-kms-tls-key-id", "alias/mcp-re-tls"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--aws-kms-tls-key-id has no effect without --key-source aws-kms"),
            "got: {err}"
        );
    }

    #[test]
    fn parses_gcp_kms_key_source_flags() {
        let mut a = minimal_durable();
        a.splice(0..0, gcp_kms_flags());
        let config = parse_args(&a).expect("parse");
        let kms = gcp_payload(&config);
        assert!(kms
            .key_version
            .as_deref()
            .expect("the GCP fixture names a key version")
            .ends_with("cryptoKeyVersions/1"));
        assert!(!kms.use_metadata);
    }

    #[test]
    fn gcp_kms_requires_key_version() {
        let mut a = minimal();
        a.splice(0..0, args(&["--key-source", "gcp-kms"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--gcp-kms-key-version"), "got: {err}");
    }

    #[test]
    fn gcp_use_metadata_only_with_gcp_kms() {
        // The metadata flag without --key-source gcp-kms must fail (no silent no-op).
        let mut a = minimal();
        a.splice(0..0, args(&["--gcp-kms-use-metadata"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--gcp-kms-use-metadata"), "got: {err}");
    }

    /// #61: GCP Cloud KMS leading flags WITHOUT `--tls-key` (delegated TLS path),
    /// `--inner-command` appended last so proxy flags land before the inner tail.
    fn gcp_kms_lead_no_tls_key() -> Vec<String> {
        args(&[
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "server-key-1",
            "--key-source",
            "gcp-kms",
            "--gcp-kms-key-version",
            "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
            "--signing-key-seed",
            "/unused-seed",
            "--tls-cert",
            "/cert",
            "--client-ca",
            "/ca",
            "--trust",
            "/trust.json",
            "--target-uri",
            "https://mcp.example.com/mcp",
            "--delegated-trust-epoch",
            "epoch-min",
            "--trust-domain",
            "mcp.example.com",
        ])
    }

    /// #61: `--gcp-kms-tls-key-version` parses and is captured as the SECOND,
    /// distinct TLS KMS key version. On this delegated path `--tls-key` is forbidden
    /// and not required, so the lead omits the exported TLS key.
    #[test]
    fn parses_gcp_kms_tls_key_version_flag() {
        let mut a = gcp_kms_lead_no_tls_key();
        a.push("--gcp-kms-tls-key-version".to_string());
        a.push(
            "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2".to_string(),
        );
        a.push("--inner-http-url".to_string());
        a.push("http://127.0.0.1:8080/mcp".to_string());
        a.extend(durable_replay());
        let config = parse_args(&a).expect("delegated TLS path parses without --tls-key");
        let response_key_version = gcp_payload(&config).key_version.clone();
        let Some(crate::deployment_request::DelegatedChannelKeyRequest::GcpKms(channel)) =
            channel_key(&config)
        else {
            panic!("a GCP channel key was named and must be recorded as one");
        };
        assert_eq!(
            channel.key_version,
            "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2"
        );
        // Distinct credential: the channel key version differs from the response-signing
        // one, and they are now two values of two types rather than two sibling options.
        assert_ne!(Some(channel.key_version.clone()), response_key_version);
    }

    /// #61 / #58: `--gcp-kms-tls-key-version` (delegated) PLUS an exported
    /// `--tls-key` is contradictory and must fail closed (the exclusivity guard).
    #[test]
    fn gcp_kms_tls_key_version_plus_exported_tls_key_fails_closed() {
        // minimal() carries an exported `--tls-key`; adding a delegated TLS key
        // version alongside it must be rejected.
        let mut a = minimal();
        a.splice(0..0, gcp_kms_flags());
        a.splice(
            0..0,
            args(&[
                "--gcp-kms-tls-key-version",
                "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("delegated") || err.contains("--tls-key"),
            "expected an exclusivity error, got: {err}"
        );
    }

    /// #61: a dangling `--gcp-kms-tls-key-version` on a non-GCP source would silently
    /// do nothing (a false belief the TLS key is KMS-resident), so it must fail
    /// closed.
    #[test]
    fn gcp_kms_tls_key_version_without_gcp_kms_fails_closed() {
        let mut a = minimal_delegating_the_channel_key();
        a.splice(
            0..0,
            args(&[
                "--gcp-kms-tls-key-version",
                "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--gcp-kms-tls-key-version has no effect without --key-source gcp-kms"),
            "got: {err}"
        );
    }

    #[test]
    fn unknown_key_source_lists_cloud_kms() {
        let mut a = minimal();
        a.splice(0..0, args(&["--key-source", "azure-kv"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("aws-kms") && err.contains("gcp-kms"),
            "got: {err}"
        );
    }

    // Default build (no cloud-KMS feature): the flags PARSE so the message is
    // precise, but `build_key_source` FAILS CLOSED — mirrors the pkcs11 gate.
    #[cfg(not(feature = "aws_kms_keysource"))]
    #[test]
    fn default_build_rejects_aws_kms_key_source() {
        let mut a = minimal_durable();
        a.splice(0..0, aws_kms_flags());
        let config = parse_args(&a).expect("parse");
        assert!(matches!(
            config.response_signing.source,
            SigningSourceRequest::AwsKms(_)
        ));
        let err = key_source_from(&config)
            .err()
            .expect("default build must refuse an aws-kms key source");
        assert!(
            err.to_string().contains("aws_kms_keysource")
                && err.to_string().contains("not available in this build"),
            "got: {err}"
        );
    }

    #[cfg(not(feature = "gcp_kms_keysource"))]
    #[test]
    fn default_build_rejects_gcp_kms_key_source() {
        let mut a = minimal_durable();
        a.splice(0..0, gcp_kms_flags());
        let config = parse_args(&a).expect("parse");
        assert!(matches!(
            config.response_signing.source,
            SigningSourceRequest::GcpKms(_)
        ));
        let err = key_source_from(&config)
            .err()
            .expect("default build must refuse a gcp-kms key source");
        assert!(
            err.to_string().contains("gcp_kms_keysource")
                && err.to_string().contains("not available in this build"),
            "got: {err}"
        );
    }

    #[test]
    fn parses_configurable_limits() {
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&[
                "--max-body-bytes",
                "1024",
                "--max-connections",
                "8",
                "--read-timeout-secs",
                "45",
                "--request-deadline-secs",
                "12",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.limits.max_body_bytes, 1024);
        assert_eq!(config.limits.max_concurrent_connections, 8);
        assert_eq!(
            config.limits.read_timeout,
            Some(std::time::Duration::from_secs(45)),
            "--read-timeout-secs sets the per-socket read timeout"
        );
        assert_eq!(
            config.limits.request_deadline,
            Some(std::time::Duration::from_secs(12)),
            "--request-deadline-secs sets the aggregate read-phase deadline"
        );
    }

    /// A `0` timeout is what `parse_timeout` maps to "disabled", and disabling any of
    /// these removes the slow-loris defense. The proxy documents itself as refusing every
    /// unsafe configuration, and an OUT-OF-RANGE value was already rejected for exactly
    /// this reason ("the control can never be turned off by out-of-range input") — `0`
    /// was the hole in that argument.
    #[test]
    fn a_zero_timeout_is_refused_because_it_disables_the_slow_loris_defense() {
        for flag in [
            "--read-timeout-secs",
            "--write-timeout-secs",
            "--request-deadline-secs",
        ] {
            let mut a = minimal_durable();
            a.splice(0..0, args(&[flag, "0"]));
            let err = parse_args(&a).expect_err("a disabled timeout must be refused");
            assert!(
                err.contains("refuses unsafe configuration") && err.contains(flag),
                "{flag} 0 must be named in the refusal; got: {err}"
            );
            assert!(
                err.contains("slow-loris"),
                "the refusal must say what control is being disabled; got: {err}"
            );
        }
    }

    /// Under a non-exporting custody the response key never leaves the device, so the
    /// seed is never read — requiring it made operators put an Ed25519 root seed in
    /// every pod in exactly the mode chosen because no key should land there.
    #[test]
    fn a_non_exporting_custody_does_not_require_a_signing_key_seed() {
        for (source, extra) in [
            (
                "gcp-kms",
                vec![
                    "--gcp-kms-key-version",
                    "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                ],
            ),
            (
                "aws-kms",
                vec![
                    "--aws-kms-region",
                    "us-east-1",
                    "--aws-kms-key-id",
                    "alias/k",
                ],
            ),
        ] {
            let mut a: Vec<String> = minimal_durable().into_iter().collect::<Vec<_>>();
            // Drop `--signing-key-seed /seed` from the baseline args.
            let i = a
                .iter()
                .position(|s| s == "--signing-key-seed")
                .expect("baseline has it");
            a.drain(i..i + 2);
            a.splice(0..0, args(&["--key-source", source]));
            a.splice(0..0, args(&extra));

            let config =
                parse_args(&a).unwrap_or_else(|e| panic!("{source} must not require a seed: {e}"));
            // Stronger than "the seed stayed empty": a non-exporting mechanism's payload
            // has no seed field at all, so there is no phantom file to name.
            assert!(
                !matches!(
                    config.response_signing.source,
                    SigningSourceRequest::File(_) | SigningSourceRequest::Environment(_)
                ),
                "{source}: a non-exporting selection must not be a seed-bearing one"
            );
        }
    }

    #[test]
    fn file_custody_still_requires_a_signing_key_seed() {
        // Where the seed IS read, omitting it must still fail closed at parse.
        let mut a = minimal_durable();
        let i = a
            .iter()
            .position(|s| s == "--signing-key-seed")
            .expect("baseline has it");
        a.drain(i..i + 2);
        let err = parse_args(&a).expect_err("file custody reads the seed, so it is required");
        assert!(err.contains("--signing-key-seed"), "got: {err}");
    }

    #[test]
    fn the_default_timeouts_are_bounded_so_the_refusal_never_fires_by_default() {
        // The guard above is only safe because every default is Some(30s): it must be
        // impossible to trip by omitting the flags.
        let config = parse_args(&minimal_durable()).expect("the default config parses");
        assert!(config.limits.read_timeout.is_some());
        assert!(config.limits.write_timeout.is_some());
        assert!(config.limits.request_deadline.is_some());
    }

    #[test]
    fn request_deadline_secs_over_cap_is_rejected() {
        // A nonsensically large `--request-deadline-secs` would overflow
        // `Instant::now() + t` in `tls::DeadlineStream` and silently DISABLE the
        // slow-loris defense. Parse-time capping rejects it LOUDLY so the control
        // can never be turned off by out-of-range input. The boundary (cap exactly)
        // is accepted; cap+1 is rejected.
        let cap = super::runtime_flags::MAX_INNER_READ_TIMEOUT_SECS;
        let mut at_cap = minimal_durable();
        at_cap.splice(0..0, args(&["--request-deadline-secs", &cap.to_string()]));
        let config = parse_args(&at_cap).expect("the cap value itself is accepted");
        assert_eq!(
            config.limits.request_deadline,
            Some(std::time::Duration::from_secs(cap)),
            "the deadline stays enforced at the maximum",
        );

        let mut over_cap = minimal();
        let over = cap + 1;
        over_cap.splice(0..0, args(&["--request-deadline-secs", &over.to_string()]));
        let err = parse_args(&over_cap).expect_err("over-cap value must be rejected");
        assert!(
            err.contains("--request-deadline-secs") && err.contains("<="),
            "rejection names the flag and the bound; got: {err}"
        );
    }

    #[test]
    fn missing_required_flag_errors() {
        let mut a = minimal();
        // Drop --bind and its value.
        a.drain(0..2);
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--bind"), "got: {err}");
    }

    // A Redis quorum tier requires a connection URL, and must be strict-acceptable (the
    // weaker `redis-async` tier is rejected, see
    // `strict_rejects_weak_replay_durability_tier`).
    #[test]
    fn parses_shared_replay_selection() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-wait-quorum:2:500",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config
                .replay
                .store
                .as_ref()
                .map(crate::deployment_request::ReplayStoreRequest::locator),
            Some("redis://127.0.0.1:6379")
        );
        assert_eq!(
            config.replay.durability,
            Some(
                crate::replay_tier::ReplayDurabilityTier::QuorumAcknowledged {
                    quorum: 2,
                    timeout_ms: 500
                }
            )
        );
    }

    #[test]
    fn shared_replay_requires_url() {
        // A Redis tier the strict posture accepts is declared, so the missing piece is the
        // connection URL. (A sub-strict tier names no state at all, and is refused for
        // that instead; with no tier the durability-tier clause fires, covered by
        // `shared_replay_requires_durability_tier`.)
        let mut a = minimal();
        a.splice(
            0..0,
            args(&["--replay-durability-tier", "redis-wait-quorum:1:100"]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--replay-redis-url"), "got: {err}");
    }

    // ADR-MCPS-020: a shared store must declare its durability tier.
    #[test]
    fn shared_replay_requires_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&["--replay-redis-url", "redis://127.0.0.1:6379"]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--replay-durability-tier"), "got: {err}");
    }

    #[test]
    fn parses_wait_quorum_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-wait-quorum:2:500",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.replay.durability,
            Some(
                crate::replay_tier::ReplayDurabilityTier::QuorumAcknowledged {
                    quorum: 2,
                    timeout_ms: 500
                }
            )
        );
    }

    // #69 (epic #68 v0.4 Axis 1) — CONFIG fail-closed: selecting the LINEARIZABLE
    // tier WITHOUT a CP/etcd endpoint is a HARD config-construction error. It must
    // NEVER silently downgrade to Redis or in-memory. The error names the missing
    // --cpstore-etcd-endpoint flag.
    #[test]
    fn linearizable_tier_without_cpstore_endpoint_fails_closed() {
        let mut a = minimal();
        a.splice(0..0, args(&["--replay-durability-tier", "linearizable"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--replay-durability-tier linearizable requires")
                && err.contains("--cpstore-etcd-endpoint"),
            "LINEARIZABLE without a CPStore endpoint must fail closed naming the flag; got: {err}"
        );
    }

    // #69 — the LINEARIZABLE tier with a CP/etcd endpoint parses, selects the etcd
    // backend (NOT Redis), and does NOT require --replay-redis-url.
    #[test]
    fn linearizable_tier_with_cpstore_endpoint_parses() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-durability-tier",
                "linearizable",
                "--cpstore-etcd-endpoint",
                "http://127.0.0.1:2379",
            ]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.replay.durability,
            Some(crate::replay_tier::ReplayDurabilityTier::Linearizable)
        );
        assert_eq!(
            config
                .replay
                .store
                .as_ref()
                .map(crate::deployment_request::ReplayStoreRequest::locator),
            Some("http://127.0.0.1:2379")
        );
        // One slot: naming the CP store is how the Redis one stops being named.
        assert!(matches!(
            config.replay.store,
            Some(crate::deployment_request::ReplayStoreRequest::Etcd(_))
        ));
    }

    // #69 — a --cpstore-etcd-endpoint under a non-LINEARIZABLE tier is rejected (it would
    // silently do nothing — a false belief a CP store is in force). Fail closed.
    //
    // The refusal moved: it used to be that the endpoint was a SIBLING of the Redis URL
    // and the boundary said it had no effect. There is one store slot now, so naming the
    // CP store is how Redis stops being named — and what is left is a store that cannot
    // deliver the declared tier, which the boundary says instead.
    #[test]
    fn cpstore_endpoint_without_linearizable_fails_closed() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-durability-tier",
                "redis-wait-quorum:1:100",
                "--cpstore-etcd-endpoint",
                "http://127.0.0.1:2379",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--cpstore-etcd-endpoint names the replay store")
                && err.contains("--replay-redis-url"),
            "a CP endpoint under a Redis tier must fail closed naming both: {err}"
        );
    }

    /// And the argv form of the pair — two stores at once — is the adapter's, because the
    /// request has no second slot for the boundary to find one in.
    #[test]
    fn naming_both_replay_stores_on_the_command_line_fails_closed() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-durability-tier",
                "redis-wait-quorum:1:100",
                "--cpstore-etcd-endpoint",
                "http://127.0.0.1:2379",
            ]),
        );
        a.splice(
            0..0,
            args(&["--replay-redis-url", "redis://127.0.0.1:6379"]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("both name the replay store"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "cluster",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("unknown replay durability tier"), "got: {err}");
    }

    #[test]
    fn revocation_tier_defaults_to_bounded_cache_tier_1() {
        // Absent --revocation-tier preserves the Tier-1 bounded-cache posture with
        // the deployment-default window T (existing behavior unchanged).
        let config = parse_args(&minimal_durable()).expect("parse");
        assert_eq!(
            config.request_signer_currency,
            crate::deployment_request::RequestSignerCurrencyRequest::BoundedCache {
                t_secs: crate::trust_plane::DEFAULT_T_SECS,
                reload_secs: None,
            }
        );
    }

    #[test]
    fn parses_each_revocation_tier() {
        use crate::deployment_request::RequestSignerCurrencyRequest as Currency;
        use crate::deployment_request::TrustEpochStoreRequest;
        for (flag, expected) in [
            (
                "bounded-cache:90",
                Currency::BoundedCache {
                    t_secs: 90,
                    reload_secs: Some(30),
                },
            ),
            ("live", Currency::Live { reload_secs: 30 }),
            (
                "push:30",
                Currency::Push {
                    t_secs: 30,
                    reload_secs: 30,
                    epoch: TrustEpochStoreRequest::default(),
                },
            ),
        ] {
            let mut a = minimal_durable();
            // LIVE and PUSH both state their window in terms of consulting the trust
            // store, so both require a reload cadence to make that true — and one no
            // longer than the window each tier declares.
            a.splice(
                0..0,
                args(&["--revocation-tier", flag, "--trust-reload-secs", "30"]),
            );
            let config = parse_args(&a).unwrap_or_else(|e| panic!("parse {flag}: {e}"));
            assert_eq!(config.request_signer_currency, expected, "flag {flag}");
        }
    }

    /// A tier that advertises a near-zero window must have a store that can change.
    /// Read-once `--trust` makes both LIVE and PUSH claims the binary cannot keep.
    #[test]
    fn live_and_push_tiers_require_a_trust_reload_cadence() {
        for flag in ["live", "push:30"] {
            let mut a = minimal_durable();
            a.splice(0..0, args(&["--revocation-tier", flag]));
            let err = parse_args(&a).expect_err("must be refused without a reload cadence");
            assert!(err.contains("--trust-reload-secs"), "got: {err}");
        }
        // Tier 1 makes no such claim: its window is the cache bound T, which holds
        // whether or not the file is re-read.
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--revocation-tier", "bounded-cache:90"]));
        parse_args(&a).expect("bounded-cache does not require a reload cadence");
    }

    /// PRESENCE is not the guarantee. A cadence longer than the window the tier
    /// advertises leaves the same over-claim the absent-cadence refusal exists to stop:
    /// the startup line promises near-zero while the store changes once a week.
    #[test]
    fn a_cadence_longer_than_the_declared_window_is_refused() {
        for (tier, secs) in [
            ("live", "604800"),
            ("live", "61"),
            ("push:60", "120"),
            // The push fallback window is the tighter of the two ceilings.
            ("push:10", "30"),
            ("bounded-cache:60", "300"),
        ] {
            let mut a = minimal_durable();
            a.splice(
                0..0,
                args(&["--revocation-tier", tier, "--trust-reload-secs", secs]),
            );
            let err = parse_args(&a)
                .expect_err("a cadence longer than the declared window must be refused");
            assert!(
                err.contains("--trust-reload-secs"),
                "tier {tier} cadence {secs}: got {err}"
            );
        }
        // At the ceiling exactly, the claim is keepable — accepted.
        for (tier, secs) in [
            ("live", "60"),
            ("push:60", "60"),
            ("push:10", "10"),
            ("bounded-cache:60", "60"),
            ("bounded-cache:600", "60"),
        ] {
            let mut a = minimal_durable();
            a.splice(
                0..0,
                args(&["--revocation-tier", tier, "--trust-reload-secs", secs]),
            );
            parse_args(&a)
                .unwrap_or_else(|e| panic!("tier {tier} cadence {secs} must be accepted: {e}"));
        }
    }

    /// ADR-MCPS-035: the ABSENT case has to be the safe one. An invocation that never
    /// passes `--audit-sink` — the container run directly, a harness, a unit file — must
    /// still write the per-request attribution record.
    #[test]
    fn the_audit_sink_defaults_to_on() {
        let config = parse_args(&minimal_durable()).expect("minimal durable config parses");
        assert_eq!(config.audit_sink, AuditSinkKind::Stderr);
        // Turning it off stays possible, but only by naming it.
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--audit-sink", "none"]));
        assert_eq!(
            parse_args(&a).expect("explicit none parses").audit_sink,
            AuditSinkKind::None
        );
    }

    #[test]
    fn rejects_unknown_or_malformed_revocation_tier() {
        for flag in ["ocsp", "bounded-cache", "push:0", "bounded-cache:-1"] {
            let mut a = minimal();
            a.splice(0..0, args(&["--revocation-tier", flag]));
            assert!(
                parse_args(&a).is_err(),
                "revocation tier '{flag}' must be rejected"
            );
        }
    }

    #[test]
    fn unknown_flag_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--bogus", "x"]));
        assert!(parse_args(&a).unwrap_err().contains("--bogus"));
    }

    // --- #3839 offline CRL flags ---------------------------------------------

    #[test]
    fn default_has_no_crls_and_fails_closed_on_unknown_status() {
        let config = parse_args(&minimal_durable()).expect("parse");
        assert!(
            config.peer_revocation.lists.paths.is_empty(),
            "no CRLs by default (revocation checking disabled until configured)"
        );
        // Unknown CRL revocation status is ALWAYS denied (fail closed) — there is no
        // relax knob to assert.
    }

    #[test]
    fn parses_a_single_client_crl_path() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--client-crl", "/etc/mcp-re/clients.crl"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.peer_revocation.lists.paths,
            vec!["/etc/mcp-re/clients.crl".to_string()]
        );
    }

    #[test]
    fn parses_comma_separated_client_crls() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--client-crl", "/a.crl,/b.crl,/c.crl"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.peer_revocation.lists.paths,
            vec![
                "/a.crl".to_string(),
                "/b.crl".to_string(),
                "/c.crl".to_string()
            ]
        );
    }

    // --- ADR-MCPRE-051 §3 async HTTP inner backends --------------------------

    #[test]
    fn parses_repeated_and_comma_separated_inner_http_urls() {
        let mut a = minimal_without_inner_command();
        a.extend(durable_replay());
        a.extend(args(&[
            "--inner-http-url",
            "http://10.0.0.1:8080/mcp,http://10.0.0.2:8080/mcp",
            "--inner-http-url",
            "http://10.0.0.3:8080/mcp",
        ]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.inner_http_urls,
            vec![
                "http://10.0.0.1:8080/mcp".to_string(),
                "http://10.0.0.2:8080/mcp".to_string(),
                "http://10.0.0.3:8080/mcp".to_string(),
            ]
        );
    }

    // --- ADR-MCPRE-051 §1 per-core worker count (--cores) --------------------

    #[test]
    fn cores_defaults_to_auto_zero() {
        let mut a = minimal_without_inner_command();
        a.extend(durable_replay());
        a.extend(args(&["--inner-http-url", "http://10.0.0.1:8080/mcp"]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.cores, 0,
            "unset --cores means auto (0 = one worker per core)"
        );
    }

    #[test]
    fn parses_explicit_cores() {
        let mut a = minimal_without_inner_command();
        a.extend(durable_replay());
        a.extend(args(&[
            "--inner-http-url",
            "http://10.0.0.1:8080/mcp",
            "--cores",
            "4",
        ]));
        let config = parse_args(&a).expect("parse");
        assert_eq!(config.cores, 4);
    }

    #[test]
    fn non_numeric_cores_fails_closed() {
        let mut a = minimal_without_inner_command();
        a.extend(args(&[
            "--inner-http-url",
            "http://10.0.0.1:8080/mcp",
            "--cores",
            "many",
        ]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--cores"),
            "non-numeric --cores must fail with a --cores message; got: {err}"
        );
    }

    #[test]
    fn empty_inner_http_url_segment_fails_closed() {
        let mut a = minimal();
        a.splice(0..0, args(&["--inner-http-url", "http://a,,http://b"]));
        assert!(
            parse_args(&a).unwrap_err().contains("--inner-http-url"),
            "an empty URL segment must be a hard parse error"
        );
    }

    #[test]
    fn missing_inner_http_url_fails_closed() {
        // The async serving path requires at least one HTTP inner backend; a config
        // with none must fail closed.
        let err = parse_args(&minimal_without_inner_command()).unwrap_err();
        assert!(
            err.contains("--inner-http-url"),
            "missing inner plane must name --inner-http-url; got: {err}"
        );
    }

    // --- ADR-MCPS-013 policy-layer revocation (fail-closed) ------------------

    #[test]
    fn authz_off_does_not_require_a_revocation_list() {
        // The default (authz off) wires no policy enforcement, so revocation is
        // moot — the guard must not spuriously demand a deny-list.
        let config = parse_args(&minimal_durable()).expect("parse");
        assert_eq!(config.authorization.kind, AuthzKind::Off);
        assert!(config.authorization.revocation_list_paths.is_empty());
    }

    // NOTE: `--authz reference` is NEVER accepted — the reference profile is a
    // conformance implementation, not the production authorization authority, and
    // there is no ack to override this (see `authz_reference_is_refused`).
    // `--revocation-list` itself still parses (authz stays off), exercised below.

    /// The deny-list parses into the config, but a config that CARRIES one is refused:
    /// nothing consults it while authz is off, so accepting it would be a silent
    /// no-op on a control the operator believes is enforcing.
    #[test]
    fn a_supplied_revocation_list_is_refused_because_nothing_consults_it() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--revocation-list", "/a,/b,/c"]));
        let err = parse_args(&a).expect_err("a deny-list that enforces nothing must be refused");
        assert!(err.contains("--revocation-list"), "got: {err}");
        assert!(err.contains("enforce NOTHING"), "got: {err}");
    }

    /// A trailing or doubled comma must not silently contribute a deny-list entry that
    /// names no file. The split is the CLI's; what the resulting list may contain is X6's,
    /// which refuses a deny-list no authorization profile will read at all.
    #[test]
    fn empty_revocation_list_segment_is_rejected() {
        let mut a = minimal();
        a.splice(0..0, args(&["--revocation-list", "/a,,/b"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--revocation-list"), "got: {err}");
    }

    #[test]
    fn authz_reference_is_refused() {
        // ADR-MCPS-013 (audit #94 F1/F2/F4): the reference profile is a real,
        // signature-verifying profile, but it is a conformance/reference impl, NOT the
        // production authority — and there is no ack to override that. `--authz
        // reference` is refused at parse time even with a revocation list supplied.
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--authz",
                "reference",
                "--revocation-list",
                "/etc/mcp-re/revoked",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--authz reference") && err.contains("ADR-MCPS-013"),
            "expected a reference-authz refusal, got: {err}"
        );
    }

    #[test]
    fn repeated_client_crl_flags_accumulate() {
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&["--client-crl", "/a.crl", "--client-crl", "/b.crl"]),
        );
        let config = parse_args(&a).expect("parse");
        assert_eq!(
            config.peer_revocation.lists.paths,
            vec!["/a.crl".to_string(), "/b.crl".to_string()]
        );
    }

    #[test]
    fn empty_client_crl_segment_errors() {
        // A trailing comma (or empty value) must not silently load zero CRLs and
        // quietly disable revocation — it is a clear error. The `CrlRevocation` machine
        // owns what the resulting list may contain.
        let mut a = minimal();
        a.splice(0..0, args(&["--client-crl", "/a.crl,"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--client-crl contains an empty path"),
            "got: {err}"
        );
    }

    // --- #4030 online OCSP flag parsing -------------------------------------

    #[test]
    fn default_has_online_ocsp_off_and_hard_fail() {
        let config = parse_args(&minimal_durable()).expect("parse");
        assert!(
            !config.peer_revocation.online.is_required(),
            "online revocation evidence is NOT required by default (the offline-list \
             posture is preserved)"
        );
        // Online OCSP ALWAYS hard-fails on an indeterminate result — no soft-fail knob.
        assert!(config.peer_revocation.online.responder_override().is_none());
    }

    #[test]
    fn parses_client_ocsp_require_and_knobs() {
        // `--ocsp-soft-fail` is a rejected qualifier (the hard-fail posture is
        // unconditional), so only the require mode + responder URL are exercised.
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&[
                "--client-ocsp",
                "require",
                "--ocsp-responder-url",
                "http://ocsp.example.test/r",
            ]),
        );
        // `--client-ocsp require` fails closed at parse time in EVERY build: without
        // the feature the OCSP code is absent, and with it the code exists but the
        // async serving fleet never calls it. Announcing enforcement that does not
        // happen is the defect this refusal removes.
        let err = parse_args(&a).expect_err("--client-ocsp require must fail closed");
        assert!(err.contains("cannot be honored"), "got: {err}");
        assert!(
            err.contains("--client-crl"),
            "the error must name the working alternative; got: {err}"
        );
    }

    #[test]
    fn unknown_client_ocsp_value_errors() {
        let mut a = minimal();
        a.splice(0..0, args(&["--client-ocsp", "maybe"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("unknown --client-ocsp"), "got: {err}");
    }

    #[test]
    fn responder_url_without_require_errors() {
        // A dangling --ocsp-responder-url (no --client-ocsp require) must not
        // silently do nothing.
        let mut a = minimal();
        a.splice(0..0, args(&["--ocsp-responder-url", "http://x/r"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("--ocsp-responder-url has no effect"),
            "got: {err}"
        );
    }

    #[test]
    fn empty_responder_url_errors() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&["--client-ocsp", "require", "--ocsp-responder-url", "   "]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--ocsp-responder-url is empty"), "got: {err}");
    }

    /// `--client-ocsp require` fails closed in EVERY build configuration — the check
    /// is unreachable from the async serving fleet whether or not the `online_ocsp`
    /// code is compiled in.
    #[test]
    fn client_ocsp_require_fails_closed_in_every_build() {
        let mut a = minimal();
        a.splice(0..0, args(&["--client-ocsp", "require"]));
        let err = parse_args(&a).unwrap_err();
        assert!(
            err.contains("cannot be honored") && err.contains("async fleet"),
            "require must fail closed in every build; got: {err}"
        );
    }

    // --- MCPS-3842 strict/production posture ("reject, not warn") ------------
    //
    // The strict/production posture is UNCONDITIONAL: the proxy always rejects an
    // insecure-posture config at parse time (there is no warn-only mode, and the
    // `--strict`/`--production` qualifiers are refused as redundant). These
    // black-box parser tests assert those hard refusals and the accepting cases.

    #[test]
    fn strict_is_always_on_for_a_safe_config() {
        // The bare in-memory replay default is a #90 violation, so a fully-safe
        // config declares a durable replay backend; it must then parse with no
        // unsafe-config violations (the proxy always runs maximal security).
        let config = parse_args(&minimal_durable()).expect("a fully-safe config must parse");
        assert!(
            unsafe_config_violations(&config).is_empty(),
            "a safe config must have no strict violations"
        );
    }

    /// The boundary consults that rule, so the refusal holds however the config was built.
    ///
    /// `parse_args` cannot produce this config — that is the point. The state is only
    /// reachable by setting the public field, which is what a programmatic caller does.
    #[test]
    fn the_validation_boundary_refuses_a_target_uri_that_binds_nothing() {
        let mut config = parse_args(&minimal_durable()).expect("the durable fixture parses");
        assert!(
            !unsafe_config_violations(&config)
                .iter()
                .any(|violation| violation.contains("--target-uri")),
            "the parsed fixture's absolute target must not be a violation"
        );

        config.target_uri = "/mcp".to_string();
        assert!(
            unsafe_config_violations(&config)
                .iter()
                .any(|violation| violation.contains("--target-uri")),
            "a scheme-less target must be refused at the boundary, not only by the parser"
        );
    }

    // ADR-MCPS-020: strict/production rejects a shared store declared at a tier
    // weaker than REDIS_WAIT_QUORUM.
    #[test]
    fn strict_rejects_weak_replay_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-async",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--replay-durability-tier"), "got: {err}");
        assert!(err.contains("strict-production minimum"), "got: {err}");
    }

    #[test]
    fn strict_accepts_wait_quorum_replay_durability_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-wait-quorum:2:500",
            ]),
        );
        let config = parse_args(&a).expect("wait-quorum tier must be strict-acceptable");
        assert!(
            unsafe_config_violations(&config)
                .iter()
                .all(|v| !v.contains("replay-durability-tier")),
            "wait-quorum must not be a replay-tier strict violation"
        );
    }

    // MCPS-79: --fleet ACCEPTS a shared cache at a strict-production durability tier
    // — the one posture that maintains cross-verifier replay state. No fleet
    // violation must remain.
    #[test]
    fn strict_fleet_accepts_shared_wait_quorum() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--fleet",
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-wait-quorum:2:500",
            ]),
        );
        let config = parse_args(&a).expect("--fleet + shared wait-quorum must parse");
        assert!(config.fleet);
        assert!(
            unsafe_config_violations(&config)
                .iter()
                .all(|v| !v.contains("--fleet")),
            "shared wait-quorum must not be a --fleet strict violation"
        );
    }

    // MCPS-79 (orthogonality): WITHOUT --fleet the deployment is single-node, so the
    // durable FILE cache (ADR-MCPS-014) remains valid — the node is the sole
    // verifier. The --fleet rejection must NOT fire here.
    #[test]
    fn single_node_accepts_file_replay_cache() {
        let config =
            parse_args(&minimal_durable()).expect("single-node must accept a durable file cache");
        assert!(!config.fleet);
        assert!(
            unsafe_config_violations(&config)
                .iter()
                .all(|v| !v.contains("--fleet")),
            "single-node must have no --fleet violation"
        );
    }

    // MCPS-84: a trust-epoch backend is only consumed by the Push tier; pairing it
    // with any other tier is a fail-closed misconfiguration (not silently ignored).
    #[test]
    fn trust_epoch_url_without_push_tier_is_rejected() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&["--trust-epoch-redis-url", "redis://127.0.0.1:6379"]),
        );
        // Default tier is bounded-cache, not push.
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--trust-epoch-redis-url"), "got: {err}");
        assert!(err.contains("push"), "got: {err}");
    }

    // MCPS-84: under --revocation-tier push the trust-epoch URL/key parse and land
    // on the config.
    #[test]
    fn trust_epoch_url_with_push_tier_parses() {
        let mut a = minimal_durable();
        a.splice(
            0..0,
            args(&[
                "--revocation-tier",
                "push:60",
                "--trust-epoch-redis-url",
                "redis://127.0.0.1:6379",
                "--trust-epoch-key",
                "mcp-re:trust:epoch",
                "--trust-reload-secs",
                "60",
            ]),
        );
        let config = parse_args(&a).expect("push + trust-epoch must parse");
        assert_eq!(
            config
                .request_signer_currency
                .epoch()
                .and_then(crate::deployment_request::TrustEpochStoreRequest::locator),
            Some("redis://127.0.0.1:6379")
        );
        assert_eq!(
            config
                .request_signer_currency
                .epoch()
                .and_then(crate::deployment_request::TrustEpochStoreRequest::key),
            Some("mcp-re:trust:epoch")
        );
    }

    // #90 (ADR-MCPS-014/020): a command line that declares no replay configuration is a
    // hard parse error, not a fall-back to something weaker. Saying nothing about replay
    // must not become a way to run without it.
    #[test]
    fn omitting_replay_configuration_is_refused() {
        let err = parse_args(&minimal()).unwrap_err();
        assert!(err.contains("--replay-durability-tier"), "got: {err}");
        // The remedy must name states that can actually start.
        assert!(
            err.contains("redis-wait-quorum") || err.contains("linearizable"),
            "the refusal must name a startable tier: {err}"
        );
    }

    // #90: the horizontally-durable `shared` backend at an adequate tier is NOT a
    // replay strict violation either (the weaker-tier case is covered by
    // `strict_rejects_weak_replay_durability_tier`).
    #[test]
    fn strict_accepts_shared_replay_at_adequate_tier() {
        let mut a = minimal();
        a.splice(
            0..0,
            args(&[
                "--replay-redis-url",
                "redis://127.0.0.1:6379",
                "--replay-durability-tier",
                "redis-wait-quorum:2:500",
            ]),
        );
        let config = parse_args(&a).expect("durable shared replay must parse");
        assert!(
            unsafe_config_violations(&config)
                .iter()
                .all(|v| !v.contains("--replay-durability-tier")),
            "a durable shared replay must not trip the missing-tier violation"
        );
    }

    #[test]
    fn strict_rejects_disabled_cert_lifetime_none() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "none"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--max-client-cert-lifetime"), "got: {err}");
    }

    #[test]
    fn strict_rejects_disabled_cert_lifetime_zero() {
        // `0` parses to the same disabled (None) enforcement as `none`.
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "0"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--max-client-cert-lifetime"), "got: {err}");
    }

    // ADR-MCPS-023 §A1 (MCPS-57), conformance vector (a): a client-cert lifetime
    // ABOVE the 1h ceiling is a hard violation — Mode-A's revocation posture is
    // short-lived certs, so a longer-lived cert cannot be audited as
    // `short_lived_cert`.
    #[test]
    fn strict_rejects_over_ceiling_cert_lifetime() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "24h"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("exceeds the ceiling"), "got: {err}");
        assert!(err.contains("86400s"), "got: {err}");
        assert!(err.contains("short_lived_cert"), "got: {err}");
    }

    // ADR-MCPS-023 §A1: the boundary is inclusive — a lifetime EXACTLY at the 1h
    // ceiling (the default) is acceptable, so a default config is not self-rejecting.
    #[test]
    fn strict_accepts_cert_lifetime_at_ceiling() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "3600"]));
        let config = parse_args(&a).expect("a 1h lifetime must be strict-acceptable");
        assert!(
            unsafe_config_violations(&config)
                .iter()
                .all(|v| !v.contains("max-client-cert-lifetime")),
            "a lifetime at the ceiling must not be a strict violation"
        );
    }

    // ADR-MCPS-023 §A1: a lifetime just BELOW the ceiling is also acceptable.
    #[test]
    fn strict_accepts_cert_lifetime_below_ceiling() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "30m"]));
        let config = parse_args(&a).expect("a 30m lifetime must be strict-acceptable");
        assert!(
            unsafe_config_violations(&config)
                .iter()
                .all(|v| !v.contains("max-client-cert-lifetime")),
            "a lifetime below the ceiling must not be a strict violation"
        );
    }

    // SUPERSEDED by ADR-MCPS-023 §A1 (v0.9, MCPS-57): the earlier MCPS-3842 stance
    // treated a lifetime > 1h as a warning-only recommendation. That is reversed —
    // Mode-A's revocation posture IS the cert lifetime, so a lifetime above the
    // ceiling fails closed. A 2h lifetime is enforced but cannot be audited as
    // `short_lived_cert`, so it is rejected.
    #[test]
    fn strict_rejects_over_ceiling_lifetime_2h() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--max-client-cert-lifetime", "2h"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("exceeds the ceiling"), "got: {err}");
        assert!(err.contains("7200s"), "got: {err}");
    }

    #[test]
    fn strict_rejects_cn_legacy_identity_source() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--transport-identity-source", "cn_legacy"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("cn_legacy"), "got: {err}");
    }

    #[test]
    fn strict_reports_all_violations_at_once() {
        // The error aggregates every parse-time violation so the operator can fix
        // the whole posture in one pass, not one error per restart. A command line that
        // declares no replay configuration is itself a violation and aggregates alongside
        // the cert-lifetime and cn_legacy ones.
        let mut a = minimal(); // declares no replay configuration
        a.splice(
            0..0,
            args(&[
                "--max-client-cert-lifetime",
                "none",
                "--transport-identity-source",
                "cn_legacy",
            ]),
        );
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("--replay-durability-tier"), "got: {err}");
        assert!(err.contains("--max-client-cert-lifetime"), "got: {err}");
        assert!(err.contains("cn_legacy"), "got: {err}");
    }

    // --- #4082 (MCP-RE-MED-1) additional strict/production posture rejections -----
    //
    // M11: the unconditional strict/production posture turns an otherwise
    // decoupled posture into a HARD parse error.

    // M11 — `--transport-binding none` is no longer a selectable value (the only
    // accepted bindings enforce a channel↔signer binding), so it fails closed at
    // argument-parse time.
    #[test]
    fn strict_rejects_transport_binding_none() {
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--transport-binding", "none"]));
        let err = parse_args(&a).unwrap_err();
        assert!(err.contains("unknown --transport-binding"), "got: {err}");
        assert!(err.contains("none"), "got: {err}");
    }

    /// The leading PKCS#11-source flags (no `--tls-key`, no TLS label, no inner
    /// plane). Tests append the #59 toggles and then an `--inner-http-url` inner.
    fn pkcs11_lead_no_tls_key() -> Vec<String> {
        args(&[
            "--bind",
            "127.0.0.1:8443",
            "--audience",
            "did:example:server-1",
            "--server-signer",
            "did:example:server-1",
            "--server-key-id",
            "server-key-1",
            "--key-source",
            "pkcs11",
            "--pkcs11-module",
            "/opt/pkcs11/libmock_pkcs11.so",
            "--pkcs11-pin-file",
            "/etc/mcp-re/pkcs11-pin",
            "--pkcs11-token-label",
            "mcp-re-test",
            "--pkcs11-key-label",
            "mcp-re-response-signing",
            "--signing-key-seed",
            "/unused-seed",
            "--tls-cert",
            "/cert",
            "--client-ca",
            "/ca",
            "--trust",
            "/trust.json",
            "--target-uri",
            "https://mcp.example.com/mcp",
            "--delegated-trust-epoch",
            "epoch-min",
            "--trust-domain",
            "mcp.example.com",
        ])
    }

    fn with_inner_http_url(mut a: Vec<String>) -> Vec<String> {
        a.push("--inner-http-url".to_string());
        a.push("http://127.0.0.1:8080/mcp".to_string());
        a
    }

    /// #59: with `--pkcs11-tls-key-label`, the TLS handshake is DELEGATED to the
    /// token, so `--tls-key` is NOT required (it must not be read from disk) — the
    /// config parses and carries the TLS label.
    #[test]
    fn pkcs11_tls_label_makes_tls_key_optional() {
        let mut a = pkcs11_lead_no_tls_key();
        a.push("--pkcs11-tls-key-label".to_string());
        a.push("mcp-re-tls".to_string());
        a.extend(durable_replay());
        let config = parse_args(&with_inner_http_url(a))
            .expect("delegated TLS path parses without --tls-key");
        let Some(crate::deployment_request::DelegatedChannelKeyRequest::Pkcs11(channel)) =
            channel_key(&config)
        else {
            panic!("a PKCS#11 channel key was named and must be recorded as one");
        };
        assert_eq!(channel.key_label, "mcp-re-tls");
        assert!(matches!(
            config.response_signing.source,
            SigningSourceRequest::Pkcs11(_)
        ));
    }

    /// #59 / #58: `--pkcs11-tls-key-label` (delegated) PLUS an exported `--tls-key`
    /// is contradictory and fails closed via the XOR exclusivity guard.
    #[test]
    fn pkcs11_tls_label_with_exported_tls_key_is_rejected() {
        let mut a = pkcs11_lead_no_tls_key();
        a.push("--pkcs11-tls-key-label".to_string());
        a.push("mcp-re-tls".to_string());
        a.push("--tls-key".to_string());
        a.push("/exported-key".to_string());
        let err = parse_args(&with_inner_http_url(a))
            .expect_err("delegated + exported TLS key must be rejected");
        assert!(
            err.contains("delegated XOR exported"),
            "the rejection must name the XOR rule, got: {err}"
        );
    }

    /// #59: the TLS-key label only has meaning for the PKCS#11 source. A dangling
    /// `--pkcs11-tls-key-label` on a file source would silently do nothing (a false
    /// belief the TLS key is token-resident), so it fails closed.
    #[test]
    fn pkcs11_tls_label_without_pkcs11_source_is_rejected() {
        // Without `--tls-key`, so the only thing wrong with this deployment is where the
        // label says its handshake key lives.
        let mut a = minimal_durable_without("--tls-key");
        a.extend(args(&["--pkcs11-tls-key-label", "mcp-re-tls"]));
        let err = parse_args(&a).expect_err("dangling TLS label must be rejected");
        assert!(
            err.contains("--pkcs11-tls-key-label has no effect without --key-source pkcs11"),
            "got: {err}"
        );
    }

    /// #59: without a TLS-key label the PKCS#11 source keeps the exported-TLS-key
    /// path, so `--tls-key` is STILL required (no silent fallback to a delegated
    /// path that was not requested).
    #[test]
    fn pkcs11_without_tls_label_still_requires_tls_key() {
        let err = parse_args(&with_inner_http_url(pkcs11_lead_no_tls_key()))
            .expect_err("non-delegated pkcs11 must still require --tls-key");
        assert!(err.contains("--tls-key"), "got: {err}");
    }

    #[test]
    fn parse_rejects_bad_values_and_names_each_missing_required_flag() {
        for (flag, val) in [
            ("--client-crl-reload-secs", "abc"),
            ("--max-connections", "abc"),
            ("--max-body-bytes", "abc"),
            ("--max-clock-skew", "abc"),
            ("--request-deadline-secs", "abc"),
            ("--read-timeout-secs", "abc"),
        ] {
            let mut a = minimal_durable();
            a.splice(0..0, args(&[flag, val]));
            assert!(parse_args(&a).is_err(), "{flag} {val} must be rejected");
        }
        // `--authz off` is the explicit no-authz selection (the default value).
        let mut a = minimal_durable();
        a.splice(0..0, args(&["--authz", "off"]));
        assert_eq!(
            parse_args(&a).expect("parse").authorization.kind,
            AuthzKind::Off
        );
        // Dropping any required (flag, value) pair fails closed naming the flag.
        for miss in [
            "--audience",
            "--server-signer",
            "--server-key-id",
            "--tls-cert",
            "--tls-key",
            "--client-ca",
            "--trust",
        ] {
            let mut a = minimal_durable();
            let i = a
                .iter()
                .position(|x| x == miss)
                .expect("required flag present");
            a.drain(i..i + 2);
            let e = parse_args(&a).unwrap_err();
            assert!(e.contains(miss), "missing {miss} must be named; got: {e}");
        }
    }

    /// R9-C001 — an authority a URL parser reads differently from the text it shows.
    ///
    /// `ureq` resolves a request URL with `url::Url::parse` and connects to its
    /// `host_str()`, which reads `https://cloudkms.googleapis.com@evil.example.com` as host
    /// `evil.example.com` with the recognisable half demoted to userinfo. Verified against
    /// url 2.5.8 (what ureq 2.12.1 links): every string below resolves to
    /// `evil.example.com`. That host receives the root-key trust bootstrap — and on GCP a
    /// live workload-identity bearer token authorizing `asymmetricSign` on the ROOT
    /// response-signing key.
    ///
    /// `http://localhost:80@evil.example.com` is the case that also defeats the loopback
    /// exception: deriving the loopback host with `rsplit_once(':')` BEFORE userinfo is
    /// stripped reads `localhost`, so a plaintext bearer token left the machine under a
    /// rule written to stop exactly that.
    #[test]
    fn a_kms_endpoint_whose_authority_carries_userinfo_is_refused() {
        let hostile = [
            "https://cloudkms.googleapis.com@evil.example.com",
            "https://kms.us-east-1.amazonaws.com@evil.example.com/",
            "https://sts.eu-north-1.amazonaws.com@evil.example.com",
            "http://localhost:80@evil.example.com",
            "http://127.0.0.1:8080@evil.example.com",
            "http://localhost@evil.example.com",
            "https://user:pass@evil.example.com",
            "https://@evil.example.com",
        ];
        for flag in [
            "--aws-kms-endpoint",
            "--aws-sts-endpoint",
            "--gcp-kms-endpoint",
        ] {
            for endpoint in hostile {
                let err = crate::config_state::kms_endpoint::validated_kms_endpoint(flag, endpoint)
                    .expect_err("an authority carrying userinfo must be refused");
                assert!(
                    err.contains(flag) && err.contains("userinfo"),
                    "{flag} {endpoint}: the refusal must name the flag and the reason, got \
                     {err:?}"
                );
            }
        }
        // And through the two boundaries a config actually crosses: the argv match arms,
        // and `kms_endpoint_refusals` for a `DeploymentRequest` built in code — the payload
        // fields are public, and an embedder reaches key-source construction without a
        // parser.
        //
        // Three endpoint fields, examined across the two selections that can carry them:
        // one request can no longer hold all three, because AWS and GCP are alternatives
        // rather than siblings.
        for endpoint in hostile {
            for flag in ["--aws-kms-endpoint", "--gcp-kms-endpoint"] {
                let err = with_kms_endpoint(flag, endpoint).expect_err("refused at parse");
                assert!(
                    err.contains(flag) && err.contains("userinfo"),
                    "got {err:?}"
                );
            }
            assert_eq!(
                hostile_endpoint_refusals(SigningSourceRequest::AwsKms(
                    AwsKmsSigningSourceRequest {
                        region: Some("eu-north-1".to_string()),
                        key_id: Some("alias/k".to_string()),
                        endpoint: Some(endpoint.to_string()),
                        use_web_identity: true,
                        sts_endpoint: Some(endpoint.to_string()),
                    }
                ))
                .len(),
                2,
                "{endpoint}: both AWS endpoint fields must be held to the rule"
            );
            assert_eq!(
                hostile_endpoint_refusals(SigningSourceRequest::GcpKms(
                    GcpKmsSigningSourceRequest {
                        key_version: Some("projects/p/..".to_string()),
                        endpoint: Some(endpoint.to_string()),
                        use_metadata: false,
                    }
                ))
                .len(),
                1,
                "{endpoint}: the GCP endpoint field must be held to the rule"
            );
        }
    }

    /// The endpoint refusals a programmatically built request produces for `source`.
    fn hostile_endpoint_refusals(source: SigningSourceRequest) -> Vec<String> {
        let mut config = parse_args(&minimal_durable()).expect("the base config parses");
        config.response_signing.source = source;
        crate::config_state::kms_endpoint::kms_endpoint_refusals(&config)
    }

    /// POSITIVE CONTROL for both refusals above, on all three flags.
    ///
    /// The endpoints an operator actually sets — the public Cloud KMS and KMS/STS hosts, a
    /// regional or VPC-endpoint host, an in-cluster emulator with a port, and the loopback
    /// `http://` emulator lane in every spelling — must still parse. A gate that refused
    /// them all would satisfy every assertion above; that is precisely how round 8 shipped
    /// three fail-closed regressions.
    #[test]
    fn the_kms_endpoints_an_operator_legitimately_sets_are_still_accepted() {
        let legitimate = [
            "https://cloudkms.googleapis.com",
            "https://cloudkms.googleapis.com/",
            "https://us-east1-cloudkms.googleapis.com",
            "https://kms.us-east-1.amazonaws.com",
            "https://sts.eu-north-1.amazonaws.com",
            "https://vpce-0abc123-xy1z.kms.us-east-1.vpce.amazonaws.com",
            "https://kms.emulator.svc.cluster.local:8443",
            "https://10.0.0.5:8443",
            // The LocalStack / KMS-emulator lane, in every spelling.
            "http://localhost:4566",
            "http://localhost:4566/",
            "http://127.0.0.1:4566",
            "http://127.0.0.1:4566/",
            "http://[::1]:4566",
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
        ];
        for flag in [
            "--aws-kms-endpoint",
            "--aws-sts-endpoint",
            "--gcp-kms-endpoint",
        ] {
            for endpoint in legitimate {
                let admitted =
                    crate::config_state::kms_endpoint::validated_kms_endpoint(flag, endpoint);
                assert!(
                    admitted.is_ok(),
                    "{flag} {endpoint} is an endpoint an operator sets and must be accepted, \
                     got {:?}",
                    admitted.err()
                );
            }
        }
        // End to end through both boundaries. `--aws-sts-endpoint` is parsed only alongside
        // `--aws-kms-use-web-identity` (an unrelated coherence rule), so its accept case is
        // proved at the `DeploymentRequest` boundary, which is what `app::run` consults.
        for endpoint in legitimate {
            for flag in ["--aws-kms-endpoint", "--gcp-kms-endpoint"] {
                assert!(
                    with_kms_endpoint(flag, endpoint).is_ok(),
                    "{flag} {endpoint} must parse"
                );
            }
            assert_eq!(
                hostile_endpoint_refusals(SigningSourceRequest::AwsKms(
                    AwsKmsSigningSourceRequest {
                        region: Some("eu-north-1".to_string()),
                        key_id: Some("alias/k".to_string()),
                        endpoint: Some(endpoint.to_string()),
                        use_web_identity: true,
                        sts_endpoint: Some(endpoint.to_string()),
                    }
                )),
                Vec::<String>::new(),
                "{endpoint} must be admissible on both AWS endpoint fields"
            );
            assert_eq!(
                hostile_endpoint_refusals(SigningSourceRequest::GcpKms(
                    GcpKmsSigningSourceRequest {
                        key_version: Some("projects/p/..".to_string()),
                        endpoint: Some(endpoint.to_string()),
                        use_metadata: false,
                    }
                )),
                Vec::<String>::new(),
                "{endpoint} must be admissible on the GCP endpoint field"
            );
        }
    }
}
