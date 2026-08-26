// SPDX-License-Identifier: Apache-2.0
//! Authoritative layer-A rules whose semantic OWNER has not been ruled.
//!
//! Residue means exactly one thing here:
//!
//! > an authoritative layer-A rule that the boundary must enforce, and for which no
//! > narrower owner has yet been ruled.
//!
//! It does not mean "miscellaneous validation we did not know where to put". Every entry
//! below states three things in its doc comment — the proposition it enforces, why layer A
//! is where it must be enforced, and why no narrower owner currently claims it. An entry
//! that cannot state the third belongs in a machine, not here.
//!
//! This file is an architectural work queue. Each function is meant to LEAVE, one at a
//! time, when an owner is ruled for it; what must not happen is the set growing back into
//! one anonymous function whose contents nobody can count. That is what [`INVENTORY`] and
//! its self-check are for: the inventory is derived from this file's own source, so a rule
//! added without registering it fails the build rather than joining a junk drawer.
//!
//! Nothing here decides precedence. `legality_violations` calls each of these at the
//! position its clauses already occupied.

use crate::deployment_request::{AuthzKind, DeploymentRequest, OcspKind};

/// The `--target-uri` shape the request-target reconstruction check depends on, as a pure
/// rule over the configured value.
///
/// ADR-MCPRE-058 §8.3, and the member of this file's former parser-only family with the
/// most direct effect on a served request.
///
/// `async_serve` compares the origin-form of the configured target against the one the
/// request arrived at, and refuses to serve where they differ. That comparison is
/// answerable only for an ABSOLUTE target: `origin_form_of` finds `://` or returns `None`,
/// and `target_uri_mismatch` propagates that `None` as "no mismatch". A blank target
/// short-circuits to `None` one line earlier. So a configured target that is empty or
/// scheme-less does not weaken the check — it disables it, silently, for every request,
/// and the deployment goes on reporting that the binding is in force.
///
/// Both functions say in their own docs that the parser guarantees the shape. It did, and
/// only for argv: `target_uri` is a public `DeploymentRequest` field, so a programmatically built
/// config reaches the serving path having met no parser. An ingress fanning several paths
/// into one process would then verify signatures over a `@target-uri` the request never
/// arrived at, which is the exact scenario the parse-time diagnostic describes.
///
/// The validation boundary is the one caller, so a command line and a struct literal are
/// held to the shape by the same clause.
fn target_uri_violation(uri: &str) -> Option<String> {
    if uri.trim().is_empty() {
        return Some(
            "--target-uri must not be empty: an empty target makes the audience/target \
             binding a tautology (both sides compare equal) instead of binding this \
             deployment's dispatch boundary"
                .to_string(),
        );
    }
    if !uri.contains("://") {
        return Some(format!(
            "--target-uri {uri:?} is not an absolute URI: it must be \
             <scheme>://<authority><path> (e.g. https://proxy.internal:8600/mcp). \
             A scheme-less target disables the request-target reconstruction check \
             entirely, so an ingress fanning several paths into one process would \
             verify signatures over a @target-uri the request never arrived at"
        ));
    }
    None
}

/// The one decision about whether a configured authorization profile can be honored.
///
/// `Some(diagnostic)` means it cannot. Two independent facts make it so, and the
/// diagnostic carries both because an operator needs both to know what to do:
///
/// - the reference profile is a CONFORMANCE implementation, never accepted as the production
///   authority (ADR-MCPS-013), and it was bound to the object carrier ADR-MCPRE-050 retired;
/// - it names no mechanism this build can install: the production mechanism is the carried
///   PDP decision (ADR-MCPRE-065 §8), which no configuration value selects today.
///
/// Either alone is sufficient to refuse. A configured policy that would silently not
/// enforce is the forbidden-claim shape (security-boundary §2).
///
/// One function because this prohibition was once stated TWICE, in two places, with two
/// different messages: in `parse_args` and in the composition root. Neither was at the
/// validation boundary. That was not a bypass — the composition root did catch a
/// programmatically built `DeploymentRequest` — but two independent statements of one prohibition can
/// drift, and a policy decision does not belong in a composition root (ADR-MCPRE-056 §12).
fn unaccepted_authz_profile_refusal(authz: AuthzKind) -> Option<String> {
    (authz == AuthzKind::Reference).then(|| {
        "--authz reference selects the reference/conformance signed-authorization \
         profile, which is NOT accepted as the production authorization authority \
         (ADR-MCPS-013) and was bound to the object carrier this release retired. The \
         production mechanism is the carried PDP decision (ADR-MCPRE-065), which this \
         value does not select and which no configuration installs today. Run --authz off."
            .to_string()
    })
}

/// The one decision about whether `--client-ocsp require` can be honored.
///
/// `Some(diagnostic)` means it cannot. Today that is unconditional, and the reason is a
/// property of the SERVING PATH rather than of the build: `ocsp_rejection` is reached only
/// from `connection_rejection`, which only the blocking serve loops call. The production
/// data plane is the per-core async fleet (ADR-MCPRE-051 §1), which calls
/// `connection_rejection_for_chain` and performs only the offline cert-lifetime and CRL
/// checks. So the responder round trip never happens, with or without the `online_ocsp`
/// feature — without it the code is absent, with it the code is present but never called.
///
/// Accepting it would announce `ONLINE OCSP client-cert revocation enabled` at startup on
/// a deployment that admits every revoked client certificate: the forbidden-claim shape
/// (security-boundary §2). The refusal lifts when the async path performs the round trip
/// off the runtime worker, and this is the single place that would have to change.
///
/// A function rather than an inline condition because it is what
/// [`unsafe_config_violations`] consults, and that is what a programmatically built
/// `DeploymentRequest` meets. Two copies is how the two drifted in the first place: the
/// parser refused, the validation boundary did not, and a caller that skipped the parser
/// reached the serving path with the claim intact.
fn online_ocsp_refusal(client_ocsp: OcspKind) -> Option<String> {
    (client_ocsp == OcspKind::Require).then(|| {
        "--client-ocsp require cannot be honored: online OCSP is implemented only on \
         the blocking serve loop, while the production data plane is the per-core \
         async fleet, which performs no OCSP revocation check. Accepting it would \
         announce enforcement that does not happen. Use --client-crl (with \
         --client-crl-reload-secs for restart-free refresh) for client-certificate \
         revocation on the async serving path."
            .to_string()
    })
}

/// The AIA-override responder, held to its own shape and then to the mode that reads it.
///
/// `--ocsp-responder-url` is the one OCSP parameter, and it parameterizes a mode rather
/// than naming a state, so it has no machine of its own; these are its two columns in the
/// order semantic dependency puts them. A responder that names nothing is a defect in the
/// value; a responder no mode will read is a defect in the combination, and only the second
/// depends on `client_ocsp`.
///
/// The second clause matters even though [`online_ocsp_refusal`] refuses `require`
/// unconditionally: the surviving case is a responder configured beside `--client-ocsp off`,
/// which no clause reaches, and which leaves an operator believing a revocation authority is
/// configured while every certificate is admitted unchecked.
fn ocsp_responder_violations(config: &DeploymentRequest) -> Vec<String> {
    let Some(url) = config.ocsp_responder_url.as_deref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if url.trim().is_empty() {
        out.push(
            "--ocsp-responder-url is empty: it overrides the responder named by the \
             certificate's AIA extension, so an empty value replaces a resolvable authority \
             with none"
                .to_string(),
        );
    }
    if config.client_ocsp != OcspKind::Require {
        out.push(
            "--ocsp-responder-url has no effect without --client-ocsp require: nothing \
             consults a responder in this mode, so the deployment would carry a revocation \
             authority it never asks"
                .to_string(),
        );
    }
    out
}

/// `--client-ocsp require` cannot be honored.
///
/// **Why layer A enforces it.** `client_ocsp` is a public field, so a request built in code reaches the serving path announcing revocation checking that never happens.
///
/// **Why no narrower owner.** It is client-certificate revocation, but CRL and OCSP are different mechanisms: if CRL support were removed tomorrow this rule would still hold, because the async data plane performs no responder round trip. `CrlRevocation` is therefore not its owner, and no OCSP state exists because every OCSP posture is excluded.
pub(super) fn ocsp_mode_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(refusal) = online_ocsp_refusal(config.client_ocsp) {
        out.push(refusal);
    }
    out
}

/// A responder URL must name something, and something must read it.
///
/// **Why layer A enforces it.** A responder configured beside a mode that never consults one leaves an operator believing a revocation authority is in force.
///
/// **Why no narrower owner.** Same as the mode it parameterizes: it belongs to whatever owner OCSP eventually gets.
pub(super) fn ocsp_responder_url_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    out.extend(ocsp_responder_violations(config));
    out
}

/// `--authz reference` is not an accepted production authorization authority.
///
/// **Why layer A enforces it.** Accepting it would surface a capability the serving path does not deliver.
///
/// **Why no narrower owner.** A LOCAL degenerate-posture refusal. X6 mentions `Authz` only because `Authz` is degenerate; colocating there would let a local refusal acquire cross-machine relation semantics.
pub(super) fn authz_profile_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(refusal) = unaccepted_authz_profile_refusal(config.authz) {
        out.push(refusal);
    }
    out
}

/// `--audience` names something.
///
/// **Why layer A enforces it.** It is the audience a verifier binds a response to, and
/// nothing dereferences it — an empty one fails no startup step and simply makes this
/// deployment's evidence indistinguishable from any other deployment that also set none.
///
/// **Why no narrower owner.** It is consumed as an ordinary audience PARAMETER — into
/// `AudienceTuple` beside `--target-uri` and `--route`, and into `CustodyConfig::aud` — not
/// as part of an identity. `ServerIdentity` deliberately does not take it: grouping it with
/// the identity coordinates because they were validated together is how a validation
/// location gets mistaken for an owner. `DelegatedSigning` guards the RESOLVED
/// `audience_hash` that this may default into, which is a different proposition.
pub(super) fn audience_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    if config.audience.trim().is_empty() {
        out.push(
            "--audience is empty: it is the audience verifiers bind a response to, so an \
             empty one makes this deployment's evidence indistinguishable from that of any \
             other deployment that also set none"
                .to_string(),
        );
    }
    out
}

/// The three locators this deployment opens are non-empty.
///
/// **Why layer A enforces it.** That a string names nothing is purely knowable (ADR-MCPRE-056 §5.1); that the file is absent is an observation for materialization.
///
/// **Why no narrower owner.** They span the listener and the TLS plane — no single existing machine owns the set, and inventing one to hold three strings would be the premature abstraction. `--trust` was the fourth until it acquired one: `TrustDocumentSource` exists because a `TrustPlan` has to pair the locator with a sealed revocation posture, which is a reason none of these three have.
pub(super) fn required_locator_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    for (value, message) in [
        (
            config.bind.as_str(),
            "--bind is empty: it names the address this proxy listens on, and an empty value \
             resolves to no address rather than to a default",
        ),
        (
            config.tls_cert.as_str(),
            "--tls-cert is empty: it names the server certificate chain presented on every \
             handshake",
        ),
        (
            config.client_ca.as_str(),
            "--client-ca is empty: it names the roots every client certificate is verified \
             against, which is the whole of who may connect",
        ),
    ] {
        if value.trim().is_empty() {
            out.push(message.to_string());
        }
    }
    out
}

/// The configured `@target-uri` has a shape the reconstruction check can answer.
///
/// **Why layer A enforces it.** An empty or scheme-less target does not weaken the request-target check, it disables it for every request while the deployment reports the binding as in force.
///
/// **Why no narrower owner.** It is the RFC 9421 signature-base binding, not the mTLS channel binding `ChannelBinding` owns and not the version contract `McpTransportContract` owns.
pub(super) fn target_uri_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(refusal) = target_uri_violation(&config.target_uri) {
        out.push(refusal);
    }
    out
}

/// A deployment names at least one inner server.
///
/// **Why layer A enforces it.** It arrived here from the trust plane, which could reject it only after two planes had established resources.
///
/// **Why no narrower owner.** There is no inner-plane machine; the request carries a list and nothing classifies it into states.
pub(super) fn inner_plane_presence_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    if config.inner_http_urls.is_empty() {
        out.push(
            "the proxy serves over an async HTTP inner plane: pass --inner-http-url <url>. To \
             protect a local stdio MCP server, run it behind the mcp-re-stdio-bridge adapter \
             and point --inner-http-url at the bridge."
                .to_string(),
        );
    }
    out
}

/// No inner-server URL is blank.
///
/// **Why layer A enforces it.** A list holding `""` satisfies the presence clause and then contributes a backend the pool can never reach — a trailing comma produces exactly that.
///
/// **Why no narrower owner.** Same absent owner as the presence clause it follows.
pub(super) fn inner_plane_structure_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    if config
        .inner_http_urls
        .iter()
        .any(|url| url.trim().is_empty())
    {
        out.push(
            "--inner-http-url contains an empty URL: every backend in the inner plane must \
             name one, or the pool carries a member no request can be forwarded to"
                .to_string(),
        );
    }
    out
}

/// The concurrent-connection ceiling is not zero.
///
/// **Why layer A enforces it.** A limit of zero disables the control it bounds, which is a security posture whatever tier it sits in.
///
/// **Why no narrower owner.** `ServerLimits` is a materialized runtime type, not a layer-A machine; no owner classifies its quantities into states.
pub(super) fn connection_ceiling_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    if config.limits.max_concurrent_connections == 0 {
        out.push(
            "--max-connections 0 accepts no connection at all: there is no \"unlimited\" \
             spelling, because an unbounded connection count is attacker-controlled \
             buffering ahead of the verify gate. Set a positive ceiling"
                .to_string(),
        );
    }
    out
}

/// The drain window is not zero.
///
/// **Why layer A enforces it.** Same class as the ceiling above: a bound of zero is the absence of the bound.
///
/// **Why no narrower owner.** Same absent owner as the ceiling.
pub(super) fn drain_window_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    if config.limits.drain_grace.is_zero() {
        out.push(
            "--drain-grace-secs 0 abandons every in-flight request on SIGTERM: the drain \
             window is what lets an admitted request finish before the listener goes away, \
             and the k8s invariant request_deadline <= drain_grace < \
             terminationGracePeriodSeconds cannot hold with a zero window. Set a positive \
             window (default 30s)"
                .to_string(),
        );
    }
    out
}

/// The read, write and request-deadline timeouts are all set.
///
/// **Why layer A enforces it.** They are the slow-loris defense; a disabled one removes it for every connection.
///
/// **Why no narrower owner.** Same absent owner as the two limits above — the `ServerLimits` quantities have no layer-A machine.
pub(super) fn slow_loris_timeout_violations(config: &DeploymentRequest) -> Vec<String> {
    let mut out = Vec::new();
    for (value, flag) in [
        (config.limits.read_timeout, "--read-timeout-secs"),
        (config.limits.write_timeout, "--write-timeout-secs"),
        (config.limits.request_deadline, "--request-deadline-secs"),
    ] {
        if value.is_none() {
            out.push(format!(
                "{flag} 0 disables a slow-loris defense: a peer that trickles bytes then \
                 holds a serve slot indefinitely, up to --max-connections, with no \
                 fail-closed drop. Set a bounded value (default 30s)"
            ));
        }
    }
    out
}

/// Every ownerless obligation in this file, by name.
///
/// Hand-maintained lists drift, so this one is CHECKED against the file it describes
/// rather than trusted. Any count that appears in prose or a commit message should be
/// derived from here — `INVENTORY.len()` — and never typed.
/// Compiled only for the self-check: it exists to be COMPARED with this file, not to be
/// read at runtime. A residue rule is invoked by name from the orchestrator, so nothing in
/// the shipped binary needs the list — only the test that keeps it honest does.
#[cfg(test)]
pub(super) const INVENTORY: &[&str] = &[
    "ocsp_mode_violations",
    "ocsp_responder_url_violations",
    "authz_profile_violations",
    "audience_violations",
    "required_locator_violations",
    "target_uri_violations",
    "inner_plane_presence_violations",
    "inner_plane_structure_violations",
    "connection_ceiling_violations",
    "drain_window_violations",
    "slow_loris_timeout_violations",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// THM-0013 evidence, half one: no build honours `--client-ocsp require`.
    ///
    /// Asserted on the predicate the validation boundary consults, and over BOTH modes, so
    /// the claim is the biconditional the theorem states rather than "one refusal exists".
    /// The result is feature-independent by construction: nothing here reads a `cfg`, which
    /// is the point — a deployment cannot buy online OCSP by rebuilding with the backend.
    #[test]
    fn no_build_admits_the_online_ocsp_mode() {
        let refusal = online_ocsp_refusal(OcspKind::Require)
            .expect("--client-ocsp require is refused in every build");
        assert!(
            refusal.contains("--client-ocsp require cannot be honored"),
            "the refusal must name the flag it refuses, got: {refusal}"
        );
        assert!(
            refusal.contains("--client-crl"),
            "and it must name the mechanism that does work on the async plane: {refusal}"
        );
        assert!(
            online_ocsp_refusal(OcspKind::Off).is_none(),
            "the OFF posture is the one the legality model admits"
        );
    }

    /// THM-0013 evidence, half two: the refusal is on the route to a validated deployment.
    ///
    /// The predicate above could be correct and unreached. This asserts it through
    /// `ocsp_mode_violations`, which is what the boundary's clause list calls, so what is
    /// measured is the rule's PLACEMENT and not only its content. Together the two halves
    /// give the theorem: every validated deployment has online OCSP off.
    #[test]
    fn the_boundary_clause_carries_the_online_ocsp_refusal() {
        let mut config = crate::config_state::test_support::legal_config();
        assert!(
            ocsp_mode_violations(&config).is_empty(),
            "the legal fixture does not request online OCSP"
        );
        config.client_ocsp = OcspKind::Require;
        let violations = ocsp_mode_violations(&config);
        assert_eq!(
            violations.len(),
            1,
            "exactly one clause answers for the mode: {violations:?}"
        );
        assert!(violations[0].contains("--client-ocsp require cannot be honored"));
    }

    /// The inventory names exactly the residue rules this file defines.
    ///
    /// Reads its own source at compile time, so adding a `pub(super) fn` without
    /// registering it — or registering one that no longer exists — fails here. Without
    /// this the inventory would be prose about the code rather than a statement of it,
    /// which is the drift this whole campaign keeps finding.
    /// ADR-MCPRE-058 §8.3: the rule the request-target reconstruction check depends on,
    /// asserted directly on the pure predicate.
    ///
    /// The shapes that matter are the ones `origin_form_of` cannot answer for. A
    /// scheme-less or empty target makes `target_uri_mismatch` return `None` for every
    /// request, which reads as "consistent" — so the check does not weaken, it disappears.
    #[test]
    fn a_target_uri_that_would_disable_the_reconstruction_check_is_refused() {
        for absolute in [
            "https://proxy.internal:8600/mcp",
            "http://127.0.0.1:8600/",
            "https://proxy.internal",
        ] {
            assert!(
                target_uri_violation(absolute).is_none(),
                "an absolute target is the supported shape: {absolute}"
            );
        }
        for unusable in [
            "",
            "   ",
            "/mcp",
            "proxy.internal:8600/mcp",
            "proxy.internal",
        ] {
            let refusal = target_uri_violation(unusable)
                .unwrap_or_else(|| panic!("{unusable:?} leaves the check unanswerable"));
            assert!(
                refusal.contains("--target-uri"),
                "the refusal must name the flag, got: {refusal}"
            );
        }
    }

    #[test]
    fn the_inventory_is_the_file() {
        let source = include_str!("residue.rs");
        let defined: Vec<&str> = source
            .lines()
            .filter_map(|l| l.strip_prefix("pub(super) fn "))
            .filter_map(|l| l.split('(').next())
            .collect();
        assert_eq!(
            defined, INVENTORY,
            "the residue inventory and the functions defined in residue.rs have diverged"
        );
        assert!(
            !INVENTORY.is_empty(),
            "an empty inventory would make this test vacuous"
        );
    }
}
