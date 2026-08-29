// SPDX-License-Identifier: Apache-2.0
//! The peer-identity flag family, parsed as one — ADR-MCPRE-067 §16.
//!
//! An operator names a `--transport-binding` form and then, flatly, the material for it.
//! The request has one tagged value, so this is the adapter: it accumulates the flags and
//! assembles the form's own payload, discarding nothing silently.
//!
//! **Five refusals live here now.** They were configuration-boundary clauses saying that a
//! value belonged to a form the deployment had not selected. The union makes those pairs
//! unbuildable, so the boundary has nothing left to examine and the parser — the one place
//! that still sees both the form and the stray value — answers them, with the sentences the
//! boundary used to (ADR-MCPRE-067 §7).
//!
//! A sixth moved further than that: `--ingress-pinned-mtls` is not a flag the request
//! carries beside a form, it is the acknowledgement the attested form is BUILT from, so its
//! absence is refused here and cannot be stated anywhere else.

mod stray_value;

use stray_value::split_key;

use crate::deployment_request::{
    AttestedIngressRequest, ChannelCredentialIdentityRequest, IngressAssertionRequest,
    PeerIdentityEvidenceRequest, PinnedChannelAcknowledgement,
};
use crate::transport::IdentityPolicy;

/// Which form the command line named, before its material is known.
///
/// Three, not four: `--transport-binding none` is not a selectable value, so the unbound
/// form has no spelling here. It stays a form a programmatic request can name, and the
/// configuration boundary refuses it there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Form {
    /// `--transport-binding exact`, the default.
    #[default]
    ChannelCredential,
    /// `--transport-binding lb-assertion`.
    IngressAssertion,
    /// `--transport-binding attested-ingress`.
    AttestedIngress,
}

/// The peer-identity inputs, as they accumulate across the argument list.
#[derive(Default)]
pub(super) struct PeerIdentityFlags {
    form: Form,
    identity_field: IdentityPolicy,
    lb_keys: Vec<(String, String)>,
    attestor_keys: Vec<(String, String)>,
    identities: Vec<String>,
    audience: Option<String>,
    pinned_channel: bool,
}

impl PeerIdentityFlags {
    /// Whether this value-taking flag belongs to the family.
    pub(super) fn owns(flag: &str) -> bool {
        matches!(
            flag,
            "--transport-binding"
                | "--transport-identity-source"
                | "--ingress-lb-key"
                | "--ingress-attestor-key"
                | "--ingress-identity"
                | "--ingress-audience"
        )
    }

    /// Read one value-taking flag of the family. [`Self::owns`] decided it is one.
    pub(super) fn take(&mut self, flag: &str, value: &str) -> Result<(), String> {
        match flag {
            "--transport-binding" => self.take_form(value)?,
            "--transport-identity-source" => self.take_identity_field(value)?,
            // ADR-MCPS-023: a trusted verification key, as
            // `<keyid>:<base64url-ed25519-pub>`. Repeatable. The key id is the opaque label
            // an assertion stamps; that the body decodes to a 32-byte Ed25519 key is the
            // configuration boundary's, and an unknown key id fails closed at verification.
            // The two flags are DISTINCT so a Tier-3 LB key can never be mistaken for a
            // Mode-C attestor key.
            "--ingress-lb-key" | "--ingress-attestor-key" => {
                let (key_id, key_b64) = split_key(flag, value)?;
                if flag == "--ingress-lb-key" {
                    self.take_lb_key(key_id, key_b64);
                } else {
                    self.take_attestor_key(key_id, key_b64);
                }
            }
            // ADR-MCPS-023 §C: a trusted ingress identity (repeatable), and the node's own
            // audience, which a v2 assertion's `audience` must equal.
            "--ingress-identity" => self.take_identity(value.to_string()),
            _ => self.take_audience(value.to_string()),
        }
        Ok(())
    }

    /// Read one valueless flag of the family, reporting whether it was one.
    pub(super) fn take_switch(&mut self, flag: &str) -> bool {
        if flag == "--ingress-pinned-mtls" {
            self.take_pinned_channel();
            return true;
        }
        false
    }

    /// Read `--transport-binding`.
    fn take_form(&mut self, value: &str) -> Result<(), String> {
        // `none` is deliberately not a selectable value: the accepted forms all bind the
        // request signer to something the node verified. `Unbound` remains a form a
        // programmatic request can name, and the configuration boundary refuses it there.
        self.form = match value {
            "exact" => Form::ChannelCredential,
            "lb-assertion" => Form::IngressAssertion,
            "attested-ingress" => Form::AttestedIngress,
            other => {
                return Err(format!(
                    "unknown --transport-binding '{other}' \
                     (exact|lb-assertion|attested-ingress)"
                ))
            }
        };
        Ok(())
    }

    /// Read `--transport-identity-source`.
    fn take_identity_field(&mut self, value: &str) -> Result<(), String> {
        self.identity_field = match value {
            "uri_san" => IdentityPolicy::UriSan,
            "dns_san" => IdentityPolicy::DnsSan,
            "cn_legacy" => IdentityPolicy::CnLegacy,
            other => {
                return Err(format!(
                    "unknown --transport-identity-source '{other}' (uri_san|dns_san|cn_legacy)"
                ))
            }
        };
        Ok(())
    }

    /// Read one `--ingress-lb-key`.
    fn take_lb_key(&mut self, key_id: String, key_b64: String) {
        self.lb_keys.push((key_id, key_b64));
    }

    /// Read one `--ingress-attestor-key`.
    fn take_attestor_key(&mut self, key_id: String, key_b64: String) {
        self.attestor_keys.push((key_id, key_b64));
    }

    /// Read one `--ingress-identity`.
    fn take_identity(&mut self, identity: String) {
        self.identities.push(identity);
    }

    /// Read `--ingress-audience`.
    fn take_audience(&mut self, audience: String) {
        self.audience = Some(audience);
    }

    /// Read `--ingress-pinned-mtls`.
    fn take_pinned_channel(&mut self) {
        self.pinned_channel = true;
    }

    /// The form this command line names, with its own material.
    pub(super) fn finish(self) -> Result<PeerIdentityEvidenceRequest, String> {
        self.stray_value_refusal()?;
        Ok(match self.form {
            Form::ChannelCredential => {
                PeerIdentityEvidenceRequest::ChannelCredential(ChannelCredentialIdentityRequest {
                    field: self.identity_field,
                })
            }
            Form::IngressAssertion => {
                PeerIdentityEvidenceRequest::IngressAssertion(IngressAssertionRequest {
                    verification_keys: self.lb_keys,
                })
            }
            Form::AttestedIngress => {
                PeerIdentityEvidenceRequest::AttestedIngress(AttestedIngressRequest {
                    asserted_identity_kind: self.identity_field,
                    attestor_keys: self.attestor_keys,
                    identities: self.identities,
                    audience: self.audience.unwrap_or_default(),
                    pinned_channel: PinnedChannelAcknowledgement::acknowledged(),
                })
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attested() -> PeerIdentityFlags {
        let mut flags = PeerIdentityFlags::default();
        flags.take_form("attested-ingress").expect("a known form");
        flags.take_pinned_channel();
        flags
    }

    /// Every stray value is answered where it is still visible.
    #[test]
    fn a_value_belonging_to_another_form_is_refused_by_the_adapter() {
        /// A flag a case must name in its refusal, and the value that provokes it.
        type Case = (&'static str, fn(&mut PeerIdentityFlags));
        let cases: Vec<Case> = vec![
            ("--ingress-lb-key", |f| {
                f.take_lb_key("a".to_string(), "k".to_string());
            }),
            ("--ingress-attestor-key", |f| {
                f.take_attestor_key("a".to_string(), "k".to_string());
            }),
            ("--ingress-identity", |f| f.take_identity("i".to_string())),
            ("--ingress-audience", |f| f.take_audience("a".to_string())),
            (
                "--ingress-pinned-mtls",
                PeerIdentityFlags::take_pinned_channel,
            ),
        ];
        for (flag, mutate) in cases {
            let mut flags = PeerIdentityFlags::default();
            mutate(&mut flags);
            let err = flags.finish().expect_err("a stray value under exact");
            assert!(err.contains(flag), "{flag}: {err}");
            assert!(err.contains("has no effect without"), "{flag}: {err}");
        }
    }

    /// The negative control: each value under the form that owns it is accepted, so the
    /// assertion above cannot be satisfied by refusing everything.
    #[test]
    fn each_value_under_its_own_form_is_accepted() {
        let mut lb = PeerIdentityFlags::default();
        lb.take_form("lb-assertion").expect("a known form");
        lb.take_lb_key("a".to_string(), "k".to_string());
        assert!(matches!(
            lb.finish().expect("its own form"),
            PeerIdentityEvidenceRequest::IngressAssertion(_)
        ));

        let mut mode_c = attested();
        mode_c.take_attestor_key("a".to_string(), "k".to_string());
        mode_c.take_identity("ingress-1".to_string());
        mode_c.take_audience("https://node/mcp".to_string());
        assert!(matches!(
            mode_c.finish().expect("its own form"),
            PeerIdentityEvidenceRequest::AttestedIngress(_)
        ));
    }

    /// The acknowledgement is not a flag beside the form; it is what the form is built
    /// from. A command line that omits it names no attested form at all.
    #[test]
    fn attested_ingress_without_the_acknowledgement_is_refused() {
        let mut flags = PeerIdentityFlags::default();
        flags.take_form("attested-ingress").expect("a known form");
        flags.take_attestor_key("a".to_string(), "k".to_string());
        let err = flags.finish().expect_err("no acknowledgement");
        assert!(err.contains("--ingress-pinned-mtls"), "{err}");
    }

    /// The default form is the channel credential over the default identity field.
    #[test]
    fn the_default_command_line_names_the_channel_credential() {
        assert_eq!(
            PeerIdentityFlags::default().finish().expect("the default"),
            PeerIdentityEvidenceRequest::default()
        );
    }
}
