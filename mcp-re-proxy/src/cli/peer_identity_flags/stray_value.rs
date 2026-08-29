// SPDX-License-Identifier: Apache-2.0
//! A value belonging to a form this command line did not name, and the pair encoding.
//!
//! Its own module because both are about ARGV rather than about the request: after
//! assembly a form carries only its own material, so a stray value has nowhere to live and
//! the `<keyid>:<pub>` pair has already been split. This is the last place either is
//! visible, which is why the five refusals the configuration boundary used to make live
//! here (ADR-MCPRE-067 §7, §16).

use super::{Form, PeerIdentityFlags};

impl PeerIdentityFlags {
    /// A value belonging to a form this command line did not name.
    ///
    /// After assembly the form has nowhere to put it, so this is the last place it is
    /// visible. The audience is checked for PRESENCE only; whether it names anything is the
    /// configuration boundary's, because an assembled request can still carry an empty one.
    pub(super) fn stray_value_refusal(&self) -> Result<(), String> {
        let lb = matches!(self.form, Form::IngressAssertion);
        let attested = matches!(self.form, Form::AttestedIngress);
        let stray: [(bool, &str); 5] = [
            (
                !self.lb_keys.is_empty() && !lb,
                "--ingress-lb-key|lb-assertion",
            ),
            (
                !self.attestor_keys.is_empty() && !attested,
                "--ingress-attestor-key|attested-ingress",
            ),
            (
                !self.identities.is_empty() && !attested,
                "--ingress-identity|attested-ingress",
            ),
            (
                self.audience.is_some() && !attested,
                "--ingress-audience|attested-ingress",
            ),
            (
                self.pinned_channel && !attested,
                "--ingress-pinned-mtls|attested-ingress",
            ),
        ];
        for (is_stray, case) in stray {
            if is_stray {
                let (flag, form) = case.split_once('|').unwrap_or((case, "exact"));
                return Err(format!(
                    "{flag} has no effect without --transport-binding {form}"
                ));
            }
        }
        // The acknowledgement is what the attested form is built from, so its absence is a
        // command line that cannot name the form at all.
        if attested && !self.pinned_channel {
            return Err(
                "--transport-binding attested-ingress requires --ingress-pinned-mtls: the \
                 attestor→node hop MUST be a pinned mTLS channel (ADR-MCPS-023 §C2); \
                 acknowledge it explicitly or do not enable attested ingress"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// One `<keyid>:<base64url-ed25519-pub>` pair, split.
///
/// The shape is the CLI's encoding of a pair, so it is refused here; what the body decodes
/// to is the configuration boundary's, and it says so about the form that named the key.
pub(super) fn split_key(flag: &str, value: &str) -> Result<(String, String), String> {
    let (key_id, key_b64) = value.split_once(':').ok_or_else(|| {
        format!("invalid {flag} '{value}' (expected <keyid>:<base64url-ed25519-pub>)")
    })?;
    if key_id.is_empty() || key_b64.is_empty() {
        return Err(format!(
            "invalid {flag} '{value}' (empty key id or key body)"
        ));
    }
    Ok((key_id.to_string(), key_b64.to_string()))
}
