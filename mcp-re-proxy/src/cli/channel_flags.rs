// SPDX-License-Identifier: Apache-2.0
//! The channel credential's chain, the anchors peers are held to, and their window.
//!
//! The KEY is not here: which key establishes the channel is one arm of the signing-source
//! family's tagged value, and `--tls-key` is read there. What is left is the material every
//! custody needs, plus the ceiling a peer credential authorizes traffic for.

use crate::deployment_request::{ChannelCredentialRequest, ChannelKeyRequest};
use std::time::Duration;

/// The channel inputs, as they accumulate across the argument list.
#[derive(Default)]
pub(super) struct ChannelFlags {
    credential_chain: Option<String>,
    peer_trust_anchors: Option<String>,
    max_client_cert_lifetime: Option<Option<Duration>>,
}

/// What one deployment establishes channels with, and who may use them.
#[derive(Debug)]
pub(super) struct ChannelSurface {
    pub(super) credential: ChannelCredentialRequest,
    pub(super) peer_trust_anchors: String,
    pub(super) max_client_cert_lifetime: Option<Duration>,
}

impl ChannelFlags {
    /// Whether this value-taking flag belongs to the family.
    pub(super) fn owns(flag: &str) -> bool {
        matches!(
            flag,
            "--tls-cert" | "--client-ca" | "--max-client-cert-lifetime"
        )
    }

    /// Read one flag of the family. [`Self::owns`] decided it is one.
    pub(super) fn take(&mut self, flag: &str, value: &str) -> Result<(), String> {
        match flag {
            "--tls-cert" => self.credential_chain = Some(value.to_string()),
            "--client-ca" => self.peer_trust_anchors = Some(value.to_string()),
            _ => self.max_client_cert_lifetime = Some(parse_cert_lifetime(value)?),
        }
        Ok(())
    }

    /// The channel surface, assembled around the key the signing-source family read.
    ///
    /// The key arrives from there rather than being read here because it is one arm of that
    /// family's tagged value: `--tls-key` and a delegated key object are alternatives, and
    /// only the family that owns both can refuse a command line naming both.
    pub(super) fn finish(
        self,
        key: ChannelKeyRequest,
        default_cert_lifetime: Option<Duration>,
    ) -> Result<ChannelSurface, String> {
        Ok(ChannelSurface {
            credential: ChannelCredentialRequest {
                credential_chain: super::require(self.credential_chain, "--tls-cert")?,
                key,
            },
            peer_trust_anchors: super::require(self.peer_trust_anchors, "--client-ca")?,
            max_client_cert_lifetime: self
                .max_client_cert_lifetime
                .unwrap_or(default_cert_lifetime),
        })
    }
}

/// Parse a client-cert lifetime: a number with an optional `h`/`m`/`s` suffix
/// (bare = seconds), or `none`/`0` to disable enforcement. E.g. `1h`, `30m`,
/// `3600`, `none`.
fn parse_cert_lifetime(value: &str) -> Result<Option<Duration>, String> {
    if value == "none" {
        return Ok(None);
    }
    let (digits, multiplier) = match value.strip_suffix('h') {
        Some(d) => (d, 3600),
        None => match value.strip_suffix('m') {
            Some(d) => (d, 60),
            None => (value.strip_suffix('s').unwrap_or(value), 1),
        },
    };
    let n: u64 = digits.parse().map_err(|_| {
        format!("invalid --max-client-cert-lifetime '{value}' (e.g. 1h, 30m, 3600, none)")
    })?;
    // Checked, because the wrapped product is a DIFFERENT lifetime rather than a larger
    // one: `5124095576030432h` wraps to 3584s, under the ceiling, so nothing downstream
    // refuses it and the deployment enforces a bound the operator never wrote.
    let secs = n.checked_mul(multiplier).ok_or_else(|| {
        format!(
            "--max-client-cert-lifetime '{value}' does not fit in seconds; the ceiling is {}s",
            crate::config_state::transport::MAX_CLIENT_CERT_LIFETIME.as_secs()
        )
    })?;
    Ok(if secs == 0 {
        None
    } else {
        Some(Duration::from_secs(secs))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment_request::ExportedChannelKeyRequest;

    fn exported() -> ChannelKeyRequest {
        ChannelKeyRequest::ExportedFile(ExportedChannelKeyRequest {
            key_path: "/key".to_string(),
        })
    }

    /// The chain and the anchors are required, and the refusal names the missing one.
    #[test]
    fn the_chain_and_the_anchors_are_required() {
        for flag in ["--tls-cert", "--client-ca"] {
            let mut flags = ChannelFlags::default();
            for (other, value) in [("--tls-cert", "/cert"), ("--client-ca", "/ca")] {
                if other != flag {
                    flags.take(other, value).expect("a locator");
                }
            }
            let err = flags
                .finish(exported(), None)
                .expect_err("one locator is missing");
            assert!(err.contains(flag), "{flag}: {err}");
        }
    }

    /// An omitted lifetime takes the deployment default; a given one wins. The two are
    /// distinguishable, which a field defaulted at parse time could not be.
    #[test]
    fn an_omitted_lifetime_takes_the_default_and_a_given_one_wins() {
        let mut flags = ChannelFlags::default();
        flags.take("--tls-cert", "/cert").expect("a locator");
        flags.take("--client-ca", "/ca").expect("a locator");
        let default = Some(Duration::from_secs(3600));
        let surface = flags.finish(exported(), default).expect("a surface");
        assert_eq!(surface.max_client_cert_lifetime, default);
        assert_eq!(surface.credential.credential_chain, "/cert");
    }
}
