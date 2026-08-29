// SPDX-License-Identifier: Apache-2.0
//! The online revocation-evidence checker (RFC 6960 over the `online_ocsp` backend).

use crate::deployment_request::DeploymentRequest;

/// Build the ONLINE OCSP checker selected by `--client-ocsp require` (#4030),
/// or `None` when `--client-ocsp off` (the default). Compiled ONLY under the
/// `online_ocsp` feature; the validation boundary already fails closed for `require` in
/// every build, so this is only reached with the backend present.
///
/// The checker uses `ocsp_responder_url` as the AIA override (else the leaf's
/// AIA OCSP URL) and ALWAYS fails closed on an indeterminate result (the
/// `--ocsp-soft-fail` fail-open relaxation was removed). Its HTTP fetch carries a
/// mandatory timeout (fail closed on timeout) so it can never wedge the blocking
/// serve loop.
#[cfg(feature = "online_ocsp")]
pub fn build_ocsp_checker(config: &DeploymentRequest) -> Option<crate::ocsp::OcspChecker> {
    // Hard-fail (fail closed) always: OCSP has no soft-fail knob any more.
    config.peer_revocation.online.is_required().then(|| {
        crate::ocsp::OcspChecker::new(
            config
                .peer_revocation
                .online
                .responder_override()
                .map(str::to_string),
            false,
        )
    })
}
