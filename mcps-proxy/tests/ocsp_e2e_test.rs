//! Black-box end-to-end test for the ONLINE OCSP client-cert revocation check
//! (issue #4030), exercised against an INDEPENDENT OpenSSL test OCSP responder.
//!
//! This proves the real online path end to end: the [`OcspChecker`] builds a
//! SHA-256 CertID OCSP request, POSTs it to a live responder, decodes the
//! response, and reports `Good` for a known-good certificate and `Revoked` for a
//! known-revoked certificate — WITHOUT a restart between them (the responder's
//! index reflects the revocation). The deterministic codec/mapping/policy pieces
//! are covered network-free by the unit tests in `src/ocsp.rs`; this test adds
//! the live-responder proof the issue requires.
//!
//! # Environment gating
//! The test runs ONLY when `MCPS_TEST_OCSP_RESPONDER_URL` is set; otherwise it
//! prints a SKIP notice and returns success (not every environment has an OCSP
//! responder provisioned, and this build does not bundle one). When run, it
//! reads:
//!   * `MCPS_TEST_OCSP_RESPONDER_URL` — the responder URL, e.g.
//!     `http://127.0.0.1:8888`.
//!   * `MCPS_TEST_OCSP_ISSUER_DER`    — path to the issuing CA certificate (DER).
//!   * `MCPS_TEST_OCSP_GOOD_DER`      — path to a known-GOOD leaf cert (DER),
//!     issued by that CA and NOT revoked in the responder's index.
//!   * `MCPS_TEST_OCSP_REVOKED_DER`   — path to a known-REVOKED leaf cert (DER),
//!     issued by that CA and revoked in the responder's index.
//!
//! This test does NOT spawn the responder; provision it once (by a human / CI)
//! with the OpenSSL recipe below and leave it running, then run this test.
//!
//! # Provisioning a SHA-256 OpenSSL test responder (run once; NOT by this test)
//! ```sh
//! # 0. A CA + an OpenSSL CA database (index.txt) are assumed; the steps below
//! #    create a throwaway CA, two leaves, revoke one, and start a responder that
//! #    answers SHA-256 CertIDs (the algorithm this checker sends).
//!
//! # 1. Throwaway CA:
//! openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt \
//!     -subj "/CN=mcps-ocsp-test-ca" -days 2 -addext "keyUsage=keyCertSign,cRLSign"
//! : > index.txt ; echo 01 > serial ; echo 1000 > crlnumber
//!
//! # 2. OpenSSL CA config (minimal) — note the OCSP responder URL baked into the
//! #    leaf's authorityInfoAccess so AIA extraction also works:
//! cat > ca.cnf <<'EOF'
//! [ ca ]
//! default_ca = CA_default
//! [ CA_default ]
//! database = index.txt
//! serial = serial
//! certificate = ca.crt
//! private_key = ca.key
//! default_md = sha256
//! policy = pol
//! x509_extensions = leaf_ext
//! [ pol ]
//! commonName = supplied
//! [ leaf_ext ]
//! authorityInfoAccess = OCSP;URI:http://127.0.0.1:8888
//! EOF
//!
//! # 3. Two leaves signed by the CA:
//! for n in good revoked; do
//!   openssl req -newkey rsa:2048 -nodes -keyout $n.key -out $n.csr -subj "/CN=$n.leaf"
//!   openssl ca -batch -config ca.cnf -in $n.csr -out $n.crt -days 1
//! done
//!
//! # 4. Revoke ONE of them (updates index.txt; no responder restart needed):
//! openssl ca -batch -config ca.cnf -revoke revoked.crt
//!
//! # 5. Start the responder answering SHA-256 CertIDs (-sha256 is REQUIRED — this
//! #    checker sends SHA-256 CertIDs and the responder must match):
//! openssl ocsp -port 8888 -index index.txt -CA ca.crt \
//!     -rkey ca.key -rsigner ca.crt -sha256 -text &
//!
//! # 6. Convert to DER and export the env vars this test reads:
//! for f in ca good revoked; do openssl x509 -in $f.crt -outform DER -out $f.der; done
//! export MCPS_TEST_OCSP_RESPONDER_URL=http://127.0.0.1:8888
//! export MCPS_TEST_OCSP_ISSUER_DER=$PWD/ca.der
//! export MCPS_TEST_OCSP_GOOD_DER=$PWD/good.der
//! export MCPS_TEST_OCSP_REVOKED_DER=$PWD/revoked.der
//!
//! # 7. Run the feature-gated test:
//! cargo test -p mcps-proxy --features online_ocsp --test ocsp_e2e_test
//! ```
#![cfg(feature = "online_ocsp")]

use mcps_proxy::CertRevocationStatus;
use mcps_proxy::OcspChecker;

/// Read the responder URL + the three DER paths; `None` (skip) unless
/// `MCPS_TEST_OCSP_RESPONDER_URL` is set. The DER paths default to files in the
/// cwd matching the provisioning recipe so a minimal
/// `MCPS_TEST_OCSP_RESPONDER_URL=... cargo test` works against that layout.
fn ocsp_env() -> Option<(String, String, String, String)> {
    let Ok(url) = std::env::var("MCPS_TEST_OCSP_RESPONDER_URL") else {
        if std::env::var("MCPS_REQUIRE_LIVE_INFRA").is_ok_and(|v| !v.is_empty()) {
            panic!(
                "MCPS_REQUIRE_LIVE_INFRA is set but MCPS_TEST_OCSP_RESPONDER_URL is unavailable \
                 — this live e2e MUST run under CI, not skip"
            );
        }
        return None;
    };
    let issuer = std::env::var("MCPS_TEST_OCSP_ISSUER_DER")
        .unwrap_or_else(|_| "ca.der".to_string());
    let good = std::env::var("MCPS_TEST_OCSP_GOOD_DER")
        .unwrap_or_else(|_| "good.der".to_string());
    let revoked = std::env::var("MCPS_TEST_OCSP_REVOKED_DER")
        .unwrap_or_else(|_| "revoked.der".to_string());
    Some((url, issuer, good, revoked))
}

#[test]
fn live_responder_reports_good_and_revoked_without_restart() {
    let Some((url, issuer_path, good_path, revoked_path)) = ocsp_env() else {
        eprintln!(
            "SKIP live_responder_reports_good_and_revoked_without_restart: \
             MCPS_TEST_OCSP_RESPONDER_URL is unset (no OCSP responder provisioned). \
             See this test's module doc for the openssl ocsp provisioning commands."
        );
        return;
    };

    let issuer_der = std::fs::read(&issuer_path)
        .unwrap_or_else(|e| panic!("read issuer DER {issuer_path}: {e}"));
    let good_der = std::fs::read(&good_path)
        .unwrap_or_else(|e| panic!("read good leaf DER {good_path}: {e}"));
    let revoked_der = std::fs::read(&revoked_path)
        .unwrap_or_else(|e| panic!("read revoked leaf DER {revoked_path}: {e}"));

    // Override the AIA URL with the env-provided responder so the test does not
    // depend on the leaf carrying an AIA entry (though the recipe bakes one in).
    let checker = OcspChecker::new(Some(url.clone()), false);

    let good_status = checker
        .check(&good_der, &issuer_der)
        .unwrap_or_else(|e| panic!("OCSP check of known-good cert against {url}: {e}"));
    assert_eq!(
        good_status,
        CertRevocationStatus::Good,
        "the known-good certificate must be reported Good by the live responder"
    );

    // SAME checker, SAME responder, no restart in between: the revoked cert must
    // now come back Revoked from the responder's index.
    let revoked_status = checker
        .check(&revoked_der, &issuer_der)
        .unwrap_or_else(|e| panic!("OCSP check of known-revoked cert against {url}: {e}"));
    assert_eq!(
        revoked_status,
        CertRevocationStatus::Revoked,
        "the known-revoked certificate must be reported Revoked by the live responder \
         (mid-session, without a proxy restart)"
    );
}
