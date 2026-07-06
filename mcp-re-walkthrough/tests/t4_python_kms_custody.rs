//! Tier T4, Python client leg — "Enterprise key custody, cross-language" (#218).
//!
//! The integrated Cloud-KMS four-hop, but with the CLIENT leg driven by the Python
//! MCP-RE SDK instead of the Rust reference proxy: the Python driver signs every
//! request with a NON-EXPORTING GCP Cloud KMS key (via the SDK's
//! `Signer.non_exporting` seam → `asymmetricSign`), and the Rust `mcp-re-proxy` PEP
//! signs responses with a DISTINCT Cloud KMS key. Both signing keys are cloud-held;
//! the harness fetches both public keys to wire trust; mTLS stays file-backed.
//!
//! This proves the Python SDK's KMS custody path end to end over the real socket —
//! the cross-language counterpart to `t4_enterprise_kms_custody` (Rust client).
//!
//! Composition, not new harness code: `SigningMode::GcpKms` already fetches the
//! client KMS public key into the server's `--trust` and passes
//! `--key-source gcp-kms --gcp-kms-key-version` to the client leg; `client_driver`
//! points that leg at the Python SDK. The Python driver signs with the SAME client
//! key version, so its signature verifies against the harness-wired trust.
//!
//! Live + `#[ignore]`d; needs the Python driver AND Cloud KMS credentials. Skips
//! (does not fail) when `MCP_RE_DRIVER_PYTHON` is unset; fails loud when it is set but
//! the KMS config is absent. Run from the cloud script (command 6):
//! ```sh
//! MCP_RE_DRIVER_PYTHON="…/.venv/bin/python -m mcp_re_sdk.driver" \
//!   MCP_RE_GCP_ACCESS_TOKEN=… MCP_RE_GCP_KEY_VERSION=<server> \
//!   MCP_RE_GCP_KEY_VERSION_CLIENT=<client> \
//!   cargo test -p mcp-re-walkthrough --features gcp_kms \
//!     --test t4_python_kms_custody -- --ignored --nocapture
//! ```
#![cfg(feature = "gcp_kms")]

use mcp_re_walkthrough::structured;
use mcp_re_walkthrough::tool_call;
use mcp_re_walkthrough::ClientDriver;
use mcp_re_walkthrough::FourHop;
use mcp_re_walkthrough::FourHopOptions;
use mcp_re_walkthrough::SigningMode;
use mcp_re_walkthrough::SEED_TEXT;

fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!(
            "{name} must be set — run scripts/test-gcp-cloud.sh.example with GCP credentials; \
             this live lane must FAIL LOUDLY, never silently pass"
        ),
    }
}

/// Build the Python driver from `MCP_RE_DRIVER_PYTHON` (whitespace-split command), or
/// `None` when it is unset (the lane is skipped, not failed).
fn python_driver() -> Option<ClientDriver> {
    let raw = std::env::var_os("MCP_RE_DRIVER_PYTHON")?;
    let command: Vec<String> = raw.to_string_lossy().split_whitespace().map(String::from).collect();
    if command.is_empty() {
        return None;
    }
    Some(ClientDriver {
        label: "python".to_string(),
        command,
    })
}

#[test]
#[ignore = "live GCP Cloud KMS + Python SDK driver; run from the cloud script"]
fn python_client_signs_via_cloud_kms_across_the_four_hop() {
    let Some(driver) = python_driver() else {
        eprintln!("[t4-python-kms] SKIP: MCP_RE_DRIVER_PYTHON not set");
        return;
    };
    let client_key_version = require_env("MCP_RE_GCP_KEY_VERSION_CLIENT");
    let server_key_version = require_env("MCP_RE_GCP_KEY_VERSION");
    if std::env::var("MCP_RE_GCP_USE_METADATA").ok().as_deref() != Some("1") {
        require_env("MCP_RE_GCP_ACCESS_TOKEN");
    }

    let mut hop = FourHop::launch_with(FourHopOptions {
        signing: SigningMode::GcpKms {
            client_key_version,
            server_key_version,
        },
        client_driver: Some(driver),
        ..FourHopOptions::default()
    });

    // The Python SDK signed this request with a non-exporting Cloud KMS key; the PEP
    // verified it against the KMS public key the harness wired into --trust, served
    // it, signed the response with the server's Cloud KMS key, and the Python driver
    // verified that binding before handing back plain MCP.
    let response = hop.call(&tool_call(
        "py-kms-1",
        "read_file",
        serde_json::json!({ "path": "hello.txt" }),
    ));
    let content = structured(&response)["content"]
        .as_str()
        .expect("read_file returns content");
    assert_eq!(content, SEED_TEXT, "the seeded text round-trips both cloud signatures");
    assert!(
        response["result"]["_meta"].is_null(),
        "no MCP-RE envelope may leak to the ordinary client: {response}"
    );
    assert!(hop.inner_spawn_count() >= 1, "the inner server must be reached");

    // A second call proves the KMS signer callback is reusable across requests.
    let second = hop.call(&tool_call(
        "py-kms-2",
        "read_file",
        serde_json::json!({ "path": "hello.txt" }),
    ));
    assert_eq!(
        structured(&second)["content"].as_str(),
        Some(SEED_TEXT),
        "the Python KMS signer serves a second request too: {second}"
    );
}
