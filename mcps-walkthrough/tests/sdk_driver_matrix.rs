//! SDK driver matrix — the pluggable client-leg seam (multi-SDK test architecture).
//!
//! Every MCP-S SDK is an INTERCHANGEABLE client: it signs requests and verifies
//! responses, honoring the same stdio + CLI contract the Rust reference proxy does.
//! This test runs the T0 base case (a signed round-trip through the full four-hop)
//! against EVERY client driver configured in the environment.
//!
//! The Rust reference driver (`mcps-client-proxy-cli`) is always present; each
//! additional SDK driver joins via its env key — skip-not-fail, so a contributor
//! without a given SDK's toolchain runs the drivers they have and NEVER fails on the
//! ones they lack. What was skipped is logged, so a partial matrix never reads as
//! full coverage.
//!
//! Run the whole matrix (Rust reference + a Python SDK driver):
//! ```sh
//! MCPS_DRIVER_PYTHON="python3 -m mcps_sdk.driver" \
//!   cargo test -p mcps-walkthrough --test sdk_driver_matrix -- --nocapture
//! ```
//! With no env keys set it runs the Rust driver alone — the always-on lane.

use mcps_walkthrough::structured;
use mcps_walkthrough::tool_call;
use mcps_walkthrough::ClientDriver;
use mcps_walkthrough::FourHop;
use mcps_walkthrough::FourHopOptions;
use mcps_walkthrough::SEED_TEXT;

#[test]
fn every_configured_sdk_driver_round_trips_a_signed_call() {
    let drivers = ClientDriver::available();

    // Surface which SDK drivers were NOT configured, so a partial run is never
    // mistaken for full multi-SDK coverage.
    for (label, key) in [
        ("python", "MCPS_DRIVER_PYTHON"),
        ("typescript", "MCPS_DRIVER_TS"),
    ] {
        if std::env::var_os(key).is_none() {
            eprintln!("[driver-matrix] SKIP {label}: {key} not set");
        }
    }

    for driver in &drivers {
        eprintln!("[driver-matrix] RUN {} ({:?})", driver.label, driver.command);
        let mut hop = FourHop::launch_with(FourHopOptions {
            client_driver: Some(driver.clone()),
            ..FourHopOptions::default()
        });

        // The T0 guarantee, driver-agnostic: a plain call is signed, verified,
        // served, response-signed, and the binding verified — all by whichever SDK
        // sits on the client leg — and the plain client sees no MCP-S envelope.
        let response = hop.call(&tool_call(
            &format!("matrix-{}", driver.label),
            "read_file",
            serde_json::json!({ "path": "hello.txt" }),
        ));
        let content = structured(&response)["content"].as_str().unwrap_or_else(|| {
            panic!(
                "driver '{}' read_file returned no content: {response}",
                driver.label
            )
        });
        assert_eq!(
            content, SEED_TEXT,
            "driver '{}' must round-trip the signed call",
            driver.label
        );
        assert!(
            response["result"]["_meta"].is_null(),
            "driver '{}' leaked an MCP-S envelope to the plain client: {response}",
            driver.label
        );
        assert!(
            hop.inner_spawn_count() >= 1,
            "driver '{}' must reach the inner server",
            driver.label
        );
    }

    // The Rust reference driver is the always-on floor of the matrix.
    assert!(
        drivers.iter().any(|d| d.label == "rust"),
        "the Rust reference driver must always be available and run"
    );
}
