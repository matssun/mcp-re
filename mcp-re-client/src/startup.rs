// SPDX-License-Identifier: Apache-2.0
//! Everything between the command line and the serving loop.
//!
//! Two questions are asked of the invocation and nothing else — which configuration, and
//! whether to serve. The parser is deliberately this small: every argument this binary
//! accepts is one more thing that can change what gets signed under the operator's identity.
//!
//! The other half is what *running* means. The anchor refresher is started
//! UNCONDITIONALLY and held for the process lifetime, because it is not only how a
//! published revocation reaches a running client — it is the ONLY place anchors are
//! WITHDRAWN once the manifest in force has passed its own `expires_at`, and nothing on the
//! request path consults that expiry. A client without it verifies for as long as it runs
//! under a trust picture whose governing document has lapsed, which is exactly the state the
//! manifest loader's expiry check exists to refuse. `validate()` bounds
//! `trust.reload_secs`, so the cadence is also a ceiling on that window.

use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use mcp_re_client::anchors::AnchorRefresher;
use mcp_re_client::config::ClientConfig;

use crate::USAGE;

/// Set on SIGTERM/SIGINT so the accept loop stops taking new local connections.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_shutdown_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Install the graceful-shutdown handler. Best effort: a failure leaves the default
/// terminate disposition, which is still safe — just not graceful.
fn install_shutdown_handlers() {
    // SAFETY: `sigaction` with a zeroed struct and a static `extern "C"` handler that
    // performs only an atomic store (on the async-signal-safe list).
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handle_shutdown_signal as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0;
        libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
    }
}

/// What the command line asked for.
///
/// Two questions and nothing else: which configuration, and whether to serve. The parser is
/// deliberately this small — every argument this binary accepts is one more thing that can
/// change what gets signed under the operator's identity.
pub(crate) struct Invocation {
    pub(crate) config_path: String,
    pub(crate) check_only: bool,
}

/// Read the command line, or say what to print and with which status.
///
/// `Err(code)` covers both terminals that are not serving: `--help` printed the usage and
/// succeeded, a bad argument printed a diagnosis and failed. Neither is a value the rest of
/// startup could act on, which is why they leave here rather than being carried.
pub(crate) fn parse_invocation(args: &[String]) -> Result<Invocation, ExitCode> {
    let mut config_path: Option<String> = None;
    let mut check_only = false;
    let mut index = 0usize;
    // Class C: every read of `args` is a `get`, so the walk stops where the argument list
    // stops; `index += 1` is slice-index arithmetic.
    #[allow(clippy::arithmetic_side_effects)]
    while let Some(argument) = args.get(index) {
        match argument.as_str() {
            "--config" => {
                index += 1;
                match args.get(index) {
                    Some(path) => config_path = Some(path.clone()),
                    None => {
                        eprintln!("--config needs a path");
                        return Err(ExitCode::FAILURE);
                    }
                }
            }
            "--check" => check_only = true,
            "--help" | "-h" => {
                println!("{USAGE}");
                return Err(ExitCode::SUCCESS);
            }
            other => {
                eprintln!("unknown argument {other:?}\n\n{USAGE}");
                return Err(ExitCode::FAILURE);
            }
        }
        index += 1;
    }
    let Some(config_path) = config_path else {
        eprintln!("--config is required\n\n{USAGE}");
        return Err(ExitCode::FAILURE);
    };
    Ok(Invocation {
        config_path,
        check_only,
    })
}

/// Wall-clock Unix seconds, or `None` when the host clock does not read as a Unix time.
///
/// An unreadable clock is not a time. Every trust-lifetime gate this value reaches — manifest
/// expiry at startup, the refresher's withdrawal — compares `now > expires_at`, and an early
/// instant reads as "not expired", so substituting 0 would switch all of them off at once.
pub(crate) fn now_unix() -> Option<i64> {
    unix_seconds(std::time::SystemTime::now())
}

/// `at` as whole seconds since the Unix epoch; `None` before the epoch or past `i64`.
fn unix_seconds(at: std::time::SystemTime) -> Option<i64> {
    let elapsed = at.duration_since(std::time::UNIX_EPOCH).ok()?;
    i64::try_from(elapsed.as_secs()).ok()
}

/// Serve until a shutdown signal is observed.
///
/// The anchor refresher is started UNCONDITIONALLY and held for the process lifetime. It is
/// not only how a published revocation reaches a running client — it is the only place
/// anchors are WITHDRAWN once the manifest in force has passed its own `expires_at`, and
/// nothing on the request path consults that expiry. A client without it verifies for as
/// long as it runs under a trust picture whose governing document has lapsed, which is
/// exactly the state the manifest loader's expiry check exists to refuse. `validate()`
/// bounds `trust.reload_secs`, so the cadence is also a ceiling on that window.
pub(crate) fn serve_until_shutdown(
    config: &ClientConfig,
    built: mcp_re_client::BuiltClient,
    listener: mcp_re_client::serve::BoundListener,
) -> ExitCode {
    let _refresher = AnchorRefresher::start(
        built.loader,
        Arc::clone(&built.snapshot),
        built.manifest_expires_at,
        Duration::from_secs(config.trust.reload_secs),
        now_unix,
    );
    install_shutdown_handlers();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_loop = Arc::clone(&stop);
    std::thread::spawn(move || {
        while !SHUTDOWN.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
        }
        stop_loop.store(true, Ordering::Relaxed);
    });

    eprintln!(
        "mcp-re-client: serving plain MCP on {}",
        listener.local_addr()
    );
    if let Err(e) = mcp_re_client::serve::serve(listener, built.context, stop) {
        eprintln!("mcp-re-client: the local listener could not be served: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pre_epoch_clock_is_not_a_time() {
        let epoch = std::time::UNIX_EPOCH;
        assert_eq!(unix_seconds(epoch - Duration::from_secs(1)), None);
        assert_eq!(unix_seconds(epoch), Some(0));
        assert_eq!(unix_seconds(epoch + Duration::from_secs(5)), Some(5));
    }
    use mcp_re_client::config::ClientConfig;
    use mcp_re_client::config::DelegationConfig;
    use mcp_re_client::config::FloorConfig;
    use mcp_re_client::config::IdentityConfig;
    use mcp_re_client::config::LocalConfig;
    use mcp_re_client::config::OrgKey;
    use mcp_re_client::config::RemoteConfig;
    use mcp_re_client::config::TrustConfig;
    use mcp_re_client_core::ManifestIssuer;
    use mcp_re_client_core::TrustAnchorManifest;
    use mcp_re_client_proxy::AnchorSnapshot;
    use mcp_re_client_proxy::ClientProxy;
    use mcp_re_client_proxy::RouteRegistry;
    use mcp_re_core::SigningKey;
    use std::path::PathBuf;

    const PROFILE: &str = "mcp-re-http-v1";
    const ROOT_KID: &str = "root-kid";
    const ORG_KID: &str = "org-kid";

    fn org_key() -> SigningKey {
        SigningKey::from_seed_bytes(&[7u8; 32])
    }
    fn root_key() -> SigningKey {
        SigningKey::from_seed_bytes(&[33u8; 32])
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mcp-re-client-startup-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("scratch");
            Scratch(path)
        }
        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A transport that is never reached: this control drives the SERVING LIFETIME, and
    /// makes no local call over the listener.
    struct NoTransport;

    impl mcp_re_client_proxy::RemoteTransport for NoTransport {
        fn round_trip(
            &self,
            _request: &mcp_re_client_core::HttpRequest,
        ) -> Result<mcp_re_client_core::HttpResponse, mcp_re_client_proxy::TransportError> {
            Err(mcp_re_client_proxy::TransportError::new(
                "this control makes no remote call",
            ))
        }
    }

    fn publish_manifest(path: &std::path::Path, issued_at: i64, expires_at: i64) {
        let manifest = TrustAnchorManifest {
            profile: PROFILE.into(),
            manifest_version: 1,
            current_issuers: vec![ManifestIssuer {
                issuer_kid: ROOT_KID.into(),
                public_key: root_key().public_key().to_b64url(),
                role: "server".into(),
                trust_domain: "example.com".into(),
                subject: "did:example:server".into(),
            }],
            retiring_issuers: vec![],
            revoked_issuers: vec![],
            issued_at,
            expires_at,
        };
        let signed = mcp_re_client_core::sign_manifest(&manifest, &org_key(), ORG_KID);
        std::fs::write(path, serde_json::to_vec(&signed).expect("serialize")).expect("publish");
    }

    fn config(scratch: &Scratch, bind: std::net::SocketAddr) -> ClientConfig {
        ClientConfig {
            local: LocalConfig {
                bind,
                allow_non_loopback: false,
                request_lifetime_secs: 300,
                default_route: None,
                max_in_flight: 8,
            },
            identity: IdentityConfig {
                key_id: "client-key-1".into(),
                signing_key_seed_path: scratch.join("seed"),
            },
            remote: RemoteConfig {
                addr: "127.0.0.1:1".parse().expect("an address"),
                expected_server_name: "server.example.com".into(),
                client_cert_path: scratch.join("client.pem"),
                client_key_path: scratch.join("client.key"),
                server_ca_path: scratch.join("ca.pem"),
            },
            trust: TrustConfig {
                manifest_path: scratch.join("manifest.json"),
                profile: PROFILE.into(),
                org_keys: vec![OrgKey {
                    kid: ORG_KID.into(),
                    public_key: org_key().public_key().to_b64url(),
                }],
                floor: FloorConfig::Ephemeral {
                    bootstrap_version: 0,
                },
                // The floor of the accepted range. It is the cadence AND the ceiling on
                // how long a lapsed trust picture stays in force, so the shortest legal
                // one is what a control over withdrawal has to wait out.
                reload_secs: 1,
            },
            delegation: DelegationConfig {
                verifier_audiences: vec!["verifier-1".into()],
                expected_audience_hash: "aud-scope-1".into(),
                accepted_epochs: vec!["epoch-1".into()],
                max_clock_skew: 60,
            },
            routes: vec![],
        }
    }

    /// The DEPLOYABLE always starts the anchor refresher, and holds it for the serving
    /// lifetime.
    ///
    /// THM-0120 establishes what a refresh cycle does. It says nothing about whether the
    /// artifact an operator runs performs one — and the refresher is the only place anchors
    /// are WITHDRAWN once the manifest in force has passed its own `expires_at`, with
    /// nothing on the request path consulting that expiry. A client that omitted the start
    /// would therefore verify, for as long as it ran, under a trust picture whose governing
    /// document had lapsed, and every unit test of the refresher would still pass.
    ///
    /// So this control drives `serve_until_shutdown` itself and observes the one effect
    /// only a running refresher produces: the anchors in force become the EMPTY set. The
    /// question is asked at the load-time instant, before the manifest's own expiry, so
    /// "no longer trusted" cannot be an artefact of the clock having passed `expires_at`
    /// — at that instant the seeded set trusts the root, and only a withdrawal makes it
    /// stop.
    ///
    /// The manifest file is REMOVED after the startup load, so every refresh fails: past
    /// the expiry that is precisely the case where keeping last-good is the wrong answer.
    #[test]
    fn the_serving_path_starts_the_anchor_refresher_and_anchors_are_withdrawn_on_expiry() {
        let scratch = Scratch::new("refresher");
        let load_time = now_unix().expect("a readable host clock");
        // Two seconds of validity: long enough that the startup load accepts the document
        // and the first refresh cycle keeps it, short enough that the control does not
        // stand in for a deployment's cadence.
        publish_manifest(
            &scratch.join("manifest.json"),
            load_time - 100,
            load_time + 2,
        );
        let trust_config = {
            let config = config(&scratch, "127.0.0.1:0".parse().expect("an address"));
            config.trust.clone()
        };
        let mut loader =
            mcp_re_client::anchors::AnchorLoader::new(&trust_config).expect("a loader opens");
        let loaded = loader.load(load_time).expect("the startup manifest loads");
        let manifest_expires_at = loaded.expires_at;
        let snapshot = Arc::new(AnchorSnapshot::new(loaded.issuers));
        assert!(
            snapshot.load().trusts(ROOT_KID, load_time),
            "the seeded anchors trust the published root"
        );
        // Every refresh from here on fails to read a document, which past the expiry is
        // exactly the case where holding the last good set is the wrong answer.
        std::fs::remove_file(scratch.join("manifest.json")).expect("unpublish");

        let listener = mcp_re_client::serve::bind(&mcp_re_client::config::LocalConfig {
            bind: "127.0.0.1:0".parse().expect("an address"),
            allow_non_loopback: false,
            request_lifetime_secs: 300,
            default_route: None,
            max_in_flight: 8,
        })
        .expect("an ephemeral port");
        let config = config(&scratch, listener.local_addr());
        let context = Arc::new(mcp_re_client::serve::ServeContext {
            proxy: ClientProxy::new(
                RouteRegistry::new(),
                SigningKey::from_seed_bytes(&[11u8; 32]),
                "client-key-1",
                Box::new(NoTransport),
            ),
            default_route: None,
            request_lifetime_secs: 300,
            max_in_flight: 8,
            clock: Box::new(|| now_unix().expect("a readable host clock")),
            nonce: Box::new(mcp_re_client::next_nonce),
        });
        let built = mcp_re_client::BuiltClient {
            context,
            snapshot: Arc::clone(&snapshot),
            loader,
            manifest_expires_at,
            manifest_version: loaded.version,
        };

        SHUTDOWN.store(false, Ordering::SeqCst);
        let watched = Arc::clone(&snapshot);
        let withdrawn = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&withdrawn);
        let watcher = std::thread::spawn(move || {
            // A generous ceiling: the refresh cadence is one second and the expiry two, so
            // a healthy box withdraws within about three. The ceiling exists so a loaded
            // one reports a FAILED assertion rather than hanging the suite.
            for _ in 0..300 {
                std::thread::sleep(Duration::from_millis(100));
                if !watched.load().trusts(ROOT_KID, load_time) {
                    observed.store(true, Ordering::SeqCst);
                    break;
                }
            }
            SHUTDOWN.store(true, Ordering::SeqCst);
        });

        let code = serve_until_shutdown(&config, built, listener);
        watcher.join().expect("the watcher finishes");
        assert!(
            withdrawn.load(Ordering::SeqCst),
            "serve_until_shutdown must start the anchor refresher: the anchors were still \
             in force after the manifest in force had expired, which is the state a client \
             without a refresher stays in for as long as it runs"
        );
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "a clean shutdown"
        );
        SHUTDOWN.store(false, Ordering::SeqCst);
    }

    /// THM-0127 says the refresher starts BEFORE the local listener is served and is held for
    /// as long as it serves. The control above shows it runs while serving; it cannot tell
    /// "started first" from "started while serving", and it cannot see WHICH binding holds
    /// it. Both are facts about the statements of `serve_until_shutdown`, so they are read
    /// from its source: the start precedes the accept loop, and the handle is a NAMED binding
    /// (`let _ = ..` would drop it, and stop the refresher, on the spot).
    ///
    /// Evidence, not unconstructibility: it reads this file, the shape the composition
    /// controls elsewhere use, and moving the start into another function would need this
    /// control to follow it.
    #[test]
    fn the_refresher_is_started_before_the_accept_loop_and_held_by_a_named_binding() {
        let source = include_str!("startup.rs");
        let from = source
            .find("pub(crate) fn serve_until_shutdown(")
            .expect("the serving function is in this file");
        let rest = source.get(from..).expect("a slice from a found offset");
        let body = rest
            .get(..rest.find("\n}\n").expect("the function ends at column 0"))
            .expect("a slice up to a found offset");
        let start = body
            .find("let _refresher = AnchorRefresher::start(")
            .expect("the refresher is started and held by a named binding");
        let accept_loop = body
            .find("mcp_re_client::serve::serve(")
            .expect("the function serves the listener");
        assert!(
            start < accept_loop,
            "the refresher must be started before the accept loop begins"
        );
        assert!(
            !body.contains("let _ = AnchorRefresher::start("),
            "an unnamed binding drops the refresher immediately"
        );
    }
}
