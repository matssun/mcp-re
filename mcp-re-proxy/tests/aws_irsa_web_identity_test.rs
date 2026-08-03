#![cfg(feature = "aws_kms_keysource")]
//! IRSA credential exchange — the OFFLINE twin (ADR-MCPS-028 §B).
//!
//! The AWS counterpart of GKE workload identity: under IRSA the pod holds no IAM key
//! material, only a projected OIDC token that STS exchanges for temporary
//! credentials. These tests drive the real [`mcp_re_proxy::aws_sts`] exchange against
//! a local fake STS over loopback HTTP — no AWS account, no network, runs on every
//! push. The live half (a real `AssumeRoleWithWebIdentity` against real STS on a real
//! EKS pod) is `aws_kms_live_test.rs` under `--aws-kms-use-web-identity`; per
//! `docs/security/cloud-kms-claims-map.md` an offline twin guards the WIRING and
//! never earns the cloud-validation claim on its own.
//!
//! What is proven here, and why each one is a way the wiring can silently be wrong:
//!
//! * the projected token is re-read from disk on EVERY exchange — `kubelet` rewrites
//!   it in place, so a token captured once stops working mid-run;
//! * credentials are cached until the refresh margin, so the KMS path does not make
//!   an STS round trip per call;
//! * a token file that appears/changes between exchanges is picked up;
//! * a missing role ARN, a missing token file, an empty token and an STS rejection
//!   each fail CLOSED — no fallback to whatever `AWS_ACCESS_KEY_ID` happens to hold.

use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;

use mcp_re_proxy::aws_sts::AwsCredentialSource;
use mcp_re_proxy::aws_sts::WebIdentityConfig;
use mcp_re_proxy::aws_sts::WebIdentityCredentialSource;

/// What the fake STS observed, so a test can assert on the request the exchange made
/// rather than only on the credentials it got back.
#[derive(Default)]
struct Seen {
    bodies: Vec<String>,
}

struct FakeSts {
    endpoint: String,
    seen: Arc<Mutex<Seen>>,
    exchanges: Arc<AtomicUsize>,
}

/// A loopback HTTP endpoint that answers `AssumeRoleWithWebIdentity`.
///
/// `responder` receives the 0-based exchange index and returns `(status, body)`, so a
/// test can make the second exchange differ from the first (expiry, rejection).
fn fake_sts(responder: impl Fn(usize) -> (u16, String) + Send + 'static) -> FakeSts {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake STS");
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let exchanges = Arc::new(AtomicUsize::new(0));
    let seen_thread = Arc::clone(&seen);
    let exchanges_thread = Arc::clone(&exchanges);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
                if line == "\r\n" || line == "\n" {
                    break;
                }
            }
            let mut body = vec![0u8; content_length];
            let _ = reader.read_exact(&mut body);
            let n = exchanges_thread.fetch_add(1, Ordering::SeqCst);
            seen_thread
                .lock()
                .unwrap()
                .bodies
                .push(String::from_utf8_lossy(&body).into_owned());
            let (status, payload) = responder(n);
            let response = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{payload}",
                payload.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    FakeSts {
        endpoint: format!("http://127.0.0.1:{port}/"),
        seen,
        exchanges,
    }
}

/// A well-formed `AssumeRoleWithWebIdentityResponse` expiring `secs_from_now` ahead.
fn sts_ok(access_key_id: &str, secs_from_now: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expiration = mcp_re_core::unix_to_rfc3339_utc(now + secs_from_now);
    format!(
        r#"<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>{access_key_id}</AccessKeyId>
      <SecretAccessKey>secret-for-{access_key_id}</SecretAccessKey>
      <SessionToken>session-for-{access_key_id}</SessionToken>
      <Expiration>{expiration}</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"#
    )
}

/// A scratch directory holding a projected-token file, removed on drop.
struct TokenFile {
    dir: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl TokenFile {
    fn new(contents: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "mcp-re-irsa-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, contents).unwrap();
        TokenFile { dir, path }
    }

    fn rewrite(&self, contents: &str) {
        std::fs::write(&self.path, contents).unwrap();
    }

    fn remove(&self) {
        let _ = std::fs::remove_file(&self.path);
    }

    fn as_str(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

impl Drop for TokenFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Build a source directly, without touching process-wide environment variables:
/// these tests run concurrently in one process, so `set_var` would make them
/// interfere. The environment READING itself is covered by the `from_env` tests
/// below, which are serialized behind one lock.
fn source_for(sts: &FakeSts, token: &TokenFile) -> WebIdentityCredentialSource {
    WebIdentityCredentialSource::new(WebIdentityConfig {
        role_arn: "arn:aws:iam::455880745808:role/mcp-re-kms-signer".to_string(),
        token_file: token.as_str(),
        session_name: "mcp-re-proxy".to_string(),
        endpoint: sts.endpoint.clone(),
    })
}

#[test]
fn the_projected_token_is_exchanged_for_temporary_credentials() {
    let sts = fake_sts(|_| (200, sts_ok("ASIAFIRST", 3600)));
    let token = TokenFile::new("header.payload.signature");
    let source = source_for(&sts, &token);

    let creds = source.credentials().expect("exchange");

    assert_eq!(creds.access_key_id, "ASIAFIRST");
    assert_eq!(&*creds.secret_access_key, "secret-for-ASIAFIRST");
    // ALWAYS a session token: web-identity credentials are temporary, and without it
    // SigV4 omits `X-Amz-Security-Token` and every KMS call fails authentication.
    assert_eq!(
        creds.session_token.as_deref().map(|s| &**s),
        Some("session-for-ASIAFIRST")
    );

    let bodies = sts.seen.lock().unwrap();
    let body = &bodies.bodies[0];
    assert!(body.contains("Action=AssumeRoleWithWebIdentity"), "{body}");
    assert!(body.contains("Version=2011-06-15"), "{body}");
    assert!(
        body.contains("WebIdentityToken=header.payload.signature"),
        "{body}"
    );
    // The ARN's `:` and `/` must be percent-encoded, or STS reads a truncated role.
    assert!(
        body.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A455880745808%3Arole%2Fmcp-re-kms-signer"),
        "{body}"
    );
}

#[test]
fn a_live_credential_is_cached_rather_than_re_exchanged_per_call() {
    let sts = fake_sts(|_| (200, sts_ok("ASIACACHED", 3600)));
    let token = TokenFile::new("t");
    let source = source_for(&sts, &token);

    for _ in 0..5 {
        assert_eq!(source.credentials().unwrap().access_key_id, "ASIACACHED");
    }

    // The KMS adapter refreshes before EVERY signature. Without the cache that is an
    // STS round trip per KMS call, which is both a latency cost and a throttling
    // risk on a fleet.
    assert_eq!(sts.exchanges.load(Ordering::SeqCst), 1);
}

#[test]
fn a_credential_inside_the_refresh_margin_is_re_exchanged() {
    // First exchange expires in 10s — inside the 60s refresh margin, so it must not
    // be served from cache a second time.
    let sts = fake_sts(|n| {
        if n == 0 {
            (200, sts_ok("ASIAEXPIRING", 10))
        } else {
            (200, sts_ok("ASIAFRESH", 3600))
        }
    });
    let token = TokenFile::new("t");
    let source = source_for(&sts, &token);

    assert_eq!(source.credentials().unwrap().access_key_id, "ASIAEXPIRING");
    assert_eq!(source.credentials().unwrap().access_key_id, "ASIAFRESH");
    assert_eq!(sts.exchanges.load(Ordering::SeqCst), 2);
}

#[test]
fn the_token_file_is_re_read_on_every_exchange_not_cached_at_construction() {
    // kubelet rewrites the projected token in place as it approaches expiry. A
    // source that read the file once would keep presenting a token STS has stopped
    // accepting, and the failure would look like an IAM problem.
    let sts = fake_sts(|n| {
        if n == 0 {
            (200, sts_ok("ASIAONE", 10))
        } else {
            (200, sts_ok("ASIATWO", 3600))
        }
    });
    let token = TokenFile::new("first-token");
    let source = source_for(&sts, &token);

    source.credentials().unwrap();
    token.rewrite("rotated-token");
    source.credentials().unwrap();

    let bodies = sts.seen.lock().unwrap();
    assert!(bodies.bodies[0].contains("WebIdentityToken=first-token"));
    assert!(
        bodies.bodies[1].contains("WebIdentityToken=rotated-token"),
        "the second exchange presented a stale token: {}",
        bodies.bodies[1]
    );
}

#[test]
fn an_sts_rejection_fails_closed_and_names_the_role() {
    let sts = fake_sts(|_| {
        (
            403,
            "<ErrorResponse><Error><Code>AccessDenied</Code><Message>Not authorized to \
             perform sts:AssumeRoleWithWebIdentity</Message></Error></ErrorResponse>"
                .to_string(),
        )
    });
    let token = TokenFile::new("t");
    let source = source_for(&sts, &token);

    let err = source.credentials().unwrap_err();
    let rendered = format!("{err:?}");
    assert!(rendered.contains("403"), "{rendered}");
    assert!(rendered.contains("mcp-re-kms-signer"), "{rendered}");
    assert!(rendered.contains("AccessDenied"), "{rendered}");
}

#[test]
fn a_missing_token_file_fails_closed_rather_than_falling_back_to_the_environment() {
    let sts = fake_sts(|_| (200, sts_ok("ASIASHOULDNOTBEUSED", 3600)));
    let token = TokenFile::new("t");
    let source = source_for(&sts, &token);
    token.remove();

    let err = source.credentials().unwrap_err();
    assert!(
        format!("{err:?}").contains("web identity token"),
        "got: {err:?}"
    );
    // The whole point: nothing was exchanged and nothing was substituted.
    assert_eq!(sts.exchanges.load(Ordering::SeqCst), 0);
}

#[test]
fn an_empty_token_file_is_refused_rather_than_posted() {
    // A projected-token mount that exists but has not been populated yet reads as an
    // empty file. Posting it would produce an opaque STS error; refusing here names
    // the actual condition.
    let sts = fake_sts(|_| (200, sts_ok("ASIASHOULDNOTBEUSED", 3600)));
    let token = TokenFile::new("   \n");
    let source = source_for(&sts, &token);

    let err = source.credentials().unwrap_err();
    assert!(format!("{err:?}").contains("empty"), "got: {err:?}");
    assert_eq!(sts.exchanges.load(Ordering::SeqCst), 0);
}

#[test]
fn a_malformed_sts_body_fails_closed() {
    let sts = fake_sts(|_| (200, "<html>not xml we asked for</html>".to_string()));
    let token = TokenFile::new("t");
    let source = source_for(&sts, &token);

    let err = source.credentials().unwrap_err();
    assert!(format!("{err:?}").contains("Credentials"), "got: {err:?}");
}

/// The `from_env` tests mutate process-wide state, so they hold this lock and run
/// one at a time. Everything above builds its config directly and runs concurrently.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Clear every IRSA variable so a test starts from a known environment.
fn clear_irsa_env() {
    for k in [
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_SESSION_NAME",
    ] {
        std::env::remove_var(k);
    }
}

#[test]
fn a_pod_that_is_not_under_irsa_is_told_which_variable_is_missing() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_irsa_env();

    let err = WebIdentityConfig::from_env("eu-north-1", None).unwrap_err();
    assert!(format!("{err:?}").contains("AWS_ROLE_ARN"), "got: {err:?}");

    std::env::set_var("AWS_ROLE_ARN", "arn:aws:iam::1:role/r");
    let err = WebIdentityConfig::from_env("eu-north-1", None).unwrap_err();
    assert!(
        format!("{err:?}").contains("AWS_WEB_IDENTITY_TOKEN_FILE"),
        "got: {err:?}"
    );
    clear_irsa_env();
}

#[test]
fn the_default_sts_endpoint_is_regional() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_irsa_env();
    std::env::set_var("AWS_ROLE_ARN", "arn:aws:iam::1:role/r");
    std::env::set_var("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/secrets/token");

    let config = WebIdentityConfig::from_env("eu-north-1", None).unwrap();
    // The GLOBAL sts.amazonaws.com is one region's availability wearing a global
    // name, and its credentials are not valid in opt-in regions.
    assert_eq!(config.endpoint, "https://sts.eu-north-1.amazonaws.com");
    assert_eq!(config.session_name, "mcp-re-proxy");
    clear_irsa_env();
}

#[test]
fn an_empty_role_arn_is_refused_rather_than_posted_as_a_blank_role() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_irsa_env();
    std::env::set_var("AWS_ROLE_ARN", "");
    std::env::set_var("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/secrets/token");

    let err = WebIdentityConfig::from_env("eu-north-1", None).unwrap_err();
    assert!(format!("{err:?}").contains("empty"), "got: {err:?}");
    clear_irsa_env();
}

#[test]
fn an_out_of_grammar_session_name_is_refused_at_construction() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_irsa_env();
    std::env::set_var("AWS_ROLE_ARN", "arn:aws:iam::1:role/r");
    std::env::set_var("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/secrets/token");
    std::env::set_var("AWS_ROLE_SESSION_NAME", "has space");

    // STS would reject this on every call; catching it once at startup turns a
    // recurring opaque failure into one clear error.
    let err = WebIdentityConfig::from_env("eu-north-1", None).unwrap_err();
    assert!(
        format!("{err:?}").contains("AWS_ROLE_SESSION_NAME"),
        "got: {err:?}"
    );
    clear_irsa_env();
}
