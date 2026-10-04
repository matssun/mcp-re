//! MCPS-027 — `FileKeySource` loads signing key + TLS cert/key + client-CA.
//!
//! MCPS-076 secret hygiene: key errors never carry secret bytes, and the seed temporaries
//! are scrubbed on drop.

use std::fs;
use std::path::PathBuf;

use mcp_re_core::b64url_encode;
use mcp_re_core::SigningKey;
use mcp_re_proxy::capability_materialization::key_file_custody::CheckedKeyFile;
use mcp_re_proxy::config_state::KeyFileAccessPolicy;
use mcp_re_proxy::key_source::FileKeySource;
use mcp_re_proxy::key_source::KeyError;
use mcp_re_proxy::key_source::KeySource;
use mcp_re_proxy::key_source::ResponseSigner;

use rcgen::CertificateParams;
use rcgen::Issuer;
use rcgen::KeyPair;

const SEED: [u8; 32] = [7u8; 32];

/// (signing-seed b64url, server cert PEM, server key PEM, client-CA PEM).
fn material() -> (String, String, String, String) {
    let ca_key = KeyPair::generate().unwrap();
    let ca_params = CertificateParams::new(Vec::new()).unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key))
        .unwrap();
    (
        b64url_encode(&SEED),
        leaf.pem(),
        leaf_key.serialize_pem(),
        ca.pem(),
    )
}

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("mcp_re_ks_{}_{name}", std::process::id()))
}

/// Write `content` owner-only and admit it — the only way to hand a key file to a
/// `FileKeySource`.
fn admitted(path: &PathBuf, content: &str) -> CheckedKeyFile {
    fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    CheckedKeyFile::open(&path.to_string_lossy(), KeyFileAccessPolicy::OwnerOnly).unwrap()
}

fn expected_pubkey() -> String {
    SigningKey::from_seed_bytes(&SEED).public_key().to_b64url()
}

#[test]
fn file_source_loads_all_material() {
    let (seed, cert, key, ca) = material();
    let seed_p = tmp("file_seed");
    let cert_p = tmp("file_cert");
    let key_p = tmp("file_key");
    let ca_p = tmp("file_ca");
    fs::write(&cert_p, &cert).unwrap();
    fs::write(&ca_p, &ca).unwrap();

    let source = FileKeySource::from_checked(
        admitted(&seed_p, &seed),
        &cert_p.to_string_lossy(),
        Some(admitted(&key_p, &key)),
        &ca_p.to_string_lossy(),
    )
    .unwrap();

    assert_eq!(
        source.response_public_key().unwrap().to_b64url(),
        expected_pubkey()
    );
    assert!(!source.tls_server_cert_chain().unwrap().is_empty());
    let _ = source.tls_server_key().unwrap();
    assert!(!source.client_ca_roots().unwrap().is_empty());

    for p in [seed_p, cert_p, key_p, ca_p] {
        let _ = fs::remove_file(p);
    }
}

/// A missing key file never reaches the source: the check that produces its material
/// refuses it, naming the file.
#[test]
fn file_source_missing_file_is_refused_at_the_check() {
    let err = CheckedKeyFile::open("/nonexistent/mcp-re/seed", KeyFileAccessPolicy::OwnerOnly)
        .unwrap_err();
    assert!(err.contains("/nonexistent/mcp-re/seed"), "{err}");
}

#[test]
fn file_source_bad_seed_is_malformed() {
    let seed_p = tmp("bad_seed");
    let err = FileKeySource::from_checked(admitted(&seed_p, "not-base64-!!!"), "x", None, "x")
        .unwrap_err();
    assert!(matches!(err, KeyError::Malformed(_)));
    let _ = fs::remove_file(seed_p);
}

#[test]
fn key_errors_never_leak_secret_material() {
    // A malformed but secret-looking seed must not appear in the error (Display
    // or Debug) — errors are logged, secrets must not be.
    let secret = "SUPER_SECRET_SEED_VALUE_THAT_MUST_NOT_BE_LOGGED";
    let seed_p = tmp("leak_seed");
    let err = FileKeySource::from_checked(admitted(&seed_p, secret), "x", None, "x").unwrap_err();
    let rendered = format!("{err} | {err:?}");
    assert!(
        !rendered.contains(secret),
        "KeyError must not contain the secret seed value; got: {rendered}"
    );
    let _ = fs::remove_file(seed_p);
}

/// MACHINE-VERIFIED zeroize-on-drop, the SOUND (non-UB) variant.
///
/// What is verified vs. trusted:
///   * No freed memory is read: the "read just-freed heap" idiom is
///     allocator-dependent and UB-fragile, so the assertion below is the
///     deterministic, sound one.
///   * What is MACHINE-VERIFIED here, both through LIVE references (no freed
///     memory is read): (a) calling `zeroize()` on a live spy zeros its bytes in
///     place; and (b) dropping a `Zeroizing<T>` invokes `Zeroize::zeroize` on its
///     payload (the spy's `zeroize()` records into an `AtomicBool` that is observed
///     set after the drop). Together these prove WE wired `Zeroizing` so that drop
///     scrubs the value.
///   * What is TRUSTED-TO-CRATE: that `zeroize` actually overwrites real seed
///     bytes with a volatile, un-elidable write (the `zeroize` crate's core
///     guarantee). We assert we invoked it; we do not re-verify the crate's
///     internal volatile-write correctness.
///
/// The companion `seed_temporaries_are_zeroizing_typed` test confirms, at compile
/// time, that a `Zeroizing<[u8;32]>` deref-coerces into `SigningKey::from_seed_bytes`
/// — the exact wrapper-to-constructor pattern `key_source` uses. That `key_source`
/// actually wraps its seed temporaries in `Zeroizing` is a structural property of
/// the source (verified by reading it / review), not something a runtime test can
/// observe, since zeroize is invisible at the value level.
#[test]
fn zeroize_on_drop_invokes_zeroize() {
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use zeroize::Zeroize;
    use zeroize::Zeroizing;

    static ZEROIZED: AtomicBool = AtomicBool::new(false);

    /// A spy payload: `zeroize()` records that it ran and clears its own bytes.
    struct Spy {
        bytes: [u8; 32],
    }
    impl Zeroize for Spy {
        fn zeroize(&mut self) {
            self.bytes.zeroize();
            ZEROIZED.store(true, Ordering::SeqCst);
        }
    }

    // (a) Calling zeroize() on a LIVE spy zeros its bytes in place — observed
    // through a live reference (the value is NOT dropped/freed here).
    ZEROIZED.store(false, Ordering::SeqCst);
    let mut live = Spy { bytes: [0xA5; 32] };
    assert_eq!(live.bytes, [0xA5; 32], "sentinel set before zeroize");
    live.zeroize();
    assert_eq!(
        live.bytes, [0u8; 32],
        "zeroize() must zero the bytes in place"
    );
    assert!(ZEROIZED.load(Ordering::SeqCst), "zeroize() must have run");

    // (b) Dropping a Zeroizing<T> invokes Zeroize::zeroize on its payload.
    ZEROIZED.store(false, Ordering::SeqCst);
    {
        let spy: Zeroizing<Spy> = Zeroizing::new(Spy { bytes: [0xA5; 32] });
        // Sanity through a LIVE reference (no freed memory): the sentinel is set.
        assert_eq!(spy.bytes, [0xA5; 32]);
        // (spy drops here)
    }
    assert!(
        ZEROIZED.load(Ordering::SeqCst),
        "dropping Zeroizing<T> did not invoke Zeroize::zeroize on its payload"
    );
}

/// COMPILE-LEVEL demonstration of the wrapper-to-constructor contract `key_source`
/// relies on: a `zeroize::Zeroizing<[u8;32]>` deref-coerces into
/// `SigningKey::from_seed_bytes(&[u8;32])` and yields the same key as the raw seed.
///
/// This does NOT (and cannot at runtime) verify that `key_source` wraps its seed
/// temporaries in `Zeroizing` — zeroize is invisible at the value level, and
/// `signing_key_from_seed_b64url` is private. That wrapping is a structural
/// property of the source. What this pins is that the `Zeroizing` wrapper is a
/// drop-in for the raw `&[u8;32]` the dalek constructor borrows, so the production
/// code can wrap without changing behavior. Scrub-on-drop itself is proven by
/// `zeroize_on_drop_invokes_zeroize`.
#[test]
fn seed_temporaries_are_zeroizing_typed() {
    let seed: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new([7u8; 32]);
    // Deref-coerces to &[u8;32] exactly as `SigningKey::from_seed_bytes` requires,
    // and produces the same key as the unwrapped seed would.
    let key = SigningKey::from_seed_bytes(&seed);
    assert_eq!(key.public_key().to_b64url(), expected_pubkey());
}
