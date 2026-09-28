use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;

use crate::demo_fixtures::DemoFixtures;

impl DemoFixtures {
    /// Materialize the proxy CLI's file inputs into a fresh temp directory and
    /// return their paths (cleaned up when the returned [`DemoFixtureFiles`] is
    /// dropped). The same `DemoFixtures` can also be consumed directly as PEM by
    /// the in-process transport client without ever touching disk.
    pub fn write_files(&self) -> std::io::Result<DemoFixtureFiles> {
        let dir = std::env::temp_dir().join(format!(
            "mcp_re_demo_fixtures_{}_{}",
            std::process::id(),
            next_counter(),
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;

        let server_cert_path = dir.join("server_cert.pem");
        let server_key_path = dir.join("server_key.pem");
        let server_ca_path = dir.join("server_ca.pem");
        let client_ca_path = dir.join("client_ca.pem");
        let client_cert_path = dir.join("client_cert.pem");
        let client_key_path = dir.join("client_key.pem");
        let mismatched_client_cert_path = dir.join("mismatched_client_cert.pem");
        let mismatched_client_key_path = dir.join("mismatched_client_key.pem");
        let trust_path = dir.join("trust.json");
        let signing_seed_path = dir.join("signing_seed");
        let signer_seed_path = dir.join("signer_seed");

        std::fs::write(&server_cert_path, self.server_cert_pem())?;
        std::fs::write(&server_key_path, self.server_key_pem())?;
        std::fs::write(&server_ca_path, self.server_ca_pem())?;
        std::fs::write(&client_ca_path, self.client_ca_pem())?;
        std::fs::write(&client_cert_path, self.client_cert_pem())?;
        std::fs::write(&client_key_path, self.client_key_pem())?;
        std::fs::write(
            &mismatched_client_cert_path,
            self.mismatched_client_cert_pem(),
        )?;
        std::fs::write(&mismatched_client_key_path, self.mismatched_client_key_pem())?;
        std::fs::write(&trust_path, self.trust_json())?;
        std::fs::write(&signing_seed_path, self.signing_seed_b64url())?;
        std::fs::write(&signer_seed_path, self.signer_seed_b64url())?;

        Ok(DemoFixtureFiles {
            dir,
            server_cert_path,
            server_key_path,
            server_ca_path,
            client_ca_path,
            client_cert_path,
            client_key_path,
            mismatched_client_cert_path,
            mismatched_client_key_path,
            trust_path,
            signing_seed_path,
            signer_seed_path,
        })
    }
}

/// A monotonic counter so two `write_files` calls in the same process land in
/// distinct temp directories.
fn next_counter() -> u64 {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The on-disk materialization of [`DemoFixtures`]: PEM/seed/trust files under a
/// private temp directory, whose paths line up with the `mcp_re_proxy_cli` flags
/// and the `mcp-re-demo` client bin flags. The directory and all files are removed
/// when this is dropped.
#[derive(Debug)]
pub struct DemoFixtureFiles {
    dir: PathBuf,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    server_ca_path: PathBuf,
    client_ca_path: PathBuf,
    client_cert_path: PathBuf,
    client_key_path: PathBuf,
    mismatched_client_cert_path: PathBuf,
    mismatched_client_key_path: PathBuf,
    trust_path: PathBuf,
    signing_seed_path: PathBuf,
    signer_seed_path: PathBuf,
}

impl DemoFixtureFiles {
    /// The temp directory holding every file (removed on drop).
    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }
    /// Server leaf cert path (`mcp_re_proxy_cli --tls-cert`).
    pub fn server_cert_path(&self) -> &std::path::Path {
        &self.server_cert_path
    }
    /// Server leaf key path (`mcp_re_proxy_cli --tls-key`).
    pub fn server_key_path(&self) -> &std::path::Path {
        &self.server_key_path
    }
    /// Server CA path (the client bin's `--server-ca-file`).
    pub fn server_ca_path(&self) -> &std::path::Path {
        &self.server_ca_path
    }
    /// Client CA path (`mcp_re_proxy_cli --client-ca`).
    pub fn client_ca_path(&self) -> &std::path::Path {
        &self.client_ca_path
    }
    /// Positive client leaf cert path (the client bin's `--client-cert-file`).
    pub fn client_cert_path(&self) -> &std::path::Path {
        &self.client_cert_path
    }
    /// Positive client leaf key path (the client bin's `--client-key-file`).
    pub fn client_key_path(&self) -> &std::path::Path {
        &self.client_key_path
    }
    /// Mismatched client leaf cert path (T3 `--client-cert-file`).
    pub fn mismatched_client_cert_path(&self) -> &std::path::Path {
        &self.mismatched_client_cert_path
    }
    /// Mismatched client leaf key path (T3 `--client-key-file`).
    pub fn mismatched_client_key_path(&self) -> &std::path::Path {
        &self.mismatched_client_key_path
    }
    /// trust.json path (`mcp_re_proxy_cli --trust`).
    pub fn trust_path(&self) -> &std::path::Path {
        &self.trust_path
    }
    /// SERVER signing-seed file path (`mcp_re_proxy_cli --signing-key-seed`).
    pub fn signing_seed_path(&self) -> &std::path::Path {
        &self.signing_seed_path
    }
    /// SIGNER (client) signing-seed file path (the client bin's
    /// `--signing-key-seed-file`).
    pub fn signer_seed_path(&self) -> &std::path::Path {
        &self.signer_seed_path
    }
}

impl Drop for DemoFixtureFiles {
    fn drop(&mut self) {
        // Best-effort cleanup of the private temp directory and its contents.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // The only in-file test that calls `write_files`, so the counter is not raced.
    #[test]
    fn write_files_creates_an_owner_only_directory_and_refuses_an_existing_one() {
        let fx = DemoFixtures::generate_default();
        let files = fx.write_files().expect("write_files");
        let mode = std::fs::metadata(files.dir())
            .expect("dir metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);

        let n = next_counter();
        let planted = std::env::temp_dir().join(format!(
            "mcp_re_demo_fixtures_{}_{}",
            std::process::id(),
            n + 1
        ));
        std::fs::create_dir(&planted).expect("pre-create directory");
        let refused = fx.write_files();
        std::fs::remove_dir_all(&planted).expect("remove planted directory");
        let err = refused.expect_err("an existing directory must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    }
}
