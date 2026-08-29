// SPDX-License-Identifier: Apache-2.0
//! Reading the PKCS#11 User PIN, at the one point it is used.

use crate::deployment_request::SecretString;
use crate::key_source::KeyError;

/// Read the PKCS#11 User PIN from `path` into a short-lived [`SecretString`].
///
/// Enforces the key-file permission floor here as well as at startup: `run()` checks it
/// via `key_files_read_from_disk`, but `build_key_source` is a public entry point a test
/// or an embedding binary can reach directly, and a secret-reading function that trusts
/// its caller to have checked is one refactor from not being checked at all.
///
/// Trailing whitespace is trimmed — a PIN file written with `echo` ends in a newline, and
/// a token would reject the PIN with an opaque error that looks like a wrong PIN. Interior
/// whitespace is preserved: it may be part of the PIN.
pub fn read_pkcs11_pin(path: &str) -> Result<SecretString, KeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| {
            KeyError::NotFound(format!("--pkcs11-pin-file {path} cannot be read: {e}"))
        })?;
        let mode = meta.permissions().mode();
        if crate::config_state::key_file_access::mode_is_insecure(mode) {
            return Err(KeyError::NotFound(format!(
                "--pkcs11-pin-file {path} is group/world-accessible (mode {:o}); it unlocks \
                 the token holding the signing keys, so restrict it to 0600",
                mode & 0o777
            )));
        }
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| KeyError::NotFound(format!("--pkcs11-pin-file {path} cannot be read: {e}")))?;
    let pin = SecretString::new(raw.trim_end());
    if pin.expose().is_empty() {
        return Err(KeyError::NotFound(format!(
            "--pkcs11-pin-file {path} is empty; a blank PIN would be sent to the token"
        )));
    }
    Ok(pin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_string_does_not_print_its_value_or_length() {
        // C049: DeploymentRequest derives Debug and is cloned freely. The PIN is no longer a DeploymentRequest
        // field at all, but the type that carries it in transit must not leak either.
        let secret = crate::deployment_request::SecretString::new("hunter2");
        let rendered = format!("{secret:?}");
        assert!(
            !rendered.contains("hunter2"),
            "Debug leaked the value: {rendered}"
        );
        assert!(
            !rendered.contains('7'),
            "Debug leaked the length: {rendered}"
        );
        assert_eq!(
            secret.expose(),
            "hunter2",
            "the value is still retrievable on purpose"
        );
    }

    #[test]
    fn the_pin_file_reader_trims_a_trailing_newline_and_refuses_an_empty_file() {
        // A PIN file written with `echo` ends in a newline; sending that to a token gets
        // an opaque failure that looks like a wrong PIN. An EMPTY file is refused rather
        // than sending a blank PIN.
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let ok_path = dir.join(format!("mcp-re-pin-ok-{pid}"));
        let empty_path = dir.join(format!("mcp-re-pin-empty-{pid}"));
        std::fs::write(&ok_path, b"1234\n").expect("write pin");
        std::fs::write(&empty_path, b"  \n").expect("write empty pin");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [&ok_path, &empty_path] {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod 0600");
            }
        }

        let pin = read_pkcs11_pin(ok_path.to_str().unwrap()).expect("reads");
        assert_eq!(
            pin.expose(),
            "1234",
            "the trailing newline is not part of the PIN"
        );
        assert!(
            read_pkcs11_pin(empty_path.to_str().unwrap()).is_err(),
            "an empty PIN file must not yield a blank PIN"
        );
        let _ = std::fs::remove_file(&ok_path);
        let _ = std::fs::remove_file(&empty_path);
    }

    #[test]
    fn a_group_readable_pin_file_is_refused() {
        // The PIN unlocks the token holding the signing keys, so it sits behind the same
        // permission floor as a key file. Checked in the reader itself, not only at
        // startup: build_key_source is a public entry point.
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("mcp-re-pin-lax-{}", std::process::id()));
        // A PIN that cannot occur in the path itself. `b"1234"` could: the file is named
        // after the process id, and a pid of 12341 made the assertion below fire on the
        // path in the message rather than on an echoed secret.
        const PIN: &[u8] = b"pin-nowhere-in-any-path";
        std::fs::write(&path, PIN).expect("write pin");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("chmod 0640");
        let err = read_pkcs11_pin(path.to_str().unwrap()).unwrap_err();
        let message = format!("{err:?}");
        assert!(
            message.contains("group/world-accessible"),
            "expected a permission refusal, got: {message}"
        );
        assert!(
            !message.contains(std::str::from_utf8(PIN).expect("utf-8")),
            "the refusal must not echo the PIN: {message}"
        );
        let _ = std::fs::remove_file(&path);
    }
}
