// SPDX-License-Identifier: Apache-2.0
//! Where this deployment listens, what it fronts, and the topology it claims.

/// The serving inputs, as they accumulate across the argument list.
#[derive(Default)]
pub(super) struct ServingFlags {
    bind: Option<String>,
    route: Option<String>,
    inner_http_urls: Vec<String>,
    trust_path: Option<String>,
    fleet: bool,
    allow_group_readable_key_files: bool,
}

/// What one deployment serves, and from what.
#[derive(Debug)]
pub(super) struct ServingSurface {
    pub(super) bind: String,
    pub(super) route: Option<String>,
    pub(super) inner_http_urls: Vec<String>,
    pub(super) trust_path: String,
    pub(super) fleet: bool,
    pub(super) allow_group_readable_key_files: bool,
}

impl ServingFlags {
    /// Whether this value-taking flag belongs to the family.
    pub(super) fn owns(flag: &str) -> bool {
        matches!(flag, "--bind" | "--route" | "--inner-http-url" | "--trust")
    }

    /// Read one value-taking flag of the family. [`Self::owns`] decided it is one.
    pub(super) fn take(&mut self, flag: &str, value: &str) {
        match flag {
            "--bind" => self.bind = Some(value.to_string()),
            "--route" => self.route = Some(value.to_string()),
            // ADR-MCPRE-051 §3: stateless HTTP inner backend URL(s) for the async serving
            // path. Comma-separated and/or repeated; splitting is the CLI's encoding, and
            // whether a resulting value names a backend is the boundary's.
            "--inner-http-url" => self
                .inner_http_urls
                .extend(value.split(',').map(str::to_string)),
            _ => self.trust_path = Some(value.to_string()),
        }
    }

    /// Read one valueless flag of the family, reporting whether it was one.
    pub(super) fn take_switch(&mut self, flag: &str) -> bool {
        match flag {
            // Select the horizontally-scaled (fleet) deployment topology.
            "--fleet" => self.fleet = true,
            // C053b: accept a group-READABLE key file whose group this process is in — the
            // Kubernetes fsGroup mount model. Explicit, because it widens who can read a
            // signing key; the strict 0600 floor is otherwise unsatisfiable for a non-root
            // pod.
            "--allow-group-readable-key-files" => self.allow_group_readable_key_files = true,
            _ => return false,
        }
        true
    }

    /// The surface, or the locator this command line did not give.
    pub(super) fn finish(self) -> Result<ServingSurface, String> {
        Ok(ServingSurface {
            bind: super::require(self.bind, "--bind")?,
            route: self.route,
            inner_http_urls: self.inner_http_urls,
            trust_path: super::require(self.trust_path, "--trust")?,
            fleet: self.fleet,
            allow_group_readable_key_files: self.allow_group_readable_key_files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> ServingFlags {
        let mut flags = ServingFlags::default();
        flags.take("--bind", "127.0.0.1:8443");
        flags.take("--trust", "/trust.json");
        flags
    }

    /// The listen address and the trust document are required; the rest have postures for
    /// their own absence.
    #[test]
    fn the_address_and_the_trust_document_are_required() {
        for flag in ["--bind", "--trust"] {
            let mut flags = ServingFlags::default();
            for (other, value) in [("--bind", "127.0.0.1:8443"), ("--trust", "/t.json")] {
                if other != flag {
                    flags.take(other, value);
                }
            }
            let err = flags.finish().expect_err("one locator is missing");
            assert!(err.contains(flag), "{flag}: {err}");
        }
        let surface = minimal().finish().expect("both given");
        assert_eq!(surface.route, None);
        assert!(surface.inner_http_urls.is_empty());
    }

    /// Backends are comma-separated and repeatable, and both spellings reach the same list.
    #[test]
    fn backends_accumulate_however_they_were_spelled() {
        let mut flags = minimal();
        flags.take("--inner-http-url", "http://a/mcp,http://b/mcp");
        flags.take("--inner-http-url", "http://c/mcp");
        assert_eq!(flags.finish().expect("a surface").inner_http_urls.len(), 3);
    }

    /// The two switches are recognised as switches, and nothing else is.
    #[test]
    fn the_switches_are_recognised_and_only_those() {
        let mut flags = minimal();
        assert!(flags.take_switch("--fleet"));
        assert!(flags.take_switch("--allow-group-readable-key-files"));
        assert!(!flags.take_switch("--bind"));
        let surface = flags.finish().expect("a surface");
        assert!(surface.fleet && surface.allow_group_readable_key_files);
    }
}
