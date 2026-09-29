// SPDX-License-Identifier: Apache-2.0
//! The one way an operator-configured locator is rendered for human eyes.
//!
//! # The authority
//!
//! > Operator-configured locators may contain credentials. No operational error or
//! > operator-facing diagnostic may render the configured locator directly. A safe
//! > projection may expose only non-secret routing coordinates; if it cannot safely
//! > decompose the input, it names the failure without echoing the input.
//!
//! Every locator a deployment takes — an inner-backend URL, a Redis or etcd store URL, a
//! KMS endpoint, a target URI — is a string an operator typed, and a URL carries
//! credentials in more than one position: `https://user:pass@host/path`,
//! `redis://:hunter2@host:6379`, `http://host/?token=s3cr3t`, and a token carried as a
//! path segment. A diagnostic that echoes the configured string publishes whichever the
//! operator used, and does so on exactly the path where the string was WRONG — which is
//! the path a typo takes. It is a workspace-level owner because more than one crate
//! renders such a locator, and two independently authored redactions are the defect in
//! its most durable form.
//!
//! # What is rendered
//!
//! **Scheme, host and port, and nothing else.** Userinfo, path, query and fragment are all
//! removed, because nothing here proves any of them free of credentials. Their removal is
//! REPORTED — an operator who configured a path needs to know the line is not showing it —
//! but the report names the component, never its contents.
//!
//! [`RedactedLocator`] owns that rendering. The rendered text is its private
//! representation and its sole constructor performs the projection, so possession of one
//! means the removal already happened. There is no path from a raw locator to a rendered
//! one that skips it: no `Debug`, no `as_str`, no `From<String>`, no field accessor.
//!
//! The decomposition is hand-written over `std`. That is deliberate: this crate takes no
//! dependency, so nothing it renders can change because a parser upstream changed its
//! mind, and a shape the hand-written decomposition cannot confidently take apart is
//! NAMED rather than echoed.

/// The projection itself, and the only constructor that performs it.
mod locator;

pub use locator::RedactedLocator;
