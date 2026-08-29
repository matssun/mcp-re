// SPDX-License-Identifier: Apache-2.0
//! Where the authoritative admission record lives (MCPRE-493).

use super::SharedStoreRequest;

/// The admission store this deployment asks for.
///
/// Separate from replay's on purpose: admission state and replay state have different
/// owners, lifetimes and blast radii, and collapsing them would make one outage two.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdmissionStoreRequest {
    /// The shared store a revocation is written to and every replica reads. Required by
    /// any enforcing admission mode; a gate with no source checks currency against nothing.
    pub authoritative: Option<SharedStoreRequest>,
}

impl AdmissionStoreRequest {
    /// The store's locator, where one is configured. The gate needs a place to reach and
    /// no product name.
    pub fn locator(&self) -> Option<&str> {
        self.authoritative.as_ref().map(SharedStoreRequest::locator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default is no store, which every enforcing mode is refused for at the boundary.
    #[test]
    fn no_authoritative_store_is_the_default() {
        assert_eq!(AdmissionStoreRequest::default().authoritative, None);
    }

    /// The locator is read through the selection, so an enforcing gate names no product.
    #[test]
    fn the_store_is_read_as_a_locator_and_not_as_a_product() {
        let request = AdmissionStoreRequest {
            authoritative: Some(SharedStoreRequest::redis("redis://h:6379")),
        };
        assert_eq!(
            request
                .authoritative
                .as_ref()
                .map(SharedStoreRequest::locator),
            Some("redis://h:6379")
        );
    }
}
