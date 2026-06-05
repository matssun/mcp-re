//! Injected nonce-byte source for the host session (MCPS-033, ADR-MCPS-015).
//!
//! The session generates each request `nonce` from an injected [`NonceSource`]
//! and Base64URL-encodes it (MCPS_SPEC §2/§5: opaque, Base64URL-safe, ≥128 bits
//! of entropy). Injection keeps signing deterministic under test while the
//! production default draws from the OS CSPRNG.
//!
//! `getrandom` is the production entropy source: it is already in the mcps-host
//! dependency closure (transitively, via `ed25519-dalek`), is a thin wrapper over
//! the OS RNG, and pulls in NO networking/async runtime — so the crate stays
//! transport-free.

/// The number of random bytes drawn per nonce: 16 bytes = 128 bits, the spec's
/// minimum entropy. Encoded Base64URL-no-pad this is a 22-character opaque token.
pub const NONCE_BYTES: usize = 16;

/// A source of cryptographically opaque nonce bytes.
///
/// Implemented in production by [`SystemNonceSource`] (OS CSPRNG via `getrandom`)
/// and in tests by [`SeededNonceSource`] (a deterministic byte stream), so the
/// session's signed output is reproducible under a fixed seed.
pub trait NonceSource {
    /// Fill `out` with `out.len()` fresh nonce bytes.
    fn fill(&mut self, out: &mut [u8]);
}

/// Production nonce source: fills from the operating-system CSPRNG via
/// `getrandom`. No networking, no async runtime — OS entropy only.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemNonceSource;

impl SystemNonceSource {
    /// Construct the production nonce source.
    pub fn new() -> Self {
        SystemNonceSource
    }
}

impl NonceSource for SystemNonceSource {
    fn fill(&mut self, out: &mut [u8]) {
        // `getrandom` reads OS entropy and only errors when the OS RNG is
        // genuinely unavailable. A host that cannot draw entropy must not emit a
        // predictable nonce, so we fail loudly rather than degrade silently. This
        // is the production default; deterministic tests inject SeededNonceSource
        // and never reach this path.
        getrandom::getrandom(out).expect("OS CSPRNG (getrandom) must be available to sign requests");
    }
}

/// Deterministic test nonce source: yields the seed bytes as a repeating stream,
/// advancing per byte so successive nonces differ while remaining reproducible.
///
/// Lives in the library (not behind `cfg(test)`) so it is reusable as an
/// injectable fixture by integration tests in this and dependent crates. It is a
/// TEST provider — never use it in production (it has no real entropy).
#[derive(Debug, Clone)]
pub struct SeededNonceSource {
    seed: Vec<u8>,
    offset: usize,
}

impl SeededNonceSource {
    /// Construct a deterministic source over a non-empty `seed`.
    ///
    /// The first draw returns the leading `seed` bytes verbatim, so callers can
    /// pin exact nonce values in tests.
    pub fn new(seed: &[u8]) -> Self {
        SeededNonceSource {
            // A non-empty stream is required to fill any output; fall back to a
            // single zero byte for an empty seed so `fill` is always defined.
            seed: if seed.is_empty() { vec![0u8] } else { seed.to_vec() },
            offset: 0,
        }
    }
}

impl NonceSource for SeededNonceSource {
    fn fill(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            *byte = self.seed[self.offset % self.seed.len()];
            self.offset += 1;
        }
    }
}
