//! Random number generation for security-relevant values.
//!
//! All key material, initialization vectors, salts and passwords are drawn from
//! [`pb_rng`], which reads the operating system's entropy source directly.
//!
//! This module is duplicated in the portal workspace as `pb_tools_lib::utils::rng`.
//! The duplication is deliberate: this crate sits upstream of that one, so the
//! definition cannot be shared without inverting the dependency. **Keep the two
//! copies in step by hand** — in particular, a later move to a validated DRBG has
//! to be made in both places, not one.
//!
//! The alternative, `rand::rng()`, returns a [`ThreadRng`](rand::rngs::ThreadRng):
//! a thread-local ChaCha12 generator seeded from the OS and reseeded every 64 kB
//! of output. That is a sound generator, but it is a userspace one, so the
//! randomness backing a key is a construction of this process rather than of the
//! platform. Reading the OS source per call keeps the generator out of the
//! picture entirely.
//!
//! # Failure handling
//!
//! The CMS and PKCS #12 builders require [`CryptoRng`](rand_core::CryptoRng),
//! whose `fill_bytes` returns no error. An implementation of that bound must
//! therefore either panic when the OS entropy source fails or hand back bytes that
//! are not random, so [`PbRng`] panics: a failed enrollment is recoverable, a
//! credential backed by unknown randomness is not.
//!
//! This is not a new failure mode. `ThreadRng` panics on the same condition, both
//! on initial seeding and on each periodic reseed.
//!
//! Before giving up, [`PbRng`] retries [`RNG_ATTEMPTS`] times. Be clear about how
//! little this buys: on a healthy host the OS source does not fail, and most of
//! the ways it can fail are not transient. On Linux the draw is the `getrandom(2)`
//! syscall, which after boot cannot fail for buffers of this size, and the
//! `/dev/urandom` descriptor fallback is reached only when the syscall itself is
//! refused — a condition that persists rather than passes. A retry therefore
//! covers a momentary fault and nothing more. It is kept because it costs nothing
//! against a working source, not because it makes the panic unlikely; what makes
//! the panic unlikely is that the source essentially does not fail.
//!
//! Retries are immediate. These call paths are synchronous and cannot sleep
//! without blocking a worker thread.
//!
//! The terminal failure is logged through [`log`] before the panic, because a
//! panic message goes to the process's standard error via the panic hook and does
//! not pass through the logging system at all.

use core::convert::Infallible;

use log::{error, warn};
use rand::rngs::{SysError, SysRng};
use rand_core::{TryCryptoRng, TryRng};

/// Number of times a draw from the OS entropy source is attempted before panicking.
const RNG_ATTEMPTS: usize = 3;

/// The RNG used for all security-relevant randomness.
///
/// Reads the operating system's entropy source, retrying a failed draw
/// [`RNG_ATTEMPTS`] times before panicking. Satisfies
/// [`CryptoRng`](rand_core::CryptoRng), which the CMS and PKCS #12 builders
/// require, by way of the blanket implementations for infallible RNGs.
#[derive(Clone, Copy, Debug, Default)]
pub struct PbRng;

/// Returns a handle to the operating system's entropy source.
///
/// The handle is zero-sized and stateless, so callers may construct one wherever
/// they need it rather than threading a single instance through.
#[must_use]
pub fn pb_rng() -> PbRng {
    PbRng
}

/// Runs `op` against the OS entropy source, retrying up to [`RNG_ATTEMPTS`] times.
///
/// Panics once the attempts are exhausted. `op` is expected to be one of the
/// [`SysRng`] draw operations, each of which either completes fully or reports an
/// error, so a retry repeats the whole draw rather than resuming a partial one.
fn with_retry<T>(mut op: impl FnMut(&mut SysRng) -> Result<T, SysError>) -> T {
    for attempt in 1..RNG_ATTEMPTS {
        match op(&mut SysRng) {
            Ok(value) => return value,
            Err(e) => {
                warn!("OS entropy source failed on attempt {attempt} of {RNG_ATTEMPTS}: {e}");
            }
        }
    }

    // No retries remain, so a failure on this attempt is terminal.
    match op(&mut SysRng) {
        Ok(value) => value,
        Err(e) => {
            error!("OS entropy source failed after {RNG_ATTEMPTS} attempts: {e}");
            panic!("OS entropy source failed after {RNG_ATTEMPTS} attempts: {e}");
        }
    }
}

impl TryRng for PbRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(with_retry(SysRng::try_next_u32))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(with_retry(SysRng::try_next_u64))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        with_retry(|rng| rng.try_fill_bytes(dst));
        Ok(())
    }
}

impl TryCryptoRng for PbRng {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{CryptoRng, Rng};

    /// Confirms `PbRng` satisfies the bound the CMS and PKCS #12 builders require.
    #[test]
    fn satisfies_crypto_rng() {
        /// Stands in for a builder that demands an infallible cryptographic RNG.
        fn takes_crypto_rng<R: CryptoRng>(rng: &mut R) -> u32 {
            rng.next_u32()
        }
        let _ = takes_crypto_rng(&mut pb_rng());
    }

    /// Confirms a draw fills the whole buffer rather than part of it.
    #[test]
    fn fills_entire_buffer() {
        let mut rng = pb_rng();
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        assert!(buf.iter().any(|b| *b != 0), "buffer left entirely zeroed");

        let mut other = [0u8; 64];
        rng.fill_bytes(&mut other);
        assert_ne!(buf, other, "two draws produced identical output");
    }
}
