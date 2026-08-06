//! Assembles the compile-time-selected trust-store providers for
//! [`certval_stores_core`].
//!
//! The environment feature array (`dev` / `om_nipr` / `nipr` / `om_sipr` /
//! `sipr`) is retained here: each feature pulls in the matching provider crate
//! and adds its provider to the list handed to `certval_stores_core`.

use certval_stores_core::TrustStoreProvider;

#[cfg(not(any(
    feature = "dev",
    feature = "om_nipr",
    feature = "nipr",
    feature = "om_sipr",
    feature = "sipr"
)))]
compile_error!(
    "at least one environment feature (\"dev\", \"om_nipr\", \"nipr\", \"om_sipr\", or \"sipr\") must be enabled"
);

/// Returns the trust-store providers for the environments this build was
/// compiled with, for passing to `certval_stores_core` functions.
// Providers are cfg-gated, so this cannot be a `vec![]` literal.
#[allow(unused_mut, clippy::vec_init_then_push)]
pub fn providers() -> Vec<&'static dyn TrustStoreProvider> {
    let mut providers: Vec<&'static dyn TrustStoreProvider> = Vec::new();
    #[cfg(feature = "dev")]
    providers.push(certval_stores_pbdev::provider());
    #[cfg(any(feature = "om_nipr", feature = "nipr"))]
    providers.push(certval_stores_nipr::provider());
    #[cfg(any(feature = "om_sipr", feature = "sipr"))]
    providers.push(certval_stores_sipr::provider());
    providers
}
