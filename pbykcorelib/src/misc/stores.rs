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

// Checked here rather than only in the pbyk binary because this is where the providers are
// assembled: every store a provider returns is trusted, for path validation and for TLS, so a
// production build that also enables a test environment trusts that environment's roots. A crate
// that takes this one, or pbyklib, with default features gets `dev` as well.
#[cfg(all(
    any(feature = "nipr", feature = "sipr"),
    any(feature = "dev", feature = "om_nipr", feature = "om_sipr")
))]
compile_error!(
    "the production environment features \"nipr\" and \"sipr\" cannot be combined with the test environment features \"dev\", \"om_nipr\", or \"om_sipr\"; a production build takes this crate with default-features = false"
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

/// The ids of every store the providers from [`providers`] return, for an HTTP client that trusts
/// all of the trust material this build was compiled with.
pub fn store_ids() -> Vec<&'static str> {
    providers()
        .iter()
        .flat_map(|p| p.entries())
        .map(|e| e.id)
        .collect()
}

/// The store id carrying the trust material for a Purebred environment.
///
/// The two are different things that used to be one string: an environment names
/// a portal to enroll against, a store id names a set of trust anchors, and the
/// providers state the latter. Mapping here rather than at the call sites keeps
/// the correspondence beside the provider list it belongs with, and keeps it
/// cfg-gated the same way -- an environment this build has no provider for has no
/// store to name.
///
/// The ids come from the provider crates as constants, so renaming one there is a
/// compile error here rather than a run-time "did not match any provider".
#[allow(unreachable_patterns)]
pub fn store_id(env: &str) -> Option<&'static str> {
    match env {
        #[cfg(feature = "dev")]
        "DEV" => Some(certval_stores_pbdev::PUREBRED_DEV),
        #[cfg(feature = "om_nipr")]
        "OM_NIPR" => Some(certval_stores_nipr::NIPR_OM),
        #[cfg(feature = "nipr")]
        "NIPR" => Some(certval_stores_nipr::NIPR_PROD),
        #[cfg(feature = "om_sipr")]
        "OM_SIPR" => Some(certval_stores_sipr::SIPR_OM),
        #[cfg(feature = "sipr")]
        "SIPR" => Some(certval_stores_sipr::SIPR_PROD),
        _ => None,
    }
}
