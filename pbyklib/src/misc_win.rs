//! Windows-specific utility functions for use in pbyklib

pub(crate) mod cert_store;
#[cfg(feature = "vsc")]
pub(crate) mod csr;
#[cfg(feature = "vsc")]
pub(crate) mod scep;
pub(crate) mod utils;
#[cfg(feature = "vsc")]
pub mod vsc_signer;
#[cfg(feature = "vsc")]
pub(crate) mod vsc_state;
pub(crate) mod yubikey;
