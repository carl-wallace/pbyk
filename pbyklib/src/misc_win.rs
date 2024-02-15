//! Windows-specific utility functions for use in pbyklib

#![cfg(target_os = "windows")]

#[cfg(target_os = "windows")]
pub(crate) mod cert_store;
#[cfg(all(target_os = "windows", feature = "vsc"))]
pub(crate) mod csr;
#[cfg(all(target_os = "windows", feature = "vsc"))]
pub(crate) mod scep;
#[cfg(target_os = "windows")]
pub(crate) mod utils;
#[cfg(all(target_os = "windows", feature = "vsc"))]
pub mod vsc_signer;
#[cfg(all(target_os = "windows", feature = "vsc"))]
pub(crate) mod vsc_state;
#[cfg(target_os = "windows")]
pub(crate) mod yubikey;
