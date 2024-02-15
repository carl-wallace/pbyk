//! Various utility functions including support for listing available YubiKeys, resetting YubiKeys,
//! and checking portal and CA reachability

pub mod list_yubikeys;
pub mod portal_status_check;
pub mod reset_yubikey;
pub mod scep_check;
pub mod state;

pub use crate::utils::{
    list_yubikeys::*, portal_status_check::*, reset_yubikey::*, scep_check::*, state::*,
};

#[cfg(all(target_os = "windows", feature = "vsc"))]
pub mod list_vscs;
#[cfg(all(target_os = "windows", feature = "vsc"))]
pub mod reset_vsc;

#[cfg(all(target_os = "windows", feature = "vsc"))]
pub use crate::utils::list_vscs::*;
