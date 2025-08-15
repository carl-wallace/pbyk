//! Windows-specific utility functions related to YubiKey management for use within pbyklib
//!
#![cfg(target_os = "windows")]

use crate::misc_win::cert_store::delete_cert_from_store;
use der::Encode;
use yubikey::YubiKey;
use yubikey::piv::SLOTS;

/// Check each slot on the YubiKey for a certificate. If one is found, delete it from the current
/// user's CAPI stores.
pub(crate) fn cleanup_capi_yubikey(yubikey: &mut YubiKey) {
    for slot in SLOTS {
        match yubikey::certificate::Certificate::read(yubikey, slot) {
            Ok(c) => {
                if let Ok(der_cert) = c.cert.to_der() {
                    delete_cert_from_store(&der_cert);
                }
            }
            Err(_e) => {}
        };
    }
}
