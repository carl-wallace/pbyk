#![doc = include_str!("../README.md")]

pub mod data;
pub mod enroll;
pub mod list_yubikeys;
pub mod pre_enroll;
pub mod recover;
pub mod reset_yubikey;
pub mod ukm;

mod network;
mod p12;
mod rsa_utils;
mod scep;
mod utils;
mod yubikey_utils;

use hex_literal::hex;
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use yubikey::MgmKey;

/// Result type for pbyklib
pub type Result<T> = core::result::Result<T, Error>;

/// Error values for pbyklib
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[allow(dead_code)]
pub enum Error {
    Time,
    BadInput,
    Base64,
    Config,
    Network,
    Io,
    Unrecognized,
    ParseError,
    /// Asn1Error is used to propagate error information from the x509 crate.
    Asn1(der::Error),
    YubiKey(yubikey::Error),
    Signature,
    Plist,
    Decryption,
}

/// Generates error level logging output per calling application configured logging
pub fn log_error(message: &str) {
    error!("{}", message)
}

/// Generates warn level logging output per calling application configured logging
pub fn log_warn(message: &str) {
    warn!("{}", message)
}

/// Generates info level logging output per calling application configured logging
pub fn log_info(message: &str) {
    info!("{}", message)
}

/// Generates info level logging output per calling application configured logging
pub fn log_debug(message: &str) {
    debug!("{}", message)
}

lazy_static! {
    /// Default management key for devices enrolled with Purebred
    pub static ref PB_MGMT_KEY: MgmKey =
        MgmKey::new(hex!("020203040506070801020304050607080102030405060708")).unwrap();

    /// Base URL of Purebred portal
    pub static ref PB_HOST: String = "https://pb2.redhoundsoftware.net".to_string();
}
