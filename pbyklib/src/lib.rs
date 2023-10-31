#![doc = include_str!("../README.md")]

mod misc;
pub mod ota;
pub mod utils;

use hex_literal::hex;
use lazy_static::lazy_static;
use yubikey::MgmKey;

/// Result type for pbyklib
pub type Result<T> = core::result::Result<T, Error>;

/// Error values for pbyklib
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    BadInput,
    Network,
    Forbidden,
    UnexpectedDeviceState,
    Unrecognized,
    ParseError,
    KeyUsageMissing,
    /// Asn1 is used to propagate error information from the x509 and related crates
    Asn1(der::Error),
    /// Certval is used to propagate error information from the certval crate
    Certval(certval::Error),
    /// YubiKey is used to propagate error information from the yubikey crate
    YubiKey(yubikey::Error),
    Signature,
    Plist,
    Decryption,
    MissingAttribute,
    UnexpectedValue,
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
}
impl From<certval::Error> for Error {
    fn from(err: certval::Error) -> Error {
        Error::Certval(err)
    }
}

lazy_static! {
    /// Default management key for devices enrolled with Purebred
    pub static ref PB_MGMT_KEY: MgmKey =
        MgmKey::new(hex!("020203040506070801020304050607080102030405060708")).unwrap();
}
