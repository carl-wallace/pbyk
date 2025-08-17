#![doc = include_str!("../README.md")]
#![warn(clippy::missing_docs_in_private_items)]

pub mod ota;
pub mod utils;

pub mod misc;
mod ota_yubikey;

#[cfg(target_os = "windows")]
mod misc_win;
mod misc_yubikey;
#[cfg(all(target_os = "windows", feature = "vsc"))]
mod ota_vsc;

/// Result type for pbyklib
pub type Result<T> = core::result::Result<T, Error>;

/// Error values for pbyklib
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    BadInput,
    NotFound,
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
    Base64(base64ct::Error),
    SerdeJson,
    Io,
    Signature,
    Plist,
    Decryption,
    MissingAttribute,
    UnexpectedValue,
    Pbykcorelib(pbykcorelib::Error),
    #[cfg(all(target_os = "windows", feature = "vsc"))]
    Vsc,
    #[cfg(all(target_os = "windows", feature = "vsc"))]
    Rsa(pkcs1::Error),
    #[cfg(all(target_os = "windows", feature = "vsc"))]
    CertBuilder,
    #[cfg(all(target_os = "windows", feature = "vsc"))]
    CmsBuilder,
}

use std::io;
impl From<io::Error> for Error {
    fn from(_: io::Error) -> Error {
        Error::Io
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        use log::error;
        error!("reqwest::Error: {err}");
        Error::Network
    }
}

impl From<pbykcorelib::Error> for Error {
    fn from(err: pbykcorelib::Error) -> Error {
        Error::Pbykcorelib(err)
    }
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
impl From<yubikey::Error> for Error {
    fn from(err: yubikey::Error) -> Error {
        Error::YubiKey(err)
    }
}
impl From<base64ct::Error> for Error {
    fn from(err: base64ct::Error) -> Error {
        Error::Base64(err)
    }
}
impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        use log::error;
        error!("serde_json::Error: {err}");
        Error::SerdeJson
    }
}

#[cfg(all(target_os = "windows", feature = "vsc"))]
impl From<windows::core::Error> for Error {
    fn from(err: windows::core::Error) -> Error {
        use log::error;
        error!("windows::core::Error: {err}");
        Error::Vsc
    }
}
#[cfg(all(target_os = "windows", feature = "vsc"))]
impl From<pkcs1::Error> for Error {
    fn from(err: pkcs1::Error) -> Error {
        Error::Rsa(err)
    }
}

#[cfg(all(target_os = "windows", feature = "vsc"))]
impl From<x509_cert::builder::Error> for Error {
    fn from(err: x509_cert::builder::Error) -> Error {
        use log::error;
        error!("x509_cert::builder::Error: {err}");
        Error::CertBuilder
    }
}

#[cfg(all(target_os = "windows", feature = "vsc"))]
impl From<cms::builder::Error> for Error {
    fn from(err: cms::builder::Error) -> Error {
        use log::error;
        error!("cms::builder::Error: {err}");
        Error::CmsBuilder
    }
}

use const_oid::ObjectIdentifier;
use std::sync::LazyLock;

use yubikey::{MgmAlgorithmId, MgmKey, Version, YubiKey};
/// Default management key for YubiKey devices enrolled with Purebred
///
/// The value used by Purebred is a slight modification (020203040506070801020304050607080102030405060708) to
/// the [default value](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/fips-specifics.html#id4) used natively
/// by the device.
const DEFAULT_PB_MGM_KEY: [u8; 24] = [
    2, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

/// Return firmware-appropriate default management key
pub fn get_pb_default(yubikey: &YubiKey) -> MgmKey {
    match yubikey.version() {
        // Initial firmware versions default to 3DES.
        Version { major: ..=4, .. }
        | Version {
            major: 5,
            minor: ..=6,
            ..
        } => MgmKey::from_bytes(DEFAULT_PB_MGM_KEY.as_slice(), MgmAlgorithmId::ThreeDes).unwrap(),
        // Firmware 5.7.0 and above default to AES-192.
        Version {
            major: 5,
            minor: 7..,
            ..
        }
        | Version { major: 6.., .. } => {
            MgmKey::from_bytes(DEFAULT_PB_MGM_KEY.as_slice(), MgmAlgorithmId::Aes192).unwrap()
        }
    }
}

/// Determines if the given YubiKey is expected to support larger RSA key sizes, i.e., true if firmware is 5.7.0 or
/// greater and false otherwise.
pub fn supports_larger_rsa_keys(yubikey: &YubiKey) -> bool {
    match yubikey.version() {
        // Initial firmware versions default to 3DES.
        Version { major: ..=4, .. }
        | Version {
            major: 5,
            minor: ..=6,
            ..
        } => false,
        // Firmware 5.7.0 and above default to AES-192.
        Version {
            major: 5,
            minor: 7..,
            ..
        }
        | Version { major: 6.., .. } => true,
    }
}
pub fn get_min_pin_size(yubikey: &YubiKey) -> i8 {
    match yubikey.version() {
        // Initial firmware versions default to 3DES.
        Version { major: ..=4, .. }
        | Version {
            major: 5,
            minor: ..=6,
            ..
        } => 6,
        // Firmware 5.7.0 and above default to AES-192.
        Version {
            major: 5,
            minor: 7..,
            ..
        }
        | Version { major: 6.., .. } => 8,
    }
}

/// `id-purebred-yubikey-attestation-attribute` from Red Hound's OID arc
pub static ID_PUREBRED_YUBIKEY_ATTESTATION_ATTRIBUTE: LazyLock<ObjectIdentifier> =
    LazyLock::new(|| ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37623.26.4"));

/// `id-purebred-microsoft-attestation-attribute` from Red Hound's OID arc
pub static ID_PUREBRED_MICROSOFT_ATTESTATION_ATTRIBUTE: LazyLock<ObjectIdentifier> =
    LazyLock::new(|| ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37623.26.3"));

#[cfg(target_os = "windows")]
use windows::Win32::Security::Cryptography::{
    CERT_OPEN_STORE_FLAGS, CERT_SYSTEM_STORE_CURRENT_USER_ID, CERT_SYSTEM_STORE_LOCATION_SHIFT,
};

/// `CERT_OPEN_STORE_FLAGS` value to target the current user when opening a certificate store via
/// [CertOpenStore](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/Cryptography/fn.CertOpenStore.html)
#[cfg(target_os = "windows")]
pub static CERT_SYSTEM_STORE_CURRENT_USER: CERT_OPEN_STORE_FLAGS =
    CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT);
