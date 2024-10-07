pub mod misc;

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
    Base64(base64ct::Error),
    SerdeJson,
    Io,
    Signature,
    Plist,
    Decryption,
    MissingAttribute,
    UnexpectedValue,
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

use const_oid::ObjectIdentifier;
use lazy_static::lazy_static;

lazy_static! {

/// `pkcs-9-at-challengePassword` from [RFC 2985 Section 5.4.1]
///
/// [RFC 2985 Section 5.4.1]: https://www.rfc-editor.org/rfc/rfc2985#section-5.4.1
pub static ref ID_CHALLENGE_PASSWORD: ObjectIdentifier =
ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.7");

/// `id-messageType` from [RFC 8894 Section 3.2.1.2]
///
/// [RFC 8894 Section 3.2.1.2]: https://www.rfc-editor.org/rfc/rfc8894#section-3.2.1.2
pub static ref  RFC8894_ID_MESSAGE_TYPE: ObjectIdentifier =
ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.2");

/// `id-senderNonce` from [RFC 8894 Section 3.2.1.5]
///
/// [RFC 8894 Section 3.2.1.5]: https://www.rfc-editor.org/rfc/rfc8894#section-3.2.1.5
pub static ref  RFC8894_ID_SENDER_NONCE: ObjectIdentifier =
ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.5");

/// `id-transactionID` from [RFC 8894 Section 3.2.1.1]
///
/// [RFC 8894 Section 3.2.1.1]: https://www.rfc-editor.org/rfc/rfc8894#section-3.2.1.1
pub static ref  RFC8894_ID_TRANSACTION_ID: ObjectIdentifier =
ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.7");
}
