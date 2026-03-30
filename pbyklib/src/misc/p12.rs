//! Supports extracting keys and certificates from PKCS #12 objects

use log::error;

use der::{Encode, zeroize::Zeroizing};
use pkcs8::PrivateKeyInfoRef;

use crate::{Error, Result};

/// Decrypts the given PKCS #12 object using the provided password and returns a tuple containing the binary DER-encoded
/// certificate and binary DER-encoded key (PKCS #1 format), i.e., as (certificate, key).
#[allow(clippy::type_complexity)]
pub fn process_p12(
    enc_p12: &[u8],
    password: &str,
    want_key: bool,
) -> Result<(Vec<u8>, Option<Zeroizing<Vec<u8>>>)> {
    let contents = match pkcs12_builder::get_key_and_cert(enc_p12, password) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse/decrypt PKCS #12 object: {e:?}");
            return Err(Error::ParseError);
        }
    };

    let der_cert = match contents.certificate.to_der() {
        Ok(der) => der,
        Err(e) => {
            error!("Failed to encode certificate from PKCS #12 object: {e:?}");
            return Err(Error::ParseError);
        }
    };

    let der_key = if want_key {
        // pkcs12_builder returns the key as PKCS #8 PrivateKeyInfo. Extract the
        // inner algorithm-specific key bytes (PKCS #1 RSAPrivateKey for RSA keys)
        // to maintain compatibility with downstream consumers.
        let pki = match PrivateKeyInfoRef::try_from(contents.key_der.as_ref()) {
            Ok(pki) => pki,
            Err(e) => {
                error!("Failed to parse PKCS #8 key from PKCS #12 object: {e:?}");
                return Err(Error::ParseError);
            }
        };
        Some(Zeroizing::new(pki.private_key.as_bytes().to_vec()))
    } else {
        None
    };

    Ok((der_cert, der_key))
}
