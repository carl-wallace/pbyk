//! Supports extracting keys and certificates from PKCS #12 objects

use std::sync::Once;

use log::error;
use openssl::pkcs12::Pkcs12;

use der::zeroize::Zeroizing;

use crate::{Error, Result};

/// Guard to ensure openssl::init is called just once
static INIT: Once = Once::new();

/// Decrypts the given PKCS #12 object using the provided password and returns a tuple containing the binary DER-encoded
/// certificate and binary DER-encoded key, i.e., as (certificate, key).
#[allow(clippy::type_complexity)]
pub fn process_p12(
    enc_p12: &[u8],
    password: &str,
    want_key: bool,
) -> Result<(Vec<u8>, Option<Zeroizing<Vec<u8>>>)> {
    INIT.call_once(|| {
        openssl::init();
    });

    let pkcs12 = match Pkcs12::from_der(enc_p12) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to parse PKCS #12 object: {e:?}");
            return Err(Error::ParseError);
        }
    };

    let p12 = match pkcs12.as_ref().parse2(password) {
        Ok(p12) => p12,
        Err(e) => {
            error!("Failed to process PKCS #12 object: {e:?}");
            return Err(Error::ParseError);
        }
    };

    let der_cert = match p12.cert {
        Some(c) => match c.to_der() {
            Ok(der) => der,
            Err(e) => {
                error!("Failed to encode certificate from PKCS #12 object: {e:?}");
                return Err(Error::ParseError);
            }
        },
        None => {
            error!("Failed to read certificate from PKCS #12 object");
            return Err(Error::ParseError);
        }
    };

    let der_key = if want_key {
        match p12.pkey {
            Some(k) => match k.rsa() {
                Ok(rsa) => match rsa.private_key_to_der() {
                    Ok(der) => Some(Zeroizing::new(der)),
                    Err(e) => {
                        error!("Failed to encode RSA key from PKCS #12 object: {e:?}");
                        return Err(Error::ParseError);
                    }
                },
                Err(e) => {
                    error!("Failed to get RSA key from PKCS #12 object: {e:?}");
                    return Err(Error::ParseError);
                }
            },
            None => {
                error!("Failed to get key from PKCS #12 object");
                return Err(Error::ParseError);
            }
        }
    } else {
        None
    };

    Ok((der_cert, der_key))
}
