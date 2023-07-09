//! Imports a PKCS12 object into a YubiKey

use std::sync::Once;

use openssl::pkcs12::Pkcs12;

use crate::{log_error, log_info, Error};
use der::Decode;
use rsa::pkcs1::RsaPrivateKey;
use yubikey::piv::RetiredSlotId;
use yubikey::piv::SlotId::KeyManagement;
use yubikey::{
    certificate::{write, CertInfo},
    piv::{import_rsa_key, AlgorithmId, RsaKeyData, SlotId},
    PinPolicy, TouchPolicy, YubiKey,
};

static INIT: Once = Once::new();

/// Gets a SlotId from the index of a given PKCS 12 object within a configuration profile
fn get_slot_from_index(index: u8) -> SlotId {
    if 0 == index {
        KeyManagement
    } else {
        let rs: RetiredSlotId = match index.try_into() {
            Ok(rs) => rs,
            Err(_e) => RetiredSlotId::R20,
        };
        SlotId::Retired(rs)
    }
}

/// Writes the key and certificate extracted from `enc_p12` to the indicated YubiKey, using the `index`
/// value to choose the slot. The first PKCS12 object that appears in a configuration profile is
/// written to the KeyManagement slot with successive objects written to the retired slots starting with
/// retired slot 0.
pub(crate) async fn import_p12(
    yubikey: &mut YubiKey,
    enc_p12: &[u8],
    password: &str,
    index: u8,
) -> crate::Result<()> {
    log_info(&format!("Processing PKCS #12 payload with index {index}"));

    INIT.call_once(|| {
        openssl::init();
    });

    let slot = get_slot_from_index(index);

    let pkcs12 = match Pkcs12::from_der(enc_p12) {
        Ok(p) => p,
        Err(_e) => {
            log_error(&format!("Failed to parse PKCS #12 object at index {index}"));
            return Err(Error::ParseError);
        }
    };

    let p12 = match pkcs12.as_ref().parse2(password) {
        Ok(p12) => p12,
        Err(_e) => {
            log_error(&format!(
                "Failed to process PKCS #12 object at index {index}"
            ));
            return Err(Error::ParseError);
        }
    };

    let der_key = match p12.pkey {
        Some(k) => match k.rsa() {
            Ok(rsa) => match rsa.private_key_to_der() {
                Ok(der) => der,
                Err(_e) => {
                    log_error(&format!(
                        "Failed to encode RSA key from PKCS #12 object at index {index}"
                    ));
                    return Err(Error::ParseError);
                }
            },
            Err(_e) => {
                log_error(&format!(
                    "Failed to get RSA key from PKCS #12 object at index {index}"
                ));
                return Err(Error::ParseError);
            }
        },
        None => {
            log_error(&format!(
                "Failed to get key from PKCS #12 object at index {index}"
            ));
            return Err(Error::ParseError);
        }
    };

    let rpk = match RsaPrivateKey::from_der(&der_key) {
        Ok(rpk) => rpk,
        Err(e) => {
            log_error(&format!(
                "Failed to parse RSA key from PKCS #12 object at index {index}"
            ));
            return Err(Error::Asn1(e));
        }
    };

    let rkd = RsaKeyData::new(rpk.prime1.as_bytes(), rpk.prime2.as_bytes());
    if let Err(e) = import_rsa_key(
        yubikey,
        slot,
        AlgorithmId::Rsa2048,
        rkd,
        TouchPolicy::Default,
        PinPolicy::Default,
    ) {
        log_error(&format!(
            "Failed to import RSA key from PKCS #12 object at index {index} into slot {slot}: {:?}",
            e
        ));
        return Err(Error::YubiKey(e));
    }

    let der_cert = match p12.cert {
        Some(c) => match c.to_der() {
            Ok(der) => der,
            Err(_e) => {
                log_error(&format!(
                    "Failed to encode certificate from PKCS #12 object at index {index}"
                ));
                return Err(Error::ParseError);
            }
        },
        None => {
            log_error(&format!(
                "Failed to read certificate from PKCS #12 object at index {index}"
            ));
            return Err(Error::ParseError);
        }
    };
    if let Err(e) = write(yubikey, slot, CertInfo::Uncompressed, &der_cert) {
        log_error(&format!("Failed to import certificate from PKCS #12 object at index {index} into slot {slot}: {:?}", e));
        return Err(Error::YubiKey(e));
    }

    Ok(())
}
