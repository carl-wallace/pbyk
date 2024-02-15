//! Supports listing available YubiKeys and selecting a YubiKey by serial number

use crate::{Error, Result};
use certval::buffer_to_hex;
use der::Encode;
use log::error;
use sha1::Digest;
use sha1::Sha1;
use x509_cert::Certificate;
use yubikey::piv::SlotId;
use yubikey::{reader::Context, Key, Serial, YubiKey};

pub fn get_pre_enroll_hash_yubikey(serial: &str) -> Result<String> {
    if let Ok(yks) = serial.parse::<u32>() {
        let s = yubikey::Serial(yks);
        if let Ok(mut yk) = get_yubikey(Some(s)) {
            match get_cert_from_slot(&mut yk, SlotId::CardAuthentication) {
                Ok(cert) => {
                    let der_cert = cert.to_der()?;
                    return Ok(buffer_to_hex(&Sha1::digest(der_cert)));
                }
                Err(_e) => {
                    error!("Failed to read certificate to calculate pre-enroll. Consider resetting the device and restarting enrollment.");
                }
            }
        }
    }
    error!(
        "Failed to calculate pre-enroll. Consider resetting the device and restarting enrollment."
    );
    Err(Error::Unrecognized)
}

/// Reads a certificate from the given slot and returns a `Certificate` object
pub fn get_cert_from_slot(yubikey: &mut YubiKey, slot_id: SlotId) -> Result<Certificate> {
    let keys = match Key::list(yubikey) {
        Ok(l) => l,
        Err(e) => {
            error!(
                "Failed to list keys on YubiKey in get_cert_from_slot({slot_id}): {:?}",
                e
            );
            return Err(Error::Unrecognized);
        }
    };
    for key in keys {
        if key.slot() == slot_id {
            if let Some(cert) = Some(key.certificate().clone()) {
                return Ok(cert.cert);
            }
        }
    }
    Err(Error::BadInput)
}

/// Returns a list of available `YubiKey` instances
pub fn list_yubikeys() -> yubikey::Result<Vec<YubiKey>> {
    let mut rv = vec![];
    let mut readers = Context::open()?;
    let reader_iter = readers.iter()?;

    for reader in reader_iter {
        match reader.open() {
            Ok(r) => rv.push(r),
            Err(e) => {
                error!("Failed to open reader: {e:?}. Continuing...")
            }
        };
    }

    if rv.is_empty() {
        error!("No YubiKey detected!");
        Err(yubikey::Error::NotFound)
    } else {
        Ok(rv)
    }
}

/// Returns number of available YubiKeys
pub fn num_yubikeys() -> yubikey::Result<usize> {
    let list = list_yubikeys()?;
    Ok(list.len())
}

/// Returns a `YubiKey` instance corresponding to the indicated serial number
pub fn get_yubikey(serial: Option<Serial>) -> yubikey::Result<YubiKey> {
    match serial {
        Some(serial) => match YubiKey::open_by_serial(serial) {
            Ok(yk) => Ok(yk),
            Err(e) => Err(e),
        },
        None => match YubiKey::open() {
            Ok(yk) => Ok(yk),
            Err(e) => Err(e),
        },
    }
}
