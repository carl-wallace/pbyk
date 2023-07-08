//! Supports listing available YubiKeys and selecting a YubiKey by serial number

use log::error;
use yubikey::reader::Context;
use yubikey::{Serial, YubiKey};

/// Returns a list of available YubiKeys
pub fn list_yubikeys() -> yubikey::Result<Vec<YubiKey>> {
    let mut retval = vec![];
    let mut readers = Context::open()?;
    let reader_iter = readers.iter()?;

    for reader in reader_iter {
        retval.push(reader.open()?);
    }

    if retval.is_empty() {
        error!("no YubiKey detected!");
        Err(yubikey::Error::NotFound)
    } else {
        Ok(retval)
    }
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
