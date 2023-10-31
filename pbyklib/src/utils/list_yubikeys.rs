//! Supports listing available YubiKeys and selecting a YubiKey by serial number

use log::error;
use yubikey::{reader::Context, Serial, YubiKey};

/// Returns a list of available `YubiKey` instances
pub fn list_yubikeys() -> yubikey::Result<Vec<YubiKey>> {
    let mut retval = vec![];
    let mut readers = Context::open()?;
    let reader_iter = readers.iter()?;

    for reader in reader_iter {
        match reader.open() {
            Ok(r) => retval.push(r),
            Err(e) => {
                error!("Failed to open reader: {e:?}. Continuing...")
            }
        };
    }

    if retval.is_empty() {
        error!("No YubiKey detected!");
        Err(yubikey::Error::NotFound)
    } else {
        Ok(retval)
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
