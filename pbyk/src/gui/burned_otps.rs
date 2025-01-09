use std::{
    collections::BTreeMap,
    sync::{LazyLock, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
//use dioxus::prelude::WritableVecExt;
use log::error;

/// BTreeMap that maps OTP values to UNIX epoch values that correspond to observance of the value
static BURNED_OTPS: LazyLock<Mutex<BTreeMap<String, Duration>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub fn add_otp(otp: &str) {
    clean_otps();
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let mut lock = BURNED_OTPS.try_lock();
            match lock {
                Ok(ref mut bog) => {
                    bog.insert(otp.to_string(), duration);
                }
                Err(e) => {
                    error!("Failed to obtain burned OTPs lock in add_otp: {e}");
                }
            }
        }
        Err(e) => {
            error!(
                "Failed to read duration in add_otp: {e}. Continuing without OTP reuse detection."
            )
        }
    }
}

/// Returns true if given OTP is in the BURNED_OTPs map and false otherwise
pub fn check_otp(otp: &str) -> bool {
    let mut lock = BURNED_OTPS.try_lock();
    match lock {
        Ok(ref mut bog) => bog.contains_key(otp),
        Err(e) => {
            error!("Failed to obtain burned OTPs lock in check_otp: {e}");
            false
        }
    }
}

pub fn clean_otps() {
    let cur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let limit = Duration::new(180, 0);
    let mut lock = BURNED_OTPS.try_lock();
    match lock {
        Ok(ref mut bog) => bog.retain(|_, v| cur - *v < limit),
        Err(e) => {
            error!("Failed to obtain burned OTPs lock in check_otp: {e}");
        }
    }
}
