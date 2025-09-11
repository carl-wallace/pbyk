//! Utility functions supporting GUI functionality

#![cfg(feature = "gui")]
#![allow(non_snake_case)]

use std::{fs, fs::File};

use dioxus::prelude::*;
use dioxus_desktop::DesktopContext;

use home::home_dir;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use yubikey::{YubiKey, piv::SlotId};

use certval::{PDVCertificate, PkiEnvironment, is_self_signed};
use pbyklib::{Error, Result, utils::get_cert_from_slot, utils::state::create_app_home};

use crate::{args::PbYkArgs, gui::gui_main::Phase};

/// Read saved arguments from (home dir)/.pbyk/pbyk.cfg, which is a JSON-formatted representation of
/// a PbYkArgs structure.
pub(crate) fn read_saved_args_or_default() -> PbYkArgs {
    if let Some(home_dir) = home_dir() {
        let app_cfg = home_dir.join(".pbyk").join("pbyk.cfg");
        if let Ok(f) = File::open(app_cfg) {
            match serde_json::from_reader(&f) {
                Ok(saved_args) => return saved_args,
                Err(e) => {
                    error!("Failed to parse saved pbyk configuration: {:?}", e);
                }
            };
        }
    }
    PbYkArgs::default()
}

// TODO: fire this from app close event handler if possible
/// Save a JSON-formatted representation of a PbYkArgs structure to \<home dir\>/.pbyk/pbyk.cfg.
pub(crate) fn save_args(args: &PbYkArgs) -> Result<()> {
    let app_home = create_app_home()?;
    let app_cfg = app_home.join("pbyk.cfg");
    if let Ok(json_args) = serde_json::to_string(&args) {
        return if let Err(e) = fs::write(app_cfg, json_args) {
            error!("Unable to write args to file: {e}");
            Err(Error::Unrecognized)
        } else {
            Ok(())
        };
    }
    Err(Error::Unrecognized)
}

/// Default window width
static PBYK_DEFAULT_WIDTH: u32 = 625;
/// Default window height
static PBYK_DEFAULT_HEIGHT: u32 = 500;

/// Structure to serialize and deserialize window size information
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SavedWindowsSize {
    pub width: u32,
    pub height: u32,
}
impl Default for SavedWindowsSize {
    fn default() -> Self {
        SavedWindowsSize {
            width: PBYK_DEFAULT_WIDTH,
            height: PBYK_DEFAULT_HEIGHT,
        }
    }
}

/// Saves the current window size to a file named sws.json in the .pbyk folder in the user's home directory.
pub(crate) fn save_window_size(window: &DesktopContext) -> Result<()> {
    let scale_factor = if let Some(m) = window.current_monitor() {
        m.scale_factor()
    } else {
        1.0
    };

    let inner_size = window.window.inner_size().to_logical(scale_factor);
    let sws = SavedWindowsSize {
        width: inner_size.width,
        height: inner_size.height,
    };
    debug!("save_window_size: {sws:?}");

    let app_home = create_app_home()?;
    let app_cfg = app_home.join("sws.json");
    if let Ok(json_args) = serde_json::to_string(&sws) {
        return if let Err(e) = fs::write(app_cfg, json_args) {
            error!("Unable to write SavedWindowSize to file: {e}");
            Err(Error::Unrecognized)
        } else {
            Ok(())
        };
    }
    Err(Error::Unrecognized)
}

/// Reads saved window size from a file named sws.json in the .pbyk folder in the user's home directory. If the file
/// does not exist or if file contents seem irregular, default [width](PBYK_DEFAULT_WIDTH) and [height](PBYK_DEFAULT_HEIGHT) values are used.
pub(crate) fn read_saved_window_size() -> SavedWindowsSize {
    if let Some(home_dir) = home_dir() {
        let app_cfg = home_dir.join(".pbyk").join("sws.json");
        if let Ok(f) = File::open(app_cfg) {
            match serde_json::from_reader::<&File, SavedWindowsSize>(&f) {
                Ok(saved_args) => {
                    // crude sanity check
                    if PBYK_DEFAULT_WIDTH * 4 > saved_args.width
                        && PBYK_DEFAULT_HEIGHT * 4 > saved_args.height
                    {
                        debug!("read_saved_window_size: {saved_args:?}");
                        return saved_args;
                    }
                }
                Err(e) => {
                    error!("Failed to parse saved pbyk configuration: {:?}", e);
                }
            };
        }
    }
    debug!("read_saved_window_size: using default");
    SavedWindowsSize::default()
}

/// Searches the map for the given key. If an entry is found, the value is returned. Else, None is returned.
pub(crate) fn string_or_none(ev: &Event<FormData>, key: &str) -> Option<String> {
    if let Some(v) = ev.values().get(key)
        && !v[0].is_empty()
    {
        Some(v[0].clone())
    } else {
        None
    }
}

/// Searches the map for the given key. If an entry is found, the value is returned. Else, the provided default value is returned as a String.
pub(crate) fn string_or_default(ev: &Event<FormData>, key: &str, default: &str) -> String {
    if let Some(v) = ev.values().get(key)
        && !v[0].is_empty()
    {
        v[0].clone()
    } else {
        default.to_string()
    }
}

/// Returns PreEnroll if no certificate can be read from CardAuthentication slot or if
/// certificate read from CardAuthentication slot is self-signed.
///
/// Returns Ukm when certificate in CardAuthentication slot is not-self-signed and there is no
/// certificate in Authentication or Signature slot.
///
/// Returns UkmOrRecovery when certificate in CardAuthentication slot is not-self-signed and there is
/// a certificate in Authentication or Signature slot.
pub(crate) fn determine_phase(yubikey: &mut YubiKey) -> Phase {
    match get_cert_from_slot(yubikey, SlotId::CardAuthentication) {
        Ok(c) => {
            let mut pe = PkiEnvironment::default();
            pe.populate_5280_pki_environment();
            let pdv = match PDVCertificate::try_from(c) {
                Ok(pdv) => pdv,
                Err(e) => {
                    error!(
                        "Failed to parse certificate read from CardAuthentication slot with: {e:?}. Continuing with phase set to PreEnroll."
                    );
                    return Phase::PreEnroll;
                }
            };
            if !is_self_signed(&pe, &pdv) {
                let r1 = get_cert_from_slot(yubikey, SlotId::Authentication);
                let r2 = get_cert_from_slot(yubikey, SlotId::Signature);
                if r1.is_ok() || r2.is_ok() {
                    Phase::UkmOrRecovery
                } else {
                    Phase::Ukm
                }
            } else {
                Phase::Enroll
            }
        }
        Err(e) => {
            debug!(
                "Did not read certificate from CardAuthentication slot with: {e:?}. Continuing..."
            );
            Phase::PreEnroll
        }
    }
}

/// Returns an environment value to use to pre-select a radio button when no option has already been chosen.
#[allow(clippy::needless_return)]
pub(crate) fn get_default_env() -> &'static str {
    cfg_if! {
        if #[cfg(feature = "dev")] {
            return "DEV";
        }
        else if #[cfg(feature = "om_nipr")] {
            return "OM_NIPR";
        }
        else if #[cfg(feature = "om_sipr")] {
            return "OM_SIPR";
        }
        else if #[cfg(feature = "nipr")] {
            return "NIPR";
        }
        else if #[cfg(feature = "sipr")] {
            return "SIPR";
        }
        else {
            "DEV"
        }
    }
}

/// Returns UseState\<bool\> instances corresponding to each of five possible radio buttons used to
/// select an environment. Give are always returned here, though as few as zero may be displayed
/// depending on the features elected at build time.
///
/// The returned tuple can be used to assign the following variables used in app rsx definitions:
///     - s_dev_checked,
///     - s_om_nipr_checked,
///     - s_om_sipr_checked,
///     - s_nipr_checked,
///     - s_sipr_checked
pub(crate) fn get_default_env_radio_selections() -> (bool, bool, bool, bool, bool) {
    match get_default_env() {
        "DEV" => (true, false, false, false, false),
        "OM_NIPR" => (false, true, false, false, false),
        "OM_SIPR" => (false, false, true, false, false),
        "NIPR" => (false, false, false, true, false),
        "SIPR" => (false, false, false, false, true),
        _ => (false, false, false, false, false),
    }
}

#[cfg(all(target_os = "windows", feature = "vsc"))]
pub fn parse_reader_from_vsc_display(serial: &str) -> String {
    let parts = serial.split(" - ").collect::<Vec<&str>>();
    match parts.first() {
        Some(s) => s.to_string(),
        None => "".to_string(),
    }
}
