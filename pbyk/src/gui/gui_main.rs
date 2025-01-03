//! User interface for similar set of actions as offered by command line utility

#![cfg(feature = "gui")]
#![allow(non_snake_case)]

use dioxus::prelude::*;
use log::{debug, error, info};

#[cfg(all(target_os = "windows", feature = "vsc"))]
use pbyklib::utils::list_vscs::{
    get_device_cred, get_vsc_id_and_uuid_from_serial, get_vsc_id_from_serial, list_vscs,
};

use pbyklib::{
    utils::list_yubikeys::{get_yubikey, list_yubikeys},
    Error, Result, PB_MGMT_KEY,
};

use crate::gui::{app::app, fatal_error::fatal_error, utils::determine_phase};

#[cfg(all(target_os = "windows", feature = "vsc"))]
use crate::gui::utils::parse_reader_from_vsc_display;

/// Used to establish what UI elements should be displayed during each protocol phase
///
/// The UI elements for each state are as shown below:
///
/// Pre-enroll
///  - serial, agent_edipi, pre_enroll_otp, submit, PIN
/// Enroll
///  - serial, agent_edipi, enroll_otp, submit, PIN
/// UKM
///  - serial, ukm_otp, submit, PIN
/// UKM or recover
/// - serial, ukm_otp, recover checkbox, submit, PIN
#[derive(Clone, PartialEq, Debug)]
pub(crate) enum Phase {
    PreEnroll,
    Enroll,
    Ukm,
    UkmOrRecovery,
}

/// hide_console_window hides the console window from which the app is launched on Windows. This
/// was poached from: <https://stackoverflow.com/questions/29763647/how-to-make-a-program-that-does-not-display-the-console-window>.
#[cfg(all(target_os = "windows", feature = "vsc"))]
pub(crate) fn hide_console_window() {
    use winapi::um::wincon::GetConsoleWindow;
    use winapi::um::winuser::{ShowWindow, SW_HIDE};

    let window = unsafe { GetConsoleWindow() };
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
    if !window.is_null() {
        unsafe {
            ShowWindow(window, SW_HIDE);
        }
    }
}

async fn get_serials(serials: &mut Vec<String>) -> Result<String> {
    match list_yubikeys() {
        Ok(readers) => {
            let num_readers = readers.len();
            info!("Number of YubiKeys: {}", num_readers);
            for reader in readers {
                info!("Name: {}; Serial: {}", reader.name(), reader.serial());
                let serial_str = reader.serial().to_string();
                if !serials.contains(&serial_str) {
                    serials.push(serial_str);
                }
            }
        }
        Err(e) => {
            error!("Failed to find any YubiKeys with: {e:?}");
        }
    }
    #[cfg(all(target_os = "windows", feature = "vsc"))]
    match list_vscs().await {
        Ok(smart_cards) => {
            let num_smart_cards = smart_cards.len();
            info!("Number of VSCs: {}", num_smart_cards);
            for smartcard in smart_cards {
                match smartcard.Reader() {
                    Ok(reader) => match reader.Name() {
                        Ok(name) => {
                            info!("Name: {name}");
                            let name_str = name.to_string();
                            match get_vsc_id_from_serial(&name_str) {
                                Ok(vsc_id) => {
                                    let display = format!("{} - {}", name_str, vsc_id);
                                    if !serials.contains(&display) {
                                        serials.push(display);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to determine VSC ID for {name_str}: {e:?}. Continuing...");
                                }
                            };
                        }
                        Err(e) => {
                            error!("Failed to read smartcard reader name with: {e:?}");
                        }
                    },
                    Err(e) => {
                        error!("Failed to read smartcard reader with: {e:?}");
                    }
                }
            }
        }
        Err(e) => {
            error!("Failed to find any VSCs with: {e:?}");
        }
    }

    if !serials.is_empty() {
        Ok(serials[0].clone())
    } else {
        Err(Error::NotFound)
    }
}

#[cfg(all(target_os = "windows", feature = "vsc"))]
pub(crate) fn determine_vsc_phase(serial: &str) -> Result<Phase> {
    let vsc_serial = parse_reader_from_vsc_display(serial);
    match get_vsc_id_and_uuid_from_serial(&vsc_serial) {
        Ok((vsc_id, uuid)) => {
            #[allow(clippy::redundant_pattern_matching)]
            if let Ok(_cred) = get_device_cred(&vsc_id, false) {
                // todo need work to determine if Ukm or UkmOrRecovery (remove clippy allow if this is not to be done)
                Ok(Phase::UkmOrRecovery)
            } else if let Ok(_) = get_device_cred(&uuid, true) {
                Ok(Phase::Enroll)
            } else {
                Ok(Phase::PreEnroll)
            }
        }
        Err(e) => Err(e),
    }
}

/// GuiMain is invoked by main() to render the application. It determines whether there is a
/// YubiKey available then either displays a view with details of a [fatal error](fatal_error) (in
/// the event no YubiKey is available) or a [form](app) based on the observed state of the YubiKey.
///
/// The following four state items are added to cx by GuiMain. All other state items are created in [app] to comply with
/// the [rule of hooks](https://dioxuslabs.com/docs/0.3/guide/en/interactivity/hooks.html#rules-of-hooks):
/// - s_serial: Serial number of available YubiKey
/// - s_init: Boolean indicator of phase initialization
/// - s_phase: Current Phase associated with available YubiKey
/// - s_reset_req: Boolean indicator of Purebred management key detection
pub(crate) fn GuiMain() -> Element {
    let mut fatal_error_val = String::new();

    let mut serials = vec![];
    let s_serial = use_signal(|| {
        futures::executor::block_on(async {
            if let Err(e) = get_serials(&mut serials).await {
                error!("Failed to run async function to list serial numbers with {e:?}");
            }
        });

        if !serials.is_empty() {
            serials[0].clone()
        } else {
            error!("Failed to list YubiKeys");
            fatal_error_val = "Failed to list YubiKeys or VSCs. Close the app, make sure at least one YubiKey is available then try again.".to_string();
            String::new()
        }
        // "15995762".to_string()
    });

    // s_init is used to avoid re-interrogating the YubiKey to see what certs are present everytime
    // the UI is redrawn.
    let mut s_init = use_signal(|| false);
    let mut phase = Phase::PreEnroll;
    #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
    let mut do_reset = false;
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    let do_reset = false;
    let mut is_yubikey = false;
    if !*s_init.read() && !s_serial.read().is_empty() {
        debug!("Getting default device serial number inside main");
        *s_init.write() = true;
        let serial = s_serial.read();
        if let Ok(yubikey_serial) = serial.parse::<u32>() {
            let s = yubikey::Serial(yubikey_serial);
            let yubikey = match get_yubikey(Some(s)) {
                Ok(yk) => Some(yk),
                Err(e) => {
                    error!("Failed to connect to YubiKey with serial {serial} with: {e}");
                    fatal_error_val = format!("Failed to connect to YubiKey with serial {serial} with: {}. Close the app, make sure one YubiKey is available then try again.", e);
                    None
                }
            };

            is_yubikey = true;

            if let Some(mut yubikey) = yubikey {
                debug!("Determining YubiKey phase inside main");
                match yubikey.authenticate(PB_MGMT_KEY.clone()) {
                    Ok(_) => {
                        phase = determine_phase(&mut yubikey);
                    }
                    Err(e) => {
                        let err = format!("The YubiKey with serial number {serial} is not using the expected management key. Please reset the device then try again.");
                        error!("{err}: {e:?}");

                        #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
                        {
                            use native_dialog::{MessageDialog, MessageType};
                            let msg = format!("The YubiKey with serial number {serial} is not using the expected management key. Would you like to reset the device now?");
                            match MessageDialog::new()
                                .set_type(MessageType::Info)
                                .set_title("Reset?")
                                .set_text(&msg)
                                .show_confirm()
                            {
                                Ok(answer) => {
                                    if answer {
                                        do_reset = true;
                                    } else {
                                        fatal_error_val = err.to_string();
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to solicit reset answer from user: {e}");
                                    fatal_error_val = err.to_string();
                                }
                            }
                        }
                        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
                        {
                            fatal_error_val = err.to_string();
                        }
                    }
                }
            }
        } else {
            #[cfg(all(target_os = "windows", feature = "vsc"))]
            {
                match determine_vsc_phase(serial) {
                    Ok(p) => phase = p,
                    Err(e) => {
                        error!("Failed to connect to YubiKey with serial {serial} with: {e:?}");
                        fatal_error_val = format!("Failed to connect to YubiKey with serial {serial} with: {:?}. Close the app, make sure one YubiKey is available then try again.", e);
                    }
                }
            }
        }
    }
    let s_serials = use_signal(|| serials);
    let s_phase = use_signal(|| {
        info!("Setting initial phase to {phase:?}");
        phase
    });

    let s_reset_req = use_signal(|| {
        debug!("Setting initial reset to {do_reset:?}");
        do_reset
    });

    let s_fatal_error_val = use_signal(|| fatal_error_val);

    if !s_fatal_error_val.read().is_empty() {
        debug!("Showing fatal_error view");
        fatal_error(&s_fatal_error_val.read())
    } else {
        debug!("Showing app view");
        app(
            s_phase,
            s_serial,
            s_reset_req,
            s_serials,
            s_fatal_error_val,
            is_yubikey,
        )
    }
}
