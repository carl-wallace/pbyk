//! User interface for similar set of actions as offered by command line utility

#![cfg(feature = "gui")]
#![allow(non_snake_case)]

use dioxus::prelude::*;
use log::{debug, error, info};

use pbyklib::{
    utils::list_yubikeys::{get_yubikey, list_yubikeys},
    PB_MGMT_KEY,
};

use crate::gui::{app::app, fatal_error::fatal_error, utils::determine_phase};

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
#[cfg(target_os = "windows")]
pub(crate) fn hide_console_window() {
    use std::ptr;
    use winapi::um::wincon::GetConsoleWindow;
    use winapi::um::winuser::{ShowWindow, SW_HIDE};

    let window = unsafe { GetConsoleWindow() };
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
    if window != ptr::null_mut() {
        unsafe {
            ShowWindow(window, SW_HIDE);
        }
    }
}

/// GuiMain is invoked by main() to render the application. It determines whether or not there is a
/// YubiKey available then either displays a view with details of a [fatal error](fatal_error) (in
/// the event no YubiKey is available) or a [form](app) based on the observed state of the YubiKey.
///
/// The following four state items are added to cx by GuiMain. All other state items are created in [app] to comply with
/// the [rule of hooks](https://dioxuslabs.com/docs/0.3/guide/en/interactivity/hooks.html#rules-of-hooks):
/// - s_serial: Serial number of available YubiKey
/// - s_init: Boolean indicator of phase initialization
/// - s_phase: Current Phase associated with available YubiKey
/// - s_reset_req: Boolean indicator of Purebred management key detection
pub(crate) fn GuiMain(cx: Scope<'_>) -> Element<'_> {
    let mut fatal_error_val = String::new();

    let s_serial = use_state(cx, || {
        // TODO: support presence of > 1 yubikey
        let mut available = vec![];
        match list_yubikeys() {
            Ok(readers) => {
                let num_readers = readers.len();
                info!("Number of YubiKeys: {}", num_readers);
                if 1 == num_readers {
                    for reader in readers {
                        info!("Name: {}; Serial: {}", reader.name(), reader.serial());
                        if !available.contains(&reader.serial()) {
                            available.push(reader.serial());
                        }
                    }
                    available[0].to_string()
                } else {
                    fatal_error_val = "More than one YubiKey is available. At present, pbyk does not support the presence of more than one YubiKey when run in GUI mode. Close the app, make sure one YubiKey is available then try again or use pbyk as a command line app.".to_string();
                    String::new()
                }
            }
            Err(e) => {
                error!("Failed to list YubiKeys with: {}", e);
                fatal_error_val = format!("Failed to list YubiKeys with: {}. Close the app, make sure one YubiKey is available then try again.", e);
                String::new()
            }
        }
    });

    // s_init is used to avoid re-interrogating the YubiKey to see what certs are present everytime
    // the UI is redrawn.
    let s_init = use_state(cx, || false);
    let mut phase = Phase::PreEnroll;
    #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
    let mut do_reset = false;
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    let do_reset = false;
    if !s_init.get() && !s_serial.get().is_empty() {
        s_init.setter()(true);
        let serial = s_serial.get();
        let s = yubikey::Serial(serial.parse::<u32>().unwrap());
        let yubikey = match get_yubikey(Some(s)) {
            Ok(yk) => Some(yk),
            Err(e) => {
                error!("Failed to connect to YubiKey with serial {serial} with: {e}");
                fatal_error_val = format!("Failed to connect to YubiKey with serial {serial} with: {}. Close the app, make sure one YubiKey is available then try again.", e);
                None
            }
        };

        if let Some(mut yubikey) = yubikey {
            match yubikey.authenticate(PB_MGMT_KEY.clone()) {
                Ok(_) => {
                    phase = determine_phase(&mut yubikey);
                }
                Err(e) => {
                    let err = "The YubiKey with serial number {serial} is not using the expected management key. Please reset the device then try again.";
                    error!("{err}: {e:?}");

                    #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
                    use native_dialog::{MessageDialog, MessageType};
                    #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
                    match MessageDialog::new()
                        .set_type(MessageType::Info)
                        .set_title("Reset?")
                        .set_text(&format!("The YubiKey with serial number {serial} is not using the expected management key. Would you like to reset the device now?"))
                        .show_confirm()
                    {
                        Ok(answer) => {
                            if answer {
                                do_reset = true;
                            } else {
                                fatal_error_val = err.to_string();
                            }
                        },
                        Err(e) => {
                            error!("Failed to solicit reset answer from user: {e}");
                            fatal_error_val = err.to_string();
                        }
                    }
                }
            }
        }
    }
    let s_phase = use_state(cx, || {
        info!("Setting initial phase to {phase:?}");
        phase
    });

    let s_reset_req = use_state(cx, || {
        debug!("Setting initial reset to {do_reset:?}");
        do_reset
    });

    if !fatal_error_val.is_empty() {
        debug!("Showing fatal_error view");
        fatal_error(cx, &fatal_error_val)
    } else {
        debug!("Showing app view");
        app(cx, s_phase, s_serial, s_reset_req)
    }
}
