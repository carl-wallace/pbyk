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
    Error, Result, get_pb_default
};

#[cfg(all(target_os = "windows", feature = "vsc"))]
use crate::gui::utils::parse_reader_from_vsc_display;

use crate::gui::{
    app::app, app_signals::AppSignals, fatal_error::fatal_error, ui_signals::UiSignals,
    utils::determine_phase,
};

/// Used to establish what UI elements should be displayed during each protocol phase
///
/// The UI elements for each state are as shown below:
///
///     Pre-enroll
///         - serial, agent_edipi, pre_enroll_otp, submit, PIN
///     Enroll
///         - serial, agent_edipi, enroll_otp, submit, PIN
///     UKM
///         - serial, ukm_otp, submit, PIN
///     UKM or recover
///         - serial, ukm_otp, recover checkbox, submit, PIN
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
    let mut startup_fatal_error_val = String::new();

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
            startup_fatal_error_val = "Failed to list YubiKeys or VSCs. Close the app, make sure at least one YubiKey is available then try again.".to_string();
            String::new()
        }
    });

    let str_serial = s_serial.read().clone();

    // s_init is used to avoid re-interrogating the YubiKey to see what certs are present everytime
    // the UI is redrawn. It is only used in this function.
    let mut s_init = use_signal(|| false);
    let mut phase = Phase::PreEnroll;
    let mut do_reset = false;
    let mut s_is_yubikey = use_signal(|| false);
    let mut error_msg = None;
    if !*s_init.read() && !str_serial.is_empty() {
        debug!("Getting default device serial number inside main");
        if let Ok(yubikey_serial) = str_serial.parse::<u32>() {
            let s = yubikey::Serial(yubikey_serial);
            let yubikey = match get_yubikey(Some(s)) {
                Ok(yk) => Some(yk),
                Err(e) => {
                    error!("Failed to connect to YubiKey with serial {str_serial} with: {e}");
                    startup_fatal_error_val = format!("Failed to connect to YubiKey with serial {str_serial} with: {}. Close the app, make sure one YubiKey is available then try again.", e);
                    None
                }
            };

            s_is_yubikey.set(true);

            if let Some(mut yubikey) = yubikey {
                debug!("Determining YubiKey phase inside main");
                let mgmt_key = get_pb_default(&yubikey);
                match yubikey.authenticate(&mgmt_key) {
                    Ok(_) => {
                        phase = determine_phase(&mut yubikey);
                    }
                    Err(e) => {
                        let err = format!("The YubiKey with serial number {str_serial} is not using the expected management key. Please reset the device then try again.");
                        error!("{err}: {e:?}");
                        do_reset = true;
                        error_msg = Some(err);
                    }
                }
            }
        } else {
            #[cfg(all(target_os = "windows", feature = "vsc"))]
            {
                match determine_vsc_phase(&str_serial) {
                    Ok(p) => phase = p,
                    Err(e) => {
                        error!("Failed to connect to YubiKey with serial {str_serial} with: {e:?}");
                        startup_fatal_error_val = format!("Failed to connect to YubiKey with serial {str_serial} with: {:?}. Close the app, make sure one YubiKey is available then try again.", e);
                    }
                }
            }
        }
    }

    let s_startup_fatal_error_val = use_signal(|| startup_fatal_error_val);

    use_effect(move || {
        s_init.set(true);
    });

    if !s_startup_fatal_error_val.read().is_empty() {
        debug!("Showing fatal_error view");
        fatal_error(&s_startup_fatal_error_val.read())
    } else {
        debug!("Showing app view");
        let app_signals = AppSignals {
            s_phase: use_signal(|| {
                info!("Setting initial phase to {phase:?}");
                phase
            }),
            s_serial: use_signal(|| str_serial),
            s_reset_req: use_signal(|| {
                debug!("Setting initial reset to {do_reset:?}");
                do_reset
            }),
            s_serials: use_signal(|| serials),
            s_fatal_error_val: use_signal(String::new),
        };
        let ui_signals = UiSignals::init(&app_signals, *s_is_yubikey.read(), error_msg);
        app(app_signals, *s_is_yubikey.read(), ui_signals)
    }
}
