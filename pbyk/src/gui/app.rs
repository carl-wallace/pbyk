//! User interface for Purebred workflow

#![cfg(feature = "gui")]
#![allow(non_snake_case)]
// onsubmit, onclick, etc. are causing these warnings
#![allow(unused_qualifications)]

use dioxus::prelude::*;
use dioxus_desktop::use_window;
use dioxus_toast::{Icon, ToastInfo};

use std::time::{SystemTime, UNIX_EPOCH};

use log::{debug, error, info};
use zeroize::Zeroizing;

use pbyklib::{
    ota::{
        data::OtaActionInputs, enroll::enroll, pre_enroll::pre_enroll, recover::recover, ukm::ukm,
        CryptoModule,
    },
    utils::list_yubikeys::get_yubikey,
    get_pb_default,
};

use crate::args::PbYkArgs;
use crate::gui::{
    app_signals::AppSignals,
    burned_otps::*,
    gui_main::{Phase, Phase::*},
    reset::reset,
    ui_signals::UiSignals,
    utils::*,
};

#[cfg(all(target_os = "windows", feature = "vsc"))]
use pbyklib::utils::list_vscs::{get_vsc, get_vsc_id_from_serial};

#[cfg(all(target_os = "windows", feature = "vsc"))]
use crate::determine_vsc_phase;

/// Update various Signal variables based on the phase value
#[allow(clippy::too_many_arguments)]
fn update_phase(
    phase: &Phase,
    mut s_edipi_style: Signal<String>,
    mut s_pre_enroll_otp_style: Signal<String>,
    mut s_ukm_otp_style: Signal<String>,
    mut s_hide_recovery: Signal<String>,
    mut s_button_label: Signal<String>,
    mut s_hide_reset: Signal<String>,
    mut s_enroll_otp_style: Signal<String>,
) {
    match phase {
        PreEnroll => {
            s_edipi_style.set("display:table-row;".to_string());
            s_pre_enroll_otp_style
                .write()
                .push_str("display:table-row;");
            s_ukm_otp_style.set("display:none;".to_string());
            s_hide_recovery.set("none".to_string());
            s_button_label.set("Pre-enroll".to_string());
            s_hide_reset.set("none".to_string());
        }
        Enroll => {
            s_edipi_style.set("display:table-row;".to_string());
            s_pre_enroll_otp_style.set("display:none;".to_string());
            s_enroll_otp_style.set("display:table-row;".to_string());
            s_ukm_otp_style.set("display:none;".to_string());
            s_hide_recovery.set("none".to_string());
            s_button_label.set("Enroll".to_string());
            s_hide_reset.set("none".to_string());
        }
        Ukm => {
            s_edipi_style.set("display:none;".to_string());
            s_pre_enroll_otp_style.set("display:none;".to_string());
            s_enroll_otp_style.set("display:none;".to_string());
            s_ukm_otp_style.set("display:table-row;".to_string());
            s_hide_recovery.set("none".to_string());
            s_button_label.set("User Key Management".to_string());
            s_hide_reset.set("none".to_string());
        }
        UkmOrRecovery => {
            s_edipi_style.set("display:none;".to_string());
            s_pre_enroll_otp_style.set("display:none;".to_string());
            s_enroll_otp_style.set("display:none;".to_string());
            s_ukm_otp_style.set("display:table-row;".to_string());
            s_hide_recovery.set("inline-block".to_string());
            s_button_label.set("User Key Management".to_string());
            s_hide_reset.set("none".to_string());
        }
    }
}

fn set_error(
    msg: &str,
    mut s_error_msg: Signal<String>,
    mut s_cursor: Signal<String>,
    mut s_disabled: Signal<bool>,
) {
    error!("{}", msg);
    s_error_msg.set(msg.to_string());
    s_cursor.set("default".to_string());
    s_disabled.set(false);
}

/// app is the primary component of GUI mode. It draws the forms that comprise the Purebred workflow
/// and drives execution through the workflow.
pub(crate) fn app(
    mut app_signals: AppSignals,
    is_yubikey: bool,
    mut ui_signals: UiSignals,
) -> Element {
    // Macro to display toast with success or error message if ui_signals.s_error_msg or
    // ui_signals.s_success_msg is not empty. Clears the value after display.
    macro_rules! show_message {
        () => {
            if !ui_signals.s_error_msg.read().is_empty() {
                let _id = ui_signals.toast.write().popup(ToastInfo {
                    heading: Some("ERROR".to_string()),
                    context: ui_signals.s_error_msg.to_string(),
                    allow_toast_close: true,
                    position: dioxus_toast::Position::TopLeft,
                    icon: Some(Icon::Error),
                    hide_after: None,
                });
                ui_signals.s_error_msg.set(String::new());
            }
            if !ui_signals.s_success_msg.read().is_empty() {
                let _id = ui_signals.toast.write().popup(ToastInfo {
                    heading: Some("SUCCESS".to_string()),
                    context: ui_signals.s_success_msg.to_string(),
                    allow_toast_close: true,
                    position: dioxus_toast::Position::TopLeft,
                    icon: Some(Icon::Success),
                    hide_after: None,
                });
                ui_signals.s_success_msg.set(String::new());
            }
        };
    }

    // Macro used to check the phase of the currently selected target and to update various UI state
    // variables based on the result. Currently, this is only called when a drop list value is changed.
    macro_rules! check_phase {
        () => {
            if *ui_signals.s_check_phase.read() {
                ui_signals.s_pin.set(String::new());
                let serial = app_signals.s_serial.read().clone();
                match serial.parse::<u32>() {
                    Ok(yks) => {
                        ui_signals.s_pin_style.set("display:table-row;".to_string());
                        debug!("Connecting to newly selected YubiKey: {serial}");
                        let s = yubikey::Serial(yks);
                        let yubikey = match get_yubikey(Some(s)) {
                            Ok(yk) => Some(yk),
                            Err(e) => {
                                error!("Failed to connect to YubiKey with serial {serial} with: {e}");
                                app_signals.s_fatal_error_val.set(format!("Failed to connect to YubiKey with serial {serial} with: {}. Close the app, make sure one YubiKey is available then try again.", e).to_string());
                                None
                            }
                        };

                        if let Some(mut yubikey) = yubikey {
                            debug!("Determining phase of newly selected YubiKey: {serial}");
                            let mgmt_key = get_pb_default(&yubikey);
                            match yubikey.authenticate(&mgmt_key) {
                                Ok(_) => {
                                    let phase = determine_phase(&mut yubikey);
                                    if phase != *app_signals.s_phase.read() {
                                        app_signals.s_phase.set(phase.clone());
                                        update_phase(
                                            &phase,
                                            ui_signals.s_edipi_style,
                                            ui_signals.s_pre_enroll_otp_style,
                                            ui_signals.s_ukm_otp_style,
                                            ui_signals.s_hide_recovery,
                                            ui_signals.s_button_label,
                                            ui_signals.s_hide_reset,
                                            ui_signals.s_enroll_otp_style,
                                        );
                                    }
                                }
                                Err(e) => {
                                    let err = format!("The YubiKey with serial number {serial} is not using the expected management key. Please reset the device then try again.");
                                    error!("{err}: {e:?}");
                                    ui_signals.s_error_msg.set(err.to_string());
                                    app_signals.s_reset_req.set(true);
                                    ui_signals.s_reset_abandoned.set(false);
                                    clear_pin_and_puk!();
                                    show_message!();
                                }
                            }
                        }
                    }
                    Err(_e) => {
                        ui_signals.s_pin_style.set("display:none;".to_string());
                        #[cfg(all(target_os = "windows", feature = "vsc"))]
                        match determine_vsc_phase(&serial) {
                            Ok(phase) => {
                                if phase != *app_signals.s_phase.read() {
                                    app_signals.s_phase.set(phase.clone());
                                    update_phase(
                                        &phase,
                                        ui_signals.s_edipi_style,
                                        ui_signals.s_pre_enroll_otp_style,
                                        ui_signals.s_ukm_otp_style,
                                        ui_signals.s_hide_recovery,
                                        ui_signals.s_button_label,
                                        ui_signals.s_hide_reset,
                                        ui_signals.s_enroll_otp_style,
                                    );
                                }
                            }
                            Err(_e) => {
                                app_signals.s_fatal_error_val.set(
                                    "Could not determine the state of the VSC named {serial}".to_string(),
                                );
                            }
                        };
                    }
                };

                ui_signals.s_check_phase.set(false);
            };
        }
    }

    // Macro to clean PIN and PUK values prior to redirecting to the reset form.
    macro_rules! clear_pin_and_puk {
        () => {
            if !ui_signals.s_pin.read().is_empty() || !ui_signals.s_puk.read().is_empty() {
                ui_signals.s_pin.set(String::new());
                ui_signals.s_puk.set(String::new());
            }
        };
    }

    // Macro to prepare UI for enroll phase
    macro_rules! enter_enroll_phase {
        () => {
            app_signals.s_phase.set(Enroll);
            ui_signals
                .s_pre_enroll_otp_style
                .set("display:none;".to_string());
            ui_signals
                .s_enroll_otp_style
                .set("display:table-row;".to_string());
            ui_signals.s_button_label.set("Enroll".to_string());
        };
    }

    // Macro to prepare UI for UKM phase
    macro_rules! enter_ukm_phase {
        () => {
            app_signals.s_phase.set(Ukm);
            ui_signals
                .s_pre_enroll_otp_style
                .set("display:none;".to_string());
            ui_signals
                .s_enroll_otp_style
                .set("display:none;".to_string());
            ui_signals.s_edipi_style.set("display:none;".to_string());
            ui_signals
                .s_ukm_otp_style
                .set("display:table-row;".to_string());
            ui_signals
                .s_button_label
                .set("User Key Management".to_string());
        };
    }
    // Macro to prepare UI for UKM or Recovery phase
    macro_rules! enter_ukm_or_recovery_phase {
        () => {
            app_signals.s_phase.set(UkmOrRecovery);
            ui_signals.s_hide_recovery.set("inline-block".to_string());
            ui_signals
                .s_pre_enroll_otp_style
                .set("display:none;".to_string());
            ui_signals
                .s_enroll_otp_style
                .set("display:none;".to_string());
            ui_signals.s_edipi_style.set("display:none;".to_string());
            ui_signals
                .s_ukm_otp_style
                .set("display:table-row;".to_string());
            ui_signals
                .s_button_label
                .set("User Key Management".to_string());
        };
    }

    if *app_signals.s_reset_req.read() {
        debug!("Showing reset view");
        reset(is_yubikey, app_signals, ui_signals)
    } else {
        let css = include_str!("../../assets/pbyk.css");

        // prepare rsx block for drop list display
        let serials = app_signals.s_serials.read().clone();
        let serialRsx = serials.iter().map(|s| {
            rsx! { option {
                    value : "{s}",
                    label : "{s}",
                    selected: if *app_signals.s_serial.read().clone() == *s {"true"} else {"false"}
                }
            }
        });

        rsx! {
            dioxus_toast::ToastFrame {
                manager: ui_signals.toast
            }
            style { "{css}" }
            div {
                form {
                    onsubmit: move |ev| {
                        let environment = string_or_default(&ev, "environment", "DEV");
                        info!("Targeting {environment} environment");

                        let args = PbYkArgs{
                            agent_edipi: string_or_none(&ev, "edipi"),
                            serial: None,
                            pre_enroll_otp: None,
                            enroll_otp: None,
                            ukm_otp: None,
                            recover_otp: None,
                            list_yubikeys: false,
                            #[cfg(all(target_os = "windows", feature = "vsc"))]
                            list_vscs: false,
                            reset_device: false,
                            logging_config: None,
                            log_to_console: false,
                            environment: None,
                            portal_status_check: false,
                            scep_check: false,
                            interactive: false
                        };

                        let _ = save_args(&args);
                        let window = use_window();
                        let _ = save_window_size(&window);

                        let PB_BASE_URL = match environment.as_str() {
                            #[cfg(feature = "dev")]
                            "DEV" => "https://pb2.redhoundsoftware.net".to_string(),
                            //"DEV" => "https://carls-mbp-2:8443".to_string(),
                            #[cfg(feature = "om_nipr")]
                            "OM_NIPR" => "https://purebred.c3pki.oandm.disa.mil".to_string(),
                            #[cfg(feature = "om_sipr")]
                            "OM_SIPR" => "https://purebred.snipr.disa.mil".to_string(),
                            #[cfg(feature = "nipr")]
                            "NIPR" => "https://purebred.csd.disa.mil".to_string(),
                            #[cfg(feature = "sipr")]
                            "SIPR" => "https://purebred.csd.disa.smil.mil".to_string(),
                            _ => {
                                let sm = format!("Unrecognized environment: {}.", environment);
                                error!("{}", sm);
                                ui_signals.s_error_msg.set(sm.to_string());
                                String::new()
                            }
                        };

                        let cur_phase = app_signals.s_phase.read().clone();

                        // When in UkmOrRecovery phase, determine if we got here as a consequence of
                        // the user clicking the reset button
                        let recovery_active =  *ui_signals.s_recover.read();

                        let reset_abandoned =  *ui_signals.s_reset_abandoned.read();
                        if !reset_abandoned {
                            ui_signals.s_cursor.set("wait".to_string());
                            ui_signals.s_disabled.set(true);
                        }
                        else {
                            ui_signals.s_reset_abandoned.set(false);
                        }

                        #[cfg(all(target_os = "windows", feature = "vsc"))]
                        let mut serial_str_ota = app_signals.s_serial.read().to_string();
                        #[cfg(not(all(target_os = "windows", feature = "vsc")))]
                        let serial_str_ota = app_signals.s_serial.read().to_string();

                        let serial_u32 = match app_signals.s_serial.read().parse::<u32>() {
                            Ok(serial_u32) => Some(serial_u32),
                            Err(e) => {
                                let sm = format!("Failed to process serial number as YubiKey serial number: {e}.");
                                error!("{}", sm);
                                // error_msg_setter(sm.to_string());
                                None
                            }
                        };

                        async move {
                            show_message!();

                            if reset_abandoned {
                                // if we arrive here due to an aborted reset, just bail out
                                return;
                            }

                            if PB_BASE_URL.is_empty() {
                                // error message is set up in match statement above if environment
                                // is unrecognized and PB_BASE_URL is set to empty
                                ui_signals.s_cursor.set("default".to_string());
                                ui_signals.s_disabled.set(false);
                                show_message!();
                                return;
                            }

                            let app = format!("{}-ui {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

                            let (mut cm, pin) = match serial_u32 {
                                Some(serial_u32) => {
                                    let yks = yubikey::Serial(serial_u32);
                                    debug!("Connecting to target YubiKey: {yks}");
                                    let mut yubikey = match get_yubikey(Some(yks)) {
                                        Ok(yk) => yk,
                                        Err(e) => {
                                            let sm = format!("Could not get the YubiKey with serial number {yks}. Please make sure the device is available then try again. Error: {e}");
                                            set_error(&sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                            show_message!();
                                            return;
                                        }
                                    };

                                    let mgmt_key = get_pb_default(&yubikey);
                                    if yubikey.authenticate(&mgmt_key).is_err() {
                                        let sm = format!("The YubiKey with serial number {} is not using the expected management key. Please reset the device then try again.", yubikey.serial());
                                        set_error(&sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);

                                        // choice dialog is no longer used, show a toast then send the user to the reset form
                                        ui_signals.s_reset_abandoned.set(false);
                                        app_signals.s_reset_req.set(true);
                                        clear_pin_and_puk!();
                                        show_message!();
                                        return;
                                    }

                                    let pin = match string_or_none(&ev, "pin") {
                                        Some(str) => str,
                                        None => {
                                            let sm = format!("No PIN was provided. Please enter the PIN for the YubiKey with serial number {} and try again", yks);
                                            set_error(&sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                            show_message!();
                                            return;
                                        }
                                    };
                                    ui_signals.s_pin_style.set("display:table-row;".to_string());
                                    (CryptoModule::YubiKey(yubikey), pin)
                                }
                                None => {
                                    #[cfg(all(target_os = "windows", feature = "vsc"))]
                                    {
                                        let vsc_serial = parse_reader_from_vsc_display(&serial_str_ota);
                                        let vsc = match get_vsc(&vsc_serial).await {
                                            Ok(vsc) => vsc,
                                            Err(e) => {
                                                let sm = format!("Could not get the VSC with serial number {serial_str_ota}. Please make sure the device is available then try again. Error: {e:?}");
                                                set_error(&sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                                show_message!();
                                                return;
                                            }
                                        };
                                        serial_str_ota = match get_vsc_id_from_serial(&vsc_serial) {
                                            Ok(s) => s,
                                            Err(e) => {
                                                let sm = format!("Could not get the VSC ID for VSC with serial number {serial_str_ota}. Error: {e:?}");
                                                set_error(&sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                                show_message!();
                                                return;
                                            }
                                        };
                                        ui_signals.s_pin_style.set("display:none;".to_string());
                                        (CryptoModule::SmartCard(vsc), String::new())
                                    }
                                    #[cfg(not(all(target_os = "windows", feature = "vsc")))]
                                    {
                                        let sm = "Failed to process serial number as YubiKey serial number.";
                                        set_error(sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                        show_message!();
                                        return;
                                    }
                                }
                            };

                            match cur_phase {
                                PreEnroll => {
                                    info!("Starting Pre-enroll operation...");
                                    let agent_edipi = match string_or_none(&ev, "edipi") {
                                        Some(agent_edipi) => agent_edipi,
                                        None => {
                                            let sm = "No Agent EDIPI was provided. Please enter the EDIPI of the cooperating Purebred Agent and try again";
                                            set_error(sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                            show_message!();
                                            return;
                                        }
                                    };
                                    let pre_enroll_otp = match string_or_none(&ev, "pre_enroll_otp") {
                                        Some(pre_enroll_otp) => {
                                            if !pre_enroll_otp.chars().all(|c| c.is_numeric()) || 8 != pre_enroll_otp.len() {
                                                let sm = "OTP values MUST be exactly 8 characters long and only contain numeric values.";
                                                set_error(sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                                show_message!();
                                                return;
                                            }
                                            pre_enroll_otp
                                        },
                                        None => {
                                            let sm = "No pre-enroll OTP was provided. Please enter a pre-enroll OTP and try again";
                                            set_error(sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                            show_message!();
                                            return;
                                        }
                                    };
                                    if check_otp(&pre_enroll_otp) {
                                        let sm = "OTP values MUST NOT be reused. Please obtain a fresh OTP and try again.";
                                        set_error(sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                        show_message!();
                                        return;
                                    }
                                    else {
                                        add_otp(&pre_enroll_otp);
                                    }

                                    let (tx, rx) = std::sync::mpsc::channel();
                                    let pin_t = if !pin.is_empty() {
                                        Some(Zeroizing::new(pin.clone()))
                                    }
                                    else {
                                        None
                                    };
                                    ui_signals.s_pin.set(pin);
                                    let agent_edipi_t = agent_edipi.clone();
                                    ui_signals.s_edipi.set(agent_edipi.trim().to_string());

                                    #[allow(irrefutable_let_patterns)]
                                    let mgmt_key = if let CryptoModule::YubiKey(yubikey) = &mut cm {
                                        Some(get_pb_default(&yubikey))
                                    } else {
                                        None
                                    };

                                    let _ = tokio::spawn(async move {
                                        match pre_enroll(
                                            &mut cm,
                                            &agent_edipi_t,
                                            &pre_enroll_otp,
                                            &PB_BASE_URL,
                                            pin_t,
                                            mgmt_key
                                        )
                                        .await
                                        {
                                            Ok(hash) => {
                                                info!("Pre-enroll completed successfully: {hash}");
                                                if let Err(e) = tx.send((Some(hash.clone()), None)) {
                                                    error!("Failed to send pre-enroll results to main thread: {e}");
                                                }
                                            }
                                            Err(e) => {
                                                let sm = format!("Pre-enroll failed: {:?}", e);
                                                error!("{sm}");
                                                if let Err(e) = tx.send((None, Some(format!("{sm}. Make sure the Agent EDIPI and Pre-enroll OTP are correct and try again.")))) {
                                                    error!("Failed to send pre-enroll error to main thread: {e}");
                                                }
                                            }
                                        }
                                    }).await;

                                    match rx.recv() {
                                        Ok(result) => {
                                            if let Some(hash) = result.0 {
                                                ui_signals.s_hash.set(hash.clone());
                                                enter_enroll_phase!();
                                            }
                                            else {
                                                ui_signals.s_error_msg.set(result.1.unwrap_or_default());
                                            }
                                        }
                                        Err(e) => {
                                            let sm = format!("Failed to spawn thread for pre-enrollment: {e}").to_string();
                                            error!("{}", sm);
                                            ui_signals.s_error_msg.set(sm.to_string());
                                        }
                                    }
                                    ui_signals.s_cursor.set("default".to_string());
                                    ui_signals.s_disabled.set(false);
                                }
                                Enroll => {
                                    info!("Starting Enroll operation...");
                                    let agent_edipi = match string_or_none(&ev, "edipi") {
                                        Some(agent_edipi) => agent_edipi,
                                        None => {
                                            let sm = "No Agent EDIPI was provided. Please enter the EDIPI of the cooperating Purebred Agent and try again";
                                            set_error(sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                            show_message!();
                                            return;
                                        }
                                    };
                                    let enroll_otp = match string_or_none(&ev, "enroll_otp") {
                                        Some(enroll_otp) => {
                                            if !enroll_otp.chars().all(|c| c.is_numeric()) || 8 != enroll_otp.len() {
                                                let sm = "OTP values MUST be exactly 8 characters long and only contain numeric values.";
                                                set_error(sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                                show_message!();
                                                return;
                                            }
                                            enroll_otp
                                        },
                                        None => {
                                            let sm = "No enroll OTP was provided. Please enter an enroll OTP and try again";
                                            set_error(sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                            show_message!();
                                            return;
                                        }
                                    };
                                    if check_otp(&enroll_otp) {
                                        let sm = "OTP values MUST NOT be reused. Please obtain a fresh OTP and try again.";
                                        set_error(sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                        show_message!();
                                        return;
                                    }
                                    else {
                                        add_otp(&enroll_otp);
                                    }

                                    let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
                                    let pin_t = if !pin.is_empty() {
                                        Some(Zeroizing::new(pin.clone()))
                                    }
                                    else {
                                        None
                                    };
                                    ui_signals.s_pin.set(pin);
                                    let oai = OtaActionInputs::new(
                                        &serial_str_ota,
                                        &enroll_otp,
                                        &PB_BASE_URL.to_string(),
                                        &app,
                                    );
                                    #[allow(irrefutable_let_patterns)]
                                    let mgmt_key = if let CryptoModule::YubiKey(yubikey) = &mut cm {
                                        Some(get_pb_default(&yubikey))
                                    } else {
                                        None
                                    };
                                    let _ = tokio::spawn(async move {
                                        match enroll(
                                            &mut cm,
                                            &agent_edipi,
                                            &oai,
                                            pin_t,
                                            mgmt_key,
                                            &environment
                                        )
                                        .await
                                        {
                                            Ok(_) => {
                                                info!("Enroll completed successfully");
                                                if let Err(e) = tx.send(None) {
                                                    error!("Failed to send enroll results to main thread: {e}");
                                                }
                                            }
                                            Err(e) => {
                                                let sm = format!("Enroll failed: {:?}", e);
                                                error!("{}", sm);
                                                if let Err(e) = tx.send(Some(format!("{sm}. Make sure the Agent EDIPI and Enroll OTP are correct and try again."))) {
                                                    error!("Failed to send enroll error to main thread: {e}");
                                                }
                                            }
                                        }
                                    }).await;

                                    match rx.recv() {
                                        Ok(result) => {
                                            if let Some(error) = result {
                                                ui_signals.s_error_msg.set(error.to_string());
                                            }
                                            else {
                                                enter_ukm_phase!();
                                            }
                                        }
                                        Err(e) => {
                                            let sm = format!("Failed to spawn thread for enrollment: {e}").to_string();
                                            error!("{}", sm);
                                            ui_signals.s_error_msg.set(sm.to_string());
                                        }
                                    }
                                    ui_signals.s_cursor.set("default".to_string());
                                    ui_signals.s_disabled.set(false);
                                }
                                Ukm | UkmOrRecovery => {
                                    info!("Ukm | UkmOrRecovery");
                                    // handle remaining phases (i.e., Ukm or UkmOrRecovery) with recover checkbox as governor
                                    let ukm_otp = match string_or_none(&ev, "ukm_otp") {
                                        Some(ukm_otp) => {
                                            if !ukm_otp.chars().all(|c| c.is_numeric()) || 8 != ukm_otp.len() {
                                                let sm = "OTP values MUST be exactly 8 characters long and only contain numeric values.";
                                                set_error(sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                                show_message!();
                                                return;
                                            }
                                            ukm_otp
                                        },
                                        None => {
                                            let sm = "No UKM OTP was provided. Please enter a UKM OTP and try again";
                                            set_error(sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                            show_message!();
                                            return;
                                        }
                                    };
                                    if check_otp(&ukm_otp) {
                                        let sm = "OTP values MUST NOT be reused. Please obtain a fresh OTP and try again.";
                                        set_error(sm, ui_signals.s_error_msg, ui_signals.s_cursor, ui_signals.s_disabled);
                                        show_message!();
                                        return;
                                    }
                                    else {
                                        add_otp(&ukm_otp);
                                    }

                                    let oai = OtaActionInputs::new(
                                        &serial_str_ota,
                                        &ukm_otp,
                                        &PB_BASE_URL.to_string(),
                                        &app,
                                    );

                                    if recovery_active {
                                        ui_signals.s_recover.set(false);
                                        info!("Starting recover operation...");
                                        let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
                                        let pin_t = if !pin.is_empty() {
                                            Some(Zeroizing::new(pin.clone()))
                                        }
                                        else {
                                            None
                                        };
                                        ui_signals.s_pin.set(pin);
                                        #[allow(irrefutable_let_patterns)]
                                        let mgmt_key = if let CryptoModule::YubiKey(yubikey) = &mut cm {
                                            Some(get_pb_default(&yubikey))
                                        } else {
                                            None
                                        };

                                        let _ = tokio::spawn(async move {
                                            match recover(&mut cm, &oai, pin_t, mgmt_key, &environment).await {
                                                Ok(_) => {
                                                    info!("Recover completed successfully");
                                                    if let Err(e) = tx.send(None) {
                                                        error!("Failed to send recover results to main thread: {e}");
                                                    }
                                                }
                                                Err(e) => {
                                                    let sm = format!("Recover failed: {:?}", e);
                                                    error!("{}", sm);
                                                    if let Err(e) = tx.send(Some(format!("{sm}. Make sure the UKM OTP is correct and try again."))) {
                                                        error!("Failed to send recover results to main thread: {e}");
                                                    }
                                                }
                                            }
                                        }).await;
                                        match rx.recv() {
                                            Ok(result) => {
                                                if let Some(error) = result {
                                                    ui_signals.s_error_msg.set(error.to_string());
                                                }
                                                else {
                                                    ui_signals.s_recover.set(false);
                                                    ui_signals.s_success_msg.set("Recover completed successfully".to_string());
                                                }
                                            }
                                            Err(e) => {
                                                let sm = format!("Failed to spawn thread for recover: {e}").to_string();
                                                error!("{}", sm);
                                                ui_signals.s_error_msg.set(sm.to_string());
                                            }
                                        }
                                    }
                                    else {
                                        info!("Starting UKM operation...");
                                        let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
                                        let pin_t = if !pin.is_empty() {
                                            Some(Zeroizing::new(pin.clone()))
                                        }
                                        else {
                                            None
                                        };
                                        ui_signals.s_pin.set(pin);
                                        #[allow(irrefutable_let_patterns)]
                                        let mgmt_key = if let CryptoModule::YubiKey(yubikey) = &mut cm {
                                            Some(get_pb_default(&yubikey))
                                        } else {
                                            None
                                        };

                                        let _ = tokio::spawn(async move {
                                            match ukm(&mut cm, &oai, pin_t, mgmt_key, &environment).await {
                                                Ok(_) => {
                                                    info!("UKM completed successfully");
                                                    if let Err(e) = tx.send(None) {
                                                        error!("Failed to send UKM results to main thread: {e}");
                                                    }
                                                }
                                                Err(e) => {
                                                    let sm = format!("UKM failed: {:?}", e);
                                                    error!("{}", sm);
                                                    if let Err(e) = tx.send(Some(format!("{sm}. Make sure the UKM OTP is correct and try again."))) {
                                                        error!("Failed to send UKM results to main thread: {e}");
                                                    }
                                                }
                                            }
                                        }).await;
                                        match rx.recv() {
                                            Ok(result) => {
                                                if let Some(error) = result {
                                                    ui_signals.s_error_msg.set(error);
                                                }
                                                else {
                                                    enter_ukm_or_recovery_phase!();
                                                    ui_signals.s_success_msg.set("UKM completed successfully".to_string());
                                                }
                                            }
                                            Err(e) => {
                                                let sm = format!("Failed to spawn thread for UKM: {e}").to_string();
                                                error!("{}", sm);
                                                ui_signals.s_error_msg.set(sm.to_string());
                                            }
                                        }
                                    }
                                    ui_signals.s_cursor.set("default".to_string());
                                    ui_signals.s_disabled.set(false);
                                }
                             }// end match phase
                             show_message!();
                        } // end async move
                    }, // end onsubmit
                    table {
                        class: "{ui_signals.s_cursor}",
                        tbody {
                            tr{
                                style: if *app_signals.s_phase.read() != Enroll { "display:table-row;" } else {"display:none;"},
                                td{div{label {r#for: "multi_serial", "Serial Number"}}}
                                td{select {
                                   disabled: "{ui_signals.s_disabled}",
                                   oninput: move |evt| {
                                       app_signals.s_serial.set(evt.value().to_string());
                                       ui_signals.s_check_phase.set(true);
                                       check_phase!();
                                   },
                                   name: "serials", value: "{app_signals.s_serial}",
                                   {serialRsx}
                                }}
                            }
                            tr{
                                style: if *app_signals.s_phase.read() == Enroll { "display:table-row;" } else {"display:none;"},
                                td{div{label {r#for: "serial", "Serial Number"}}}
                                td{input { r#type: "text", disabled: "{ui_signals.s_disabled}", name: "serial", readonly: true, value: "{app_signals.s_serial}"}}
                            }
                            tr{
                                style: "{ui_signals.s_edipi_style}",
                                td{div{title: "EDIPI of the cooperating Purebred Agent.", label {r#for: "edipi", "Purebred Agent's EDIPI"}}}
                                td{input { disabled: "{ui_signals.s_disabled}", r#type: "text", name: "edipi", placeholder: "Enter Purebred Agent's EDIPI", value: "{ui_signals.s_edipi}", maxlength: "10"}}
                            }
                            tr{
                                style: "{ui_signals.s_pre_enroll_otp_style}",
                                td{div{label {r#for: "pre_enroll_otp", "Pre-enroll OTP"}}}
                                td{input { disabled: "{ui_signals.s_disabled}", r#type: "text", name: "pre_enroll_otp", placeholder: "Enter Pre-Enroll OTP", value: "{ui_signals.s_pre_enroll_otp}", maxlength: "8"}}
                            }
                            tr{
                                style: "{ui_signals.s_enroll_otp_style}",
                                td{div{label {r#for: "hash", "Hash"}}}
                                td{input { r#type: "text", name: "hash", readonly: true, value: "{ui_signals.s_hash}"}}
                            }
                            tr{
                                style: "{ui_signals.s_enroll_otp_style}",
                                td{div{label {r#for: "enroll_otp", "Enroll OTP"}}}
                                td{input { disabled: "{ui_signals.s_disabled}", r#type: "text", name: "enroll_otp", placeholder: "Enter Enroll OTP", value: "{ui_signals.s_enroll_otp}", maxlength: "8"}}
                            }
                            tr{
                                style: "{ui_signals.s_ukm_otp_style}",
                                td{div{label {r#for: "ukm_otp", "UKM OTP"}}}
                                td{input { disabled: "{ui_signals.s_disabled}", r#type: "text", name: "ukm_otp", placeholder: "Enter UKM OTP", value: "{ui_signals.s_ukm_otp}", minlength: "8", maxlength: "8"}}
                            }
                            tr{
                                style: "{ui_signals.s_pin_style}",
                                td{div{label {r#for: "pin", "YubiKey PIN"}}}
                                td{input { disabled: "{ui_signals.s_disabled}", r#type: "password", placeholder: "Enter YubiKey PIN", name: "pin", value: "{ui_signals.s_pin}", maxlength: "8"}}
                            }
                            tr{
                                style: "{ui_signals.s_multi_env_style}",
                                td{div{label {"Environment"}}}
                                table {
                                    class: "nested_table",
                                    tr {
                                        style: "{ui_signals.s_dev_style}",
                                        td{input { disabled: "{ui_signals.s_disabled}", r#type: "radio", id: "dev", name: "environment", value: "DEV", onclick: move |_|  {ui_signals.s_edipi.set( String::new());}, checked: "{ui_signals.s_dev_checked}" } }
                                        td{div{label {r#for: "dev", "Development"}}}
                                    }
                                    tr {
                                        style: "{ui_signals.s_om_nipr_style}",
                                        td{input { disabled: "{ui_signals.s_disabled}", r#type: "radio", id: "om_nipr", name: "environment", value: "OM_NIPR", onclick: move |_|  {ui_signals.s_edipi.set( String::new());}, checked: "{ui_signals.s_om_nipr_checked}" } }
                                        td{div{label {r#for: "om_nipr", "NIPR O&M"}}}
                                    }
                                    tr {
                                        style: "{ui_signals.s_nipr_style}",
                                        td{input { disabled: "{ui_signals.s_disabled}", r#type: "radio", id: "nipr", name: "environment", value: "NIPR", onclick: move |_|  {ui_signals.s_edipi.set( String::new());}, checked: "{ui_signals.s_nipr_checked}" } }
                                        td{div{label {r#for: "nipr", "NIPR"}}}
                                    }
                                    tr {
                                        style: "{ui_signals.s_om_sipr_style}",
                                        td{input { disabled: "{ui_signals.s_disabled}", r#type: "radio", id: "om_sipr", name: "environment", value: "OM_SIPR", onclick: move |_|  {ui_signals.s_edipi.set( String::new());}, checked: "{ui_signals.s_om_sipr_checked}" } }
                                        td{div{label {r#for: "om_sipr", "SIPR O&M"}}}
                                    }
                                    tr {
                                        style: "{ui_signals.s_sipr_style}",
                                        td{input { disabled: "{ui_signals.s_disabled}", r#type: "radio", id: "sipr", name: "environment", value: "SIPR", onclick: move |_|  {ui_signals.s_edipi.set( String::new());}, checked: "{ui_signals.s_sipr_checked}", }}
                                        td{div{label {r#for: "sipr", "SIPR"}}}
                                    }
                                }
                            }
                        }
                    } // end table
                    div {
                        style: "text-align:center;",
                        div {
                            style: "text-align:center;",
                            div{
                                style: "text-align:center; display: inline-block; margin-right:5px;",
                                button { disabled: "{ui_signals.s_disabled}", r#type: "submit", value: "Submit", "{ui_signals.s_button_label}" }
                            }
                            div{
                                style: "text-align:center; display:  {ui_signals.s_hide_recovery}; margin-right:5px;",
                                button { disabled: "{ui_signals.s_disabled}", r#type: "submit", onclick: move |_| ui_signals.s_recover.set(true), value: "Recovery", "Recover Old Decryption Keys" }
                            }
                        }
                        div{
                            style: "text-align:center; display:  {ui_signals.s_hide_reset}; margin-right:5px;",
                            button { disabled: "{ui_signals.s_disabled}", value: "Reset",
                                onclick: move |_| {
                                    ui_signals.s_success_msg.set(String::new());
                                    ui_signals.s_error_msg.set(String::new());

                                    #[cfg(all(target_os = "windows", feature = "vsc", feature = "reset_vsc"))]
                                    let reset_supported = true;
                                    #[cfg(not(all(target_os = "windows", feature = "vsc", feature = "reset_vsc")))]
                                    let reset_supported =  *ui_signals.s_pin_style.read() == "display:table-row;";
                                    if !reset_supported {
                                        ui_signals.s_reset_abandoned.set(true);
                                        ui_signals.s_error_msg.set("VSC reset support is not provided".to_string());
                                        return;
                                    }

                                    ui_signals.s_reset_abandoned.set(false);
                                    app_signals.s_reset_req.set(true);
                                    clear_pin_and_puk!();
                                },
                                "Reset"
                            }
                        }
                    } // end div (with buttons)
                    div {
                        style: "text-align:center",
                        img {
                            src: "data:image/png;base64,  {ui_signals.s_disa_icon}",
                            max_height: "25%",
                            max_width: "25%",
                            onclick: move |_| {
                                let last_count =  *ui_signals.s_click_count.read();
                                let last_start =  *ui_signals.s_click_start.read();
                                let disabled =  *ui_signals.s_disabled.read();
                                match SystemTime::now().duration_since(UNIX_EPOCH) {
                                    Ok(n) => {
                                        #[cfg(all(target_os = "windows", feature = "vsc", feature = "reset_vsc"))]
                                        let reset_supported = true;
                                        #[cfg(not(all(target_os = "windows", feature = "vsc", feature = "reset_vsc")))]
                                        let reset_supported =  *ui_signals.s_pin_style.read() == "display:table-row;";

                                        if !disabled && reset_supported {
                                            let secs = n.as_secs();
                                            if secs - last_start > 5 {
                                                ui_signals.s_click_count.set(1);
                                                ui_signals.s_click_start.set(secs);
                                            } else if last_count >= 4 {
                                                ui_signals.s_hide_reset.set("inline-block".to_string());
                                            } else {
                                                ui_signals.s_click_count.set(last_count+1);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to get UNIX_EPOCH: {e}. Continuing...");
                                    },
                                }
                            }
                        }
                    } // end div (with icon)
                } // end form
            } // end div (with form)
        } // end rsx!
    } // end else
}
