//! Solicits PIN and PUK information in support of resetting the available YubiKey device
// onsubmit, onclick, etc. are causing these warnings
#![allow(unused_qualifications)]

use dioxus::prelude::*;
use dioxus_toast::{Icon, ToastInfo};
use log::error;
#[cfg(all(target_os = "windows", feature = "vsc", feature = "reset_vsc"))]
use pbyklib::utils::{list_vscs::get_vsc, reset_vsc::reset_vsc};

use crate::Phase::PreEnroll;
use crate::gui::app_signals::AppSignals;
use crate::gui::ui_signals::UiSignals;
#[cfg(all(target_os = "windows", feature = "vsc", feature = "reset_vsc"))]
use crate::gui::utils::parse_reader_from_vsc_display;
use crate::gui::utils::string_or_default;
use pbyklib::{
    get_pb_default,
    utils::{get_yubikey, reset_yubikey},
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn reset(
    is_yubikey: bool,
    mut app_signals: AppSignals,
    mut ui_signals: UiSignals,
) -> Element {
    // Non-fatal error handling
    macro_rules! show_error_dialog {
        () => {
            if !ui_signals.s_error_msg.read().is_empty() {
                let context = ui_signals.s_error_msg.to_string();
                let icon = if context.contains("management key") {
                    Some(Icon::Info)
                } else {
                    Some(Icon::Error)
                };

                let _id = ui_signals.toast.write().popup(ToastInfo {
                    heading: Some("Reset Error".to_string()),
                    context,
                    allow_toast_close: true,
                    position: dioxus_toast::Position::TopLeft,
                    icon,
                    hide_after: None,
                });
                ui_signals.s_error_msg.set(String::new());
            }
        };
    }

    macro_rules! reset_complete {
        () => {
            if *ui_signals.s_reset_complete.read() {
                ui_signals.s_pin.set(String::new());
                ui_signals.s_reset_complete.set(false);
                ui_signals
                    .s_edipi_style
                    .set("display:table-row;".to_string());
                ui_signals
                    .s_pre_enroll_otp_style
                    .set("display:table-row;".to_string());
                ui_signals.s_ukm_otp_style.set("display:none;".to_string());
                ui_signals.s_hide_recovery.set("none".to_string());
                ui_signals.s_button_label.set("Pre-enroll".to_string());
                ui_signals.s_hide_reset.set("none".to_string());
                app_signals.s_phase.set(PreEnroll);
            }
        };
    }

    // this is sub-ideal but the error display should only occur for the corner case where the
    // YubiKey does not have the expected management key.
    show_error_dialog!();
    let css = include_str!("../../assets/pbyk.css");
    rsx! {
        style { "{css}" }
        dioxus_toast::ToastFrame {
            manager: ui_signals.toast
        }
        div {
            form {
                onsubmit: move |ev| {
                    let pin1 = string_or_default(&ev, "pin", "");
                    let pin2 = string_or_default(&ev, "pin2", "");
                    let puk1 = string_or_default(&ev, "puk", "");
                    let puk2 = string_or_default(&ev, "puk2", "");

                    let serial = string_or_default(&ev, "serial", "");
                    let serial_u32 = app_signals.s_serial.read().parse::<u32>().ok();

                    async move {
                        if is_yubikey{
                            let min_len = *ui_signals.s_min_len.read() as usize;
                            if pin1.is_empty() || pin2.is_empty() || puk1.is_empty() || puk2.is_empty() {
                                ui_signals.s_pin.set( String::new());
                                ui_signals.s_puk.set( String::new());

                                let sm = if pin1.is_empty() || pin2.is_empty() {
                                    "You must enter a new PIN value and confirm that value"
                                }
                                else {
                                    "You must enter a new PUK value and confirm that value"
                                };
                                ui_signals.s_error_msg.set(sm.to_string());
                                show_error_dialog!();
                                return;
                            }

                            if !pin1.is_ascii() || min_len > pin1.len() || 8 < pin1.len() {
                                let sm = if min_len != 8 {
                                    "PIN values MUST be between 6 and 8 characters long and only contain ASCII values."
                                } else {
                                    "PIN values MUST be 8 characters long and only contain ASCII values."
                                };
                                error!("{}", sm);
                                ui_signals.s_error_msg.set(sm.to_string());
                                show_error_dialog!();
                                return;
                            }

                            if min_len > puk1.len() || 8 < puk1.len()  {
                                let sm = if min_len != 8 {
                                    "PUK values MUST be between 6 and 8 characters long."
                                } else {
                                    "PUK values MUST be 8 characters long."
                                };
                                error!("{}", sm);
                                ui_signals.s_error_msg.set(sm.to_string());
                                show_error_dialog!();
                                return;
                            }

                            if pin1 != pin2 || puk1 != puk2 {
                                ui_signals.s_pin.set( String::new());
                                ui_signals.s_puk.set( String::new());

                                let sm = if pin1 != pin2 {
                                    "PIN values do not match"
                                }
                                else {
                                    "PUK values do not match"
                                };

                                ui_signals.s_error_msg.set(sm.to_string());
                                show_error_dialog!();
                                return;
                            }
                        }

                        match serial_u32 {
                            Some(serial_u32) => {
                                let yks = yubikey::Serial(serial_u32);
                                log::debug!("Connecting to YubiKey to reset: {yks}");
                                let mut yubikey = match get_yubikey(Some(yks)) {
                                    Ok(yk) => yk,
                                    Err(e) => {
                                        let sm = format!("Could not get the YubiKey with serial number {yks}. Please make sure the device is available then try again. Error: {e}");
                                        error!("{}", sm);
                                        ui_signals.s_error_msg.set(sm.to_string());
                                        return;
                                    }
                                };

                                let mgmt_key = get_pb_default(&yubikey);
                                if let Err(e) = reset_yubikey(&mut yubikey, &pin1, &puk1, &mgmt_key) {
                                    let sm = format!("Failed to reset YubiKey with serial number {yks}: {e}.");
                                    error!("{}", sm);
                                    ui_signals.s_pin.set( String::new());
                                    ui_signals.s_puk.set( String::new());
                                    ui_signals.s_error_msg.set(sm.to_string());
                                }
                                else {
                                    ui_signals.s_reset_complete.set(true);
                                    app_signals.s_reset_req.set(false);
                                    ui_signals.s_edipi_style.set("display:table-row;".to_string());
                                    ui_signals.s_pre_enroll_otp_style.set("display:table-row;".to_string());
                                    ui_signals.s_ukm_otp_style.set("display:none;".to_string());
                                    ui_signals.s_hide_recovery.set("none".to_string());
                                    ui_signals.s_button_label.set("Pre-enroll".to_string());
                                    ui_signals.s_enroll_otp_style.set("display:none;".to_string());
                                    app_signals.s_phase.set(PreEnroll);

                                    reset_complete!();
                                }
                            },
                            None => {
                                #[cfg(all(target_os = "windows", feature = "vsc", feature = "reset_vsc"))]
                                {
                                    // error message is set up in match statement above if serial number
                                    // conversion fails
                                    let r = parse_reader_from_vsc_display(&serial);
                                    let smartcard = match get_vsc(&r).await {
                                        Ok(yk) => yk,
                                        Err(e) => {
                                            let sm = format!("Could not get the VSC with serial number {r}. Please make sure the device is available then try again. Error: {e:?}");
                                            error!("{}", sm);
                                            ui_signals.s_error_msg.set(sm.to_string());
                                            return;
                                        }
                                    };

                                    if let Err(e) = reset_vsc(&smartcard).await {
                                        let sm = format!("Failed to reset VSC with serial number {r}: {e:?}.");
                                        error!("{}", sm);
                                        ui_signals.s_pin.set(String::new());
                                        ui_signals.s_puk.set(String::new());
                                        ui_signals.s_error_msg.set(sm.to_string());
                                    }
                                    else {
                                        ui_signals.s_reset_complete.set(true);
                                        app_signals.s_reset_req.set(false);
                                        reset_complete!();
                                    }
                                }

                                #[cfg(not(all(target_os = "windows", feature = "vsc", feature = "reset_vsc")))]
                                {
                                    let sm = format!("ERROR: failed to process YubiKey serial number {serial}");
                                    error!("{}", sm);
                                    ui_signals.s_error_msg.set(sm.to_string());
                                    show_error_dialog!();
                                }
                            }
                        };
                    }
                },
                table {
                    tbody {
                        tr{
                            style: "display:table-row;",
                            td{div{label {r#for: "serial", "Serial Number"}}}
                            td{input { r#type: "text", name: "serial", readonly: true, value: "{app_signals.s_serial}"}}
                        }
                        tr{
                            style: "{ui_signals.s_pin_style}",
                            th{rowspan: "2", div{label {r#for: "pin", "YubiKey PIN"}}}
                            td{input { r#type: "password", placeholder: "{ui_signals.s_pin_prompt_hint}", name: "pin", value: "{ui_signals.s_pin}", maxlength: "8"}}
                        }
                        tr{
                            style: "{ui_signals.s_pin_style}",
                            td{input { r#type: "password", placeholder: "Re-enter YubiKey PIN", name: "pin2", value: "{ui_signals.s_pin}", maxlength: "8"}}
                        }
                        tr{
                            style: "{ui_signals.s_pin_style}",
                            th{rowspan: "2", div{label {r#for: "puk", "YubiKey PUK"}}}
                            td{input { r#type: "password", placeholder: "{ui_signals.s_puk_prompt_hint}", name: "puk", value: "{ui_signals.s_pin}", maxlength: "8"}}
                        }
                        tr{
                            style: "{ui_signals.s_pin_style}",
                            td{input { r#type: "password", placeholder: "Re-enter YubiKey PUK", name: "puk2", value: "{ui_signals.s_pin}", maxlength: "8"}}
                        }
                    }
                }
                div{
                    style: "text-align:center",
                    button { r#type: "submit", value: "Submit", "Reset" }
                }
                div {
                    style: "text-align:center",
                    img {
                        src: "data:image/png;base64, {ui_signals.s_disa_icon}",
                        max_height: "25%",
                        max_width: "25%",
                    }
                }
            }
        }
    }
}
