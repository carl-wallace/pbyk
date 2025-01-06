//! Solicits PIN and PUK information in support of resetting the available YubiKey device
// todo: revisit
// onsubmit, onclick, etc. are causing these warnings
#![allow(unused_qualifications)]

use dioxus::prelude::*;
use log::error;
use native_dialog::{MessageDialog, MessageType};

#[cfg(all(target_os = "windows", feature = "vsc", feature = "reset_vsc"))]
use pbyklib::utils::{list_vscs::get_vsc, reset_vsc::reset_vsc};

#[cfg(all(target_os = "windows", feature = "vsc", feature = "reset_vsc"))]
use crate::gui::utils::parse_reader_from_vsc_display;

use pbyklib::{
    utils::{get_yubikey, reset_yubikey},
    PB_MGMT_KEY,
};

use crate::gui::utils::string_or_default;
#[allow(clippy::too_many_arguments)]
pub(crate) fn reset(
    s_serial: Signal<String>,
    mut s_reset_req: Signal<bool>,
    mut s_pin: Signal<String>,
    mut s_puk: Signal<String>,
    mut s_error_msg: Signal<String>,
    mut s_reset_complete: Signal<bool>,
    s_disa_icon: Signal<String>,
    s_pin_style: Signal<String>,
    is_yubikey: bool,
) -> Element {
    // Non-fatal error handling
    let error_msg = s_error_msg.read().clone();
    if !error_msg.is_empty() {
        s_error_msg.set("".to_string());
        MessageDialog::new()
            .set_type(MessageType::Error)
            .set_title("Reset Error")
            .set_text(&error_msg.to_string())
            .show_alert()
            .unwrap_or_default();
    }

    let css = include_str!("../../assets/pbyk.css");
    rsx! {
        style { "{css}" }
        div {
            form {
                onsubmit: move |ev| {
                    let pin1 = string_or_default(&ev, "pin", "");
                    let pin2 = string_or_default(&ev, "pin2", "");
                    let puk1 = string_or_default(&ev, "puk", "");
                    let puk2 = string_or_default(&ev, "puk2", "");

                    let serial = string_or_default(&ev, "serial", "");
                    let serial_u32 = match s_serial.read().parse::<u32>() {
                        Ok(serial_u32) => Some(serial_u32),
                        Err(_e) => {
                            // let sm = format!("ERROR: failed to process YubiKey serial number: {e}.");
                            // error!("{}", sm);
                            // error_msg_setter(sm.to_string());
                            None
                        }
                    };

                    async move {
                        if is_yubikey{
                            if pin1.is_empty() || pin2.is_empty() || puk1.is_empty() || puk2.is_empty() {
                                s_pin.set( "".to_string());
                                s_puk.set( "".to_string());

                                let sm = if pin1.is_empty() || pin2.is_empty() {
                                    "You must enter a new PIN value and confirm that value"
                                }
                                else {
                                    "You must enter a new PUK value and confirm that value"
                                };
                                s_error_msg.set(sm.to_string());
                                return;
                            }

                            if !pin1.is_ascii() || 6 > pin1.len() || 8 < pin1.len() {
                                let sm = "PIN values MUST be between 6 and 8 characters long and only contain ASCII values.";
                                error!("{}", sm);
                                s_error_msg.set(sm.to_string());
                                return;
                            }

                            if 6 > puk1.len() || 8 < puk1.len()  {
                                let sm = "PUK values MUST be between 6 and 8 characters long.";
                                error!("{}", sm);
                                s_error_msg.set(sm.to_string());
                                return;
                            }

                            if pin1 != pin2 || puk1 != puk2 {
                                s_pin.set( "".to_string());
                                s_puk.set( "".to_string());

                                let sm = if pin1 != pin2 {
                                    "PIN values do not match"
                                }
                                else {
                                    "PUK values do not match"
                                };

                                s_error_msg.set(sm.to_string());
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
                                        s_error_msg.set(sm.to_string());
                                        return;
                                    }
                                };

                                if let Err(e) = reset_yubikey(&mut yubikey, &pin1, &puk1, &PB_MGMT_KEY.clone()) {
                                    let sm = format!("Failed to reset YubiKey with serial number {yks}: {e}.");
                                    error!("{}", sm);
                                    s_pin.set( "".to_string());
                                    s_puk.set( "".to_string());
                                    s_error_msg.set(sm.to_string());
                                }
                                else {
                                    s_reset_complete.set(true);
                                    s_reset_req.set(false);
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
                                            s_error_msg.set(sm.to_string());
                                            return;
                                        }
                                    };

                                    if let Err(e) = reset_vsc(&smartcard).await {
                                        let sm = format!("Failed to reset VSC with serial number {r}: {e:?}.");
                                        error!("{}", sm);
                                        s_pin.set("".to_string());
                                        s_puk.set("".to_string());
                                        s_error_msg.set(sm.to_string());
                                    }
                                    else {
                                        s_reset_complete.set(true);
                                        s_reset_req.set(false)
                                    }
                                }

                                #[cfg(not(all(target_os = "windows", feature = "vsc", feature = "reset_vsc")))]
                                {
                                    let sm = format!("ERROR: failed to process YubiKey serial number {serial}");
                                    error!("{}", sm);
                                    s_error_msg.set(sm.to_string());
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
                            td{input { r#type: "text", name: "serial", readonly: true, value: "{s_serial}"}}
                        }
                        tr{
                            style: "{s_pin_style}",
                            th{rowspan: "2", div{label {r#for: "pin", "YubiKey PIN"}}}
                            td{input { r#type: "password", placeholder: "Enter YubiKey PIN (6 to 8 ASCII characters)", name: "pin", value: "{s_pin}", maxlength: "8"}}
                        }
                        tr{
                            style: "{s_pin_style}",
                            td{input { r#type: "password", placeholder: "Re-enter YubiKey PIN", name: "pin2", value: "{s_pin}", maxlength: "8"}}
                        }
                        tr{
                            style: "{s_pin_style}",
                            th{rowspan: "2", div{label {r#for: "puk", "YubiKey PUK"}}}
                            td{input { r#type: "password", placeholder: "Enter YubiKey PUK (6 to 8 ASCII characters)", name: "puk", value: "{s_pin}", maxlength: "8"}}
                        }
                        tr{
                            style: "{s_pin_style}",
                            td{input { r#type: "password", placeholder: "Re-enter YubiKey PUK", name: "puk2", value: "{s_pin}", maxlength: "8"}}
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
                        src: "data:image/png;base64, {s_disa_icon}",
                        max_height: "25%",
                        max_width: "25%",
                    }
                }
            }
        }
    }
}
