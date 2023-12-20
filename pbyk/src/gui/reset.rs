//! Solicits PIN and PUK information in support of resetting the available YubiKey device

use dioxus::prelude::*;
use log::error;
use native_dialog::{MessageDialog, MessageType};

use pbyklib::{
    utils::{get_yubikey, reset_yubikey},
    PB_MGMT_KEY,
};

use crate::gui::utils::string_or_default;
#[allow(clippy::too_many_arguments)]
pub(crate) fn reset<'a>(
    cx: Scope<'a>,
    s_serial: &'a UseState<String>,
    s_reset_req: &'a UseState<bool>,
    s_pin: &'a UseState<String>,
    s_puk: &'a UseState<String>,
    s_error_msg: &'a UseState<String>,
    s_reset_complete: &'a UseState<bool>,
    s_disa_icon: &'a UseState<String>,
) -> Element<'a> {
    // Non-fatal error handling
    let error_msg_setter = s_error_msg.setter();
    if !s_error_msg.is_empty() {
        let error_msg = s_error_msg.get().clone();
        error_msg_setter(String::new());
        MessageDialog::new()
            .set_type(MessageType::Error)
            .set_title("Reset Error")
            .set_text(&error_msg.to_string())
            .show_alert()
            .unwrap_or_default();
    }

    cx.render(rsx! {
        style { include_str!("../../assets/pbyk.css") }
        div {
            form {
                onsubmit: move |ev| {
                    let error_msg_setter = s_error_msg.setter();
                    let reset_setter = s_reset_req.setter();
                    let pin_setter = s_pin.setter();
                    let puk_setter = s_puk.setter();
                    let reset_complete_setter = s_reset_complete.setter();

                    let pin1 = string_or_default(&ev, "pin", "");
                    let pin2 = string_or_default(&ev, "pin2", "");
                    let puk1 = string_or_default(&ev, "puk", "");
                    let puk2 = string_or_default(&ev, "puk2", "");

                    let serial_u32 = match s_serial.get().parse::<u32>() {
                        Ok(serial_u32) => Some(serial_u32),
                        Err(e) => {
                            let sm = format!("ERROR: failed to process YubiKey serial number: {e}.");
                            error!("{}", sm);
                            error_msg_setter(sm.to_string());
                            None
                        }
                    };

                    async move {
                        if pin1.is_empty() || pin2.is_empty() || puk1.is_empty() || puk2.is_empty() {
                            pin_setter("".to_string());
                            puk_setter("".to_string());

                            let sm = if pin1.is_empty() || pin2.is_empty() {
                                "You must enter a new PIN value and confirm that value"
                            }
                            else {
                                "You must enter a new PUK value and confirm that value"
                            };
                            error_msg_setter(sm.to_string());
                            return;
                        }

                        if !pin1.chars().all(|c| c.is_ascii()) || 6 > pin1.len() || 8 < pin1.len() {
                            let sm = "PIN values MUST be between 6 and 8 characters long and only contain ASCII values.";
                            error!("{}", sm);
                            error_msg_setter(sm.to_string());
                            return;
                        }

                        if 6 > puk1.len() || 8 < puk1.len()  {
                            let sm = "PUK values MUST be between 6 and 8 characters long.";
                            error!("{}", sm);
                            error_msg_setter(sm.to_string());
                            return;
                        }

                        if pin1 != pin2 || puk1 != puk2 {
                            pin_setter("".to_string());
                            puk_setter("".to_string());

                            let sm = if pin1 != pin2 {
                                "PIN values do not match"
                            }
                            else {
                                "PUK values do not match"
                            };

                            error_msg_setter(sm.to_string());
                            return;
                        }

                        let yks = match serial_u32 {
                            Some(serial_u32) => yubikey::Serial(serial_u32),
                            None => {
                                // error message is set up in match statement above if serial number
                                // conversion fails
                                return;
                            }
                        };

                        log::debug!("Connecting to YubiKey to reset: {yks}");
                        let mut yubikey = match get_yubikey(Some(yks)) {
                            Ok(yk) => yk,
                            Err(e) => {
                                let sm = format!("Could not get the YubiKey with serial number {yks}. Please make sure the device is available then try again. Error: {e}");
                                error!("{}", sm);
                                error_msg_setter(sm.to_string());
                                return;
                            }
                        };

                        if let Err(e) = reset_yubikey(&mut yubikey, &pin1, &puk1, &PB_MGMT_KEY.clone()) {
                            let sm = format!("Failed to reset YubiKey with serial number {yks}: {e}.");
                            error!("{}", sm);
                            pin_setter("".to_string());
                            puk_setter("".to_string());
                            error_msg_setter(sm.to_string());
                        }
                        else {
                            reset_complete_setter(true);
                            reset_setter(false);
                        }
                    }
                },
                table {
                    tbody {
                        tr{
                            style: "display:table-row;",
                            td{div{label {r#for: "serial", "YubiKey Serial Number"}}}
                            td{input { r#type: "text", name: "serial", readonly: true, value: "{s_serial}"}}
                        }
                        tr{
                            style: "display:table-row;",
                            th{rowspan: "2", div{label {r#for: "pin", "YubiKey PIN"}}}
                            td{input { r#type: "password", placeholder: "Enter YubiKey PIN", name: "pin", value: "{s_pin}", maxlength: "8"}}
                        }
                        tr{
                            style: "display:table-row;",
                            td{input { r#type: "password", placeholder: "Re-enter YubiKey PIN", name: "pin2", value: "{s_pin}", maxlength: "8"}}
                        }
                        tr{
                            style: "display:table-row;",
                            th{rowspan: "2", div{label {r#for: "puk", "YubiKey PUK"}}}
                            td{input { r#type: "password", placeholder: "Enter YubiKey PUK", name: "puk", value: "{s_pin}", maxlength: "8"}}
                        }
                        tr{
                            style: "display:table-row;",
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
    }) //end cx.render
}
