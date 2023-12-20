//! User interface for Purebred workflow

#![cfg(feature = "gui")]
#![allow(non_snake_case)]

use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dioxus::prelude::*;
use dioxus_toast::{Icon, ToastInfo, ToastManager};
use fermi::{use_atom_ref, use_init_atom_root, AtomRef};
use lazy_static::lazy_static;
use log::{debug, error, info};

use base64ct::{Base64, Encoding};

use pbyklib::{
    ota::{
        data::OtaActionInputs, enroll::enroll, pre_enroll::pre_enroll, recover::recover, ukm::ukm,
    },
    utils::list_yubikeys::get_yubikey,
    PB_MGMT_KEY,
};

use crate::args::{num_environments, PbYkArgs};
use crate::gui::{
    gui_main::{Phase, Phase::*},
    reset::reset,
    utils::*,
};

lazy_static! {
    pub static ref DISA_ICON_BASE64: String =
        Base64::encode_string(include_bytes!("../../assets/disa.png"));
    pub static ref BURNED_OTPS: Mutex<BTreeMap<String, Duration>> = Mutex::new(BTreeMap::new());
}

static TOAST_MANAGER: AtomRef<ToastManager> = AtomRef(|_| ToastManager::default());

fn add_otp(otp: &str) {
    clean_otps();
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            BURNED_OTPS
                .lock()
                .unwrap()
                .insert(otp.to_string(), duration);
        }
        Err(e) => {
            error!(
                "Failed to read duration in add_otp: {e}. Continuing without OTP reuse detection."
            )
        }
    }
}

fn check_otp(otp: &str) -> bool {
    BURNED_OTPS.lock().unwrap().contains_key(otp)
}

fn clean_otps() {
    let cur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let limit = Duration::new(180, 0);
    BURNED_OTPS.lock().unwrap().retain(|_, v| cur - *v < limit);
}

/// app is the primary component of GUI mode. It draws the forms that comprise the Purebred workflow
/// and drives execution through the workflow.
pub(crate) fn app<'a>(
    cx: Scope<'a>,
    s_phase: &'a UseState<Phase>,
    s_serial: &'a UseState<String>,
    s_reset_req: &'a UseState<bool>,
    s_serials: &'a UseState<Vec<String>>,
    s_fatal_error_val: &'a UseState<String>,
) -> Element<'a> {
    // initialize plumbing for status dialogs
    use_init_atom_root(cx);
    let toast = use_atom_ref(cx, &TOAST_MANAGER);

    let s_disa_icon = use_state(cx, || DISA_ICON_BASE64.clone());

    // State variables for input fields
    let s_edipi = use_state(cx, || {
        // Only saved element at present is agent edipi
        let sa = read_saved_args_or_default();
        sa.agent_edipi.unwrap_or_default()
    });
    let s_pin = use_state(cx, String::new);
    let s_puk = use_state(cx, String::new);
    let s_pre_enroll_otp = use_state(cx, String::new);
    let s_enroll_otp = use_state(cx, String::new);
    let s_hash = use_state(cx, String::new);
    let s_ukm_otp = use_state(cx, String::new);
    let s_recover = use_state(cx, || false);
    let (s_dev_checked, s_om_nipr_checked, s_om_sipr_checked, s_nipr_checked, s_sipr_checked) =
        get_default_env_radio_selections(cx);

    let serials = s_serials.get();
    let serial_setter = s_serial.setter();
    let s_check_phase = use_state(cx, || false);
    let check_phase_setter = s_check_phase.setter();

    // Style variables for enabling/disabling UI elements. One governs the cursor. The other governs
    // elements that benefit from disabling, i.e., clickable elements and editable elements. Read-only
    // elements are not changed based on app state.
    let s_cursor = use_state(cx, || "default".to_string());
    let s_disabled = use_state(cx, || false);

    let s_reset_abandoned = use_state(cx, || false);
    let reset_setter = s_reset_req.setter();
    let reset_abandoned_setter = s_reset_abandoned.setter();
    let pin_setter = s_pin.setter();
    let puk_setter = s_puk.setter();
    let s_reset_complete = use_state(cx, || false);

    // icon click variables
    let s_click_count = use_state(cx, || 0);
    let s_click_start = use_state(cx, || 0);
    let s_hide_reset = use_state(cx, || "none".to_string());

    // Style variables for impermanent UI elements
    let s_enroll_otp_style = use_state(cx, || "display:none;");
    let (s_edipi_style, s_pre_enroll_otp_style, s_ukm_otp_style, s_hide_recovery, s_button_label) =
        match s_phase.get() {
            Ukm => (
                use_state(cx, || "display:none;"),
                use_state(cx, || "display:none;"),
                use_state(cx, || "display:table-row;"),
                use_state(cx, || "none"),
                use_state(cx, || "User Key Management".to_string()),
            ),
            UkmOrRecovery => (
                use_state(cx, || "display:none;"),
                use_state(cx, || "display:none;"),
                use_state(cx, || "display:table-row;"),
                use_state(cx, || "inline-block"),
                use_state(cx, || "User Key Management".to_string()),
            ),
            _ => (
                use_state(cx, || "display:table-row;"),
                use_state(cx, || "display:table-row;"),
                use_state(cx, || "display:none;"),
                use_state(cx, || "none"),
                use_state(cx, || "Pre-enroll".to_string()),
            ),
        };
    // Only show the environment row/table when there is more than one environment option available
    let s_multi_env_style = if 1 == num_environments() {
        use_state(cx, || "display:none;")
    } else {
        use_state(cx, || "display:table-row;")
    };

    #[cfg(feature = "dev")]
    let s_dev_style = use_state(cx, || "display:table-row;");
    #[cfg(not(feature = "dev"))]
    let s_dev_style = use_state(cx, || "display:none;");

    #[cfg(feature = "om_nipr")]
    let s_om_nipr_style = use_state(cx, || "display:table-row;");
    #[cfg(not(feature = "om_nipr"))]
    let s_om_nipr_style = use_state(cx, || "display:none;");

    #[cfg(feature = "om_sipr")]
    let s_om_sipr_style = use_state(cx, || "display:table-row;");
    #[cfg(not(feature = "om_sipr"))]
    let s_om_sipr_style = use_state(cx, || "display:none;");

    #[cfg(feature = "nipr")]
    let s_nipr_style = use_state(cx, || "display:table-row;");
    #[cfg(not(feature = "nipr"))]
    let s_nipr_style = use_state(cx, || "display:none;");

    #[cfg(feature = "sipr")]
    let s_sipr_style = use_state(cx, || "display:table-row;");
    #[cfg(not(feature = "sipr"))]
    let s_sipr_style = use_state(cx, || "display:none;");

    if *s_reset_complete.get() {
        s_pin.setter()(String::new());
        s_reset_complete.setter()(false);
        s_edipi_style.setter()("display:table-row;");
        s_pre_enroll_otp_style.setter()("display:table-row;");
        s_ukm_otp_style.setter()("display:none;");
        s_hide_recovery.setter()("none");
        s_button_label.setter()("Pre-enroll".to_string());
        s_hide_reset.setter()("none".to_string());
        s_phase.setter()(PreEnroll);
    }

    if *s_check_phase.get() {
        s_pin.setter()(String::new());
        let serial = s_serial.get().clone();
        debug!("Connecting to newly selected YubiKey: {serial}");
        let s = yubikey::Serial(serial.parse::<u32>().unwrap());
        let yubikey = match get_yubikey(Some(s)) {
            Ok(yk) => Some(yk),
            Err(e) => {
                error!("Failed to connect to YubiKey with serial {serial} with: {e}");
                s_fatal_error_val.setter()(format!("Failed to connect to YubiKey with serial {serial} with: {}. Close the app, make sure one YubiKey is available then try again.", e));
                None
            }
        };

        if let Some(mut yubikey) = yubikey {
            debug!("Determining phase of newly selected YubiKey: {serial}");
            match yubikey.authenticate(PB_MGMT_KEY.clone()) {
                Ok(_) => {
                    let phase = determine_phase(&mut yubikey);
                    if phase != *s_phase.get() {
                        s_phase.setter()(phase.clone());
                        match phase {
                            PreEnroll => {
                                s_edipi_style.setter()("display:table-row;");
                                s_pre_enroll_otp_style.setter()("display:table-row;");
                                s_ukm_otp_style.setter()("display:none;");
                                s_hide_recovery.setter()("none");
                                s_button_label.setter()("Pre-enroll".to_string());
                                s_hide_reset.setter()("none".to_string());
                            }
                            Enroll => {
                                s_edipi_style.setter()("display:table-row;");
                                s_pre_enroll_otp_style.setter()("display:none;");
                                s_ukm_otp_style.setter()("display:none;");
                                s_enroll_otp_style.setter()("display:table-row;");
                                s_hide_recovery.setter()("none");
                                s_button_label.setter()("Enroll".to_string());
                                s_hide_reset.setter()("none".to_string());
                            }
                            Ukm => {
                                s_edipi_style.setter()("display:none;");
                                s_pre_enroll_otp_style.setter()("display:none;");
                                s_enroll_otp_style.setter()("display:none;");
                                s_ukm_otp_style.setter()("display:table-row;");
                                s_hide_recovery.setter()("none");
                                s_button_label.setter()("User Key Management".to_string());
                                s_hide_reset.setter()("none".to_string());
                            }
                            UkmOrRecovery => {
                                s_edipi_style.setter()("display:none;");
                                s_pre_enroll_otp_style.setter()("display:none;");
                                s_enroll_otp_style.setter()("display:none;");
                                s_ukm_otp_style.setter()("display:table-row;");
                                s_button_label.setter()("User Key Management".to_string());
                                s_hide_recovery.setter()("inline-block");
                                s_hide_reset.setter()("none".to_string());
                            }
                        }
                    }
                }
                Err(e) => {
                    let err = format!("The YubiKey with serial number {serial} is not using the expected management key. Please reset the device then try again.");
                    error!("{err}: {e:?}");

                    #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
                    {
                        let (tx, rx) = std::sync::mpsc::channel();
                        use native_dialog::{MessageDialog, MessageType};
                        match MessageDialog::new()
                            .set_type(MessageType::Info)
                            .set_title("Reset?")
                            .set_text(&format!("The YubiKey with serial number {serial} is not using the expected management key. Would you like to reset the device now?"))
                            .show_confirm()
                        {
                            Ok(answer) => {
                                if answer {
                                    let _ = tx.send(None);
                                } else {
                                    let _ = tx.send(Some(err.to_string()));
                                }
                            },
                            Err(e) => {
                                error!("Failed to solicit reset answer from user: {e}");
                            }
                        }
                        match rx.recv() {
                            Ok(result) => {
                                match result {
                                    Some(err) => {
                                        if 1 == s_serials.len() {
                                            s_fatal_error_val.setter()(err);
                                        } else {
                                            let serial_str = s_serial.get();
                                            for cur in s_serials.get().iter() {
                                                if cur != serial_str {
                                                    info!("Resetting serial from {serial_str} to {cur}");
                                                    s_serial.setter()(cur.to_string());
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    None => reset_setter(true),
                                }
                            }
                            Err(e) => {
                                let sm =
                                    format!("Failed to spawn thread for reset: {e}").to_string();
                                error!("{}", sm);
                                s_fatal_error_val.setter()(sm);
                            }
                        }
                    }

                    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
                    s_fatal_error_val.setter()(err.to_string());
                }
            }
        }

        check_phase_setter(false);
    }

    // Non-fatal error handling
    let s_error_msg = use_state(cx, String::new);
    let s_reset_msg = use_state(cx, String::new);
    let error_msg_setter = s_error_msg.setter();
    if !s_error_msg.is_empty() {
        let _id = toast.write().popup(ToastInfo {
            heading: Some("ERROR".to_string()),
            context: s_error_msg.to_string(),
            allow_toast_close: true,
            position: dioxus_toast::Position::TopLeft,
            icon: Some(Icon::Error),
            hide_after: None,
        });
        error_msg_setter(String::new());
    }
    let s_success_msg = use_state(cx, String::new);
    let success_msg_setter = s_success_msg.setter();
    if !s_success_msg.is_empty() {
        let _id = toast.write().popup(ToastInfo {
            heading: Some("SUCCESS".to_string()),
            context: s_success_msg.to_string(),
            allow_toast_close: true,
            position: dioxus_toast::Position::TopLeft,
            icon: Some(Icon::Success),
            hide_after: None,
        });
        success_msg_setter(String::new());
    }

    if *s_reset_req.get() {
        debug!("Showing reset view");
        if !s_pin.get().is_empty() || !s_puk.get().is_empty() {
            pin_setter(String::new());
            puk_setter(String::new());
        }
        reset(
            cx,
            s_serial,
            s_reset_req,
            s_pin,
            s_puk,
            s_reset_msg,
            s_reset_complete,
            s_disa_icon,
        )
    } else {
        cx.render(rsx! {
            style { include_str!("../../assets/pbyk.css") }
            div {
                form {
                    onsubmit: move |ev| {
                        let error_msg_setter = s_error_msg.setter();
                        let success_msg_setter = s_success_msg.setter();

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
                            reset_yubikey: false,
                            logging_config: None,
                            log_to_console: false,
                            environment: None,
                            portal_status_check: false,
                            scep_check: false,
                            interactive: false
                        };
                        let _ = save_args(&args);
                        let _ = save_window_size(cx);
                        let serial_u32 = match s_serial.get().parse::<u32>() {
                            Ok(serial_u32) => Some(serial_u32),
                            Err(e) => {
                                let sm = format!("Failed to process YubiKey serial number: {e}.");
                                error!("{}", sm);
                                error_msg_setter(sm.to_string());
                                None
                            }
                        };

                        let PB_BASE_URL = match environment.as_str() {
                            #[cfg(feature = "dev")]
                            "DEV" => "https://pb2.redhoundsoftware.net".to_string(),
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
                                error_msg_setter(sm.to_string());
                                String::new()
                            }
                        };

                        let p = s_phase.get().clone();
                        let hash_setter = s_hash.setter();
                        let preenroll_style_setter = s_pre_enroll_otp_style.setter();
                        let edipi_setter = s_edipi.setter();
                        let enroll_style_setter = s_enroll_otp_style.setter();
                        let edipi_style_setter = s_edipi_style.setter();
                        let ukm_setter = s_ukm_otp_style.setter();
                        let pin_setter = s_pin.setter();
                        let phase_setter = s_phase.setter();
                        let button_setter = s_button_label.setter();
                        let hide_recovery_setter = s_hide_recovery.setter();
                        let cursor_setter = s_cursor.setter();
                        let disabled_setter = s_disabled.setter();
                        let recover_setter = s_recover.setter();

                        macro_rules! enter_enroll_phase {
                                () => {
                                    preenroll_style_setter("display:none;");
                                    enroll_style_setter("display:table-row;");
                                    phase_setter(Enroll);
                                    button_setter("Enroll".to_string());
                                };
                            }
                        macro_rules! enter_ukm_phase {
                                () => {
                                    preenroll_style_setter("display:none;");
                                    enroll_style_setter("display:none;");
                                    edipi_style_setter("display:none;");
                                    ukm_setter("display:table-row;");
                                    phase_setter(Ukm);
                                    button_setter("User Key Management".to_string());
                                };
                            }
                        macro_rules! enter_ukm_or_recovery_phase {
                                () => {
                                    hide_recovery_setter("inline-block");
                                    preenroll_style_setter("display:none;");
                                    enroll_style_setter("display:none;");
                                    edipi_style_setter("display:none;");
                                    ukm_setter("display:table-row;");
                                    phase_setter(UkmOrRecovery);
                                    button_setter("User Key Management".to_string());
                                };
                            }

                        let recovery_active = *s_recover.get();
                        let reset_abandoned = *s_reset_abandoned.get();

                        if !reset_abandoned {
                            cursor_setter("wait".to_string());
                            disabled_setter(true);
                        }
                        else {
                            s_reset_abandoned.setter()(false);
                        }

                        async move {
                            if reset_abandoned {
                                // if we arrive here due to an aborted reset, just bail out
                                return;
                            }

                            if PB_BASE_URL.is_empty() {
                                // error message is set up in match statement above if environment
                                // is unrecognized and PB_BASE_URL is set to empty
                                cursor_setter("default".to_string());
                                disabled_setter(false);
                                return;
                            }

                            let yks = match serial_u32 {
                                Some(serial_u32) => yubikey::Serial(serial_u32),
                                None => {
                                    // error message is set up in match statement above if serial number
                                    // conversion fails
                                    cursor_setter("default".to_string());
                                    disabled_setter(false);
                                    return;
                                }
                            };

                            debug!("Connecting to target YubiKey: {yks}");
                            let mut yubikey = match get_yubikey(Some(yks)) {
                                Ok(yk) => yk,
                                Err(e) => {
                                    let sm = format!("Could not get the YubiKey with serial number {yks}. Please make sure the device is available then try again. Error: {e}");
                                    error!("{}", sm);
                                    error_msg_setter(sm.to_string());
                                    cursor_setter("default".to_string());
                                    disabled_setter(false);
                                    return;
                                }
                            };

                            if yubikey.authenticate(PB_MGMT_KEY.clone()).is_err() {
                                let sm = format!("The YubiKey with serial number {} is not using the expected management key. Please reset the device then try again.", yubikey.serial());
                                error!("{}", sm);
                                error_msg_setter(sm.to_string());
                                cursor_setter("default".to_string());
                                disabled_setter(false);
                                return;
                            }

                            let app = format!("{}-ui {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

                            let pin = match string_or_none(&ev, "pin") {
                                Some(str) => str,
                                None => {
                                    let sm = format!("No PIN was provided. Please enter the PIN for the YubiKey with serial number {} and try again", yks);
                                    error!("{}", sm);
                                    error_msg_setter(sm.to_string());
                                    cursor_setter("default".to_string());
                                    disabled_setter(false);
                                    return;
                                }
                            };

                            match p {
                                PreEnroll => {
                                    info!("Starting Pre-enroll operation...");
                                    let agent_edipi = match string_or_none(&ev, "edipi") {
                                        Some(agent_edipi) => agent_edipi,
                                        None => {
                                            let sm = "No Agent EDIPI was provided. Please enter the EDIPI of the cooperating Purebred Agent and try again";
                                            error!("{}", sm);
                                            error_msg_setter(sm.to_string());
                                            cursor_setter("default".to_string());
                                            disabled_setter(false);
                                            return;
                                        }
                                    };
                                    let pre_enroll_otp = match string_or_none(&ev, "pre_enroll_otp") {
                                        Some(pre_enroll_otp) => {
                                            if !pre_enroll_otp.chars().all(|c| c.is_numeric()) || 8 != pre_enroll_otp.len() {
                                                let sm = "OTP values MUST be exactly 8 characters long and only contain numeric values.";
                                                error!("{}", sm);
                                                error_msg_setter(sm.to_string());
                                                cursor_setter("default".to_string());
                                                disabled_setter(false);
                                                return;
                                            }
                                            pre_enroll_otp
                                        },
                                        None => {
                                            let sm = "No pre-enroll OTP was provided. Please enter a pre-enroll OTP and try again";
                                            error!("{}", sm);
                                            error_msg_setter(sm.to_string());
                                            cursor_setter("default".to_string());
                                            disabled_setter(false);
                                            return;
                                        }
                                    };
                                    if check_otp(&pre_enroll_otp) {
                                        let sm = "OTP values MUST NOT be reused. Please obtain a fresh OTP and try again.";
                                        error!("{}", sm);
                                        error_msg_setter(sm.to_string());
                                        cursor_setter("default".to_string());
                                        disabled_setter(false);
                                        return;
                                    }
                                    else {
                                        add_otp(&pre_enroll_otp);
                                    }

                                    let (tx, rx) = std::sync::mpsc::channel();
                                    let pin_t = pin.clone();
                                    pin_setter(pin);
                                    let agent_edipi_t = agent_edipi.clone();
                                    edipi_setter(agent_edipi);
                                    let _ = tokio::spawn(async move {
                                        match pre_enroll(
                                            &mut yubikey,
                                            &agent_edipi_t,
                                            &pre_enroll_otp,
                                            &PB_BASE_URL,
                                            pin_t.as_bytes(),
                                            &PB_MGMT_KEY.clone()
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
                                                hash_setter(hash.clone());
                                                enter_enroll_phase!();
                                            }
                                            else {
                                                error_msg_setter(result.1.unwrap_or_default());
                                            }
                                        }
                                        Err(e) => {
                                            let sm = format!("Failed to spawn thread for pre-enrollment: {e}").to_string();
                                            error!("{}", sm);
                                            error_msg_setter(sm);
                                        }
                                    }
                                    cursor_setter("default".to_string());
                                    disabled_setter(false);
                                }
                                Enroll => {
                                    info!("Starting Enroll operation...");
                                    let agent_edipi = match string_or_none(&ev, "edipi") {
                                        Some(agent_edipi) => agent_edipi,
                                        None => {
                                            let sm = "No Agent EDIPI was provided. Please enter the EDIPI of the cooperating Purebred Agent and try again";
                                            error!("{}", sm);
                                            error_msg_setter(sm.to_string());
                                            cursor_setter("default".to_string());
                                            disabled_setter(false);
                                            return;
                                        }
                                    };
                                    let enroll_otp = match string_or_none(&ev, "enroll_otp") {
                                        Some(enroll_otp) => {
                                            if !enroll_otp.chars().all(|c| c.is_numeric()) || 8 != enroll_otp.len() {
                                                let sm = "OTP values MUST be exactly 8 characters long and only contain numeric values.";
                                                error!("{}", sm);
                                                error_msg_setter(sm.to_string());
                                                cursor_setter("default".to_string());
                                                disabled_setter(false);
                                                return;
                                            }
                                            enroll_otp
                                        },
                                        None => {
                                            let sm = "No enroll OTP was provided. Please enter an enroll OTP and try again";
                                            error!("{}", sm);
                                            error_msg_setter(sm.to_string());
                                            cursor_setter("default".to_string());
                                            disabled_setter(false);
                                            return;
                                        }
                                    };
                                    if check_otp(&enroll_otp) {
                                        let sm = "OTP values MUST NOT be reused. Please obtain a fresh OTP and try again.";
                                        error!("{}", sm);
                                        error_msg_setter(sm.to_string());
                                        cursor_setter("default".to_string());
                                        disabled_setter(false);
                                        return;
                                    }
                                    else {
                                        add_otp(&enroll_otp);
                                    }

                                    let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
                                    let pin_t = pin.clone();
                                    pin_setter(pin);
                                    let oai = OtaActionInputs::new(
                                        &yubikey.serial().to_string(),
                                        &enroll_otp,
                                        &PB_BASE_URL.to_string(),
                                        &app,
                                    );
                                    let _ = tokio::spawn(async move {
                                        match enroll(
                                            &mut yubikey,
                                            &agent_edipi,
                                            &oai,
                                            pin_t.as_bytes(),
                                            &PB_MGMT_KEY.clone(),
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
                                                error_msg_setter(error);
                                            }
                                            else {
                                                enter_ukm_phase!();
                                            }
                                        }
                                        Err(e) => {
                                            let sm = format!("Failed to spawn thread for enrollment: {e}").to_string();
                                            error!("{}", sm);
                                            error_msg_setter(sm);
                                        }
                                    }
                                    cursor_setter("default".to_string());
                                    disabled_setter(false);
                                }
                                Ukm | UkmOrRecovery => {
                                    info!("Ukm | UkmOrRecovery");
                                    // handle remaining phases (i.e., Ukm or UkmOrRecovery) with recover checkbox as governor
                                    let ukm_otp = match string_or_none(&ev, "ukm_otp") {
                                        Some(ukm_otp) => {
                                            if !ukm_otp.chars().all(|c| c.is_numeric()) || 8 != ukm_otp.len() {
                                                let sm = "OTP values MUST be exactly 8 characters long and only contain numeric values.";
                                                error!("{}", sm);
                                                error_msg_setter(sm.to_string());
                                                cursor_setter("default".to_string());
                                                disabled_setter(false);
                                                return;
                                            }
                                            ukm_otp
                                        },
                                        None => {
                                            let sm = "No UKM OTP was provided. Please enter a UKM OTP and try again";
                                            error!("{}", sm);
                                            error_msg_setter(sm.to_string());
                                            cursor_setter("default".to_string());
                                            disabled_setter(false);
                                            return;
                                        }
                                    };
                                    if check_otp(&ukm_otp) {
                                        let sm = "OTP values MUST NOT be reused. Please obtain a fresh OTP and try again.";
                                        error!("{}", sm);
                                        error_msg_setter(sm.to_string());
                                        cursor_setter("default".to_string());
                                        disabled_setter(false);
                                        return;
                                    }
                                    else {
                                        add_otp(&ukm_otp);
                                    }

                                    let oai = OtaActionInputs::new(
                                        &yks.to_string(),
                                        &ukm_otp,
                                        &PB_BASE_URL.to_string(),
                                        &app,
                                    );

                                    if recovery_active {
                                        recover_setter(false);
                                        info!("Starting recover operation...");
                                        let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
                                        let pin_t = pin.clone();
                                        pin_setter(pin);
                                        let _ = tokio::spawn(async move {
                                            match recover(&mut yubikey, &oai, pin_t.as_bytes(), &PB_MGMT_KEY.clone(), &environment).await {
                                                Ok(_) => {
                                                    info!("Recover completed successfully");
                                                    if let Err(e) = tx.send(None) {
                                                        error!("Failed to send recover results to main thread: {e}");
                                                    }
                                                }
                                                Err(e) => {
                                                    let sm = format!("Recover failed: {:?}", e);
                                                    error!("{}", sm);
                                                    if let Err(e) = tx.send(Some(format!("{sm}. Make sure the UKM OTP are correct and try again."))) {
                                                        error!("Failed to send recover results to main thread: {e}");
                                                    }
                                                }
                                            }
                                        }).await;
                                        match rx.recv() {
                                            Ok(result) => {
                                                if let Some(error) = result {
                                                    error_msg_setter(error);
                                                }
                                                else {
                                                    recover_setter(false);
                                                    success_msg_setter("Recover completed successfully".to_string());
                                                }
                                            }
                                            Err(e) => {
                                                let sm = format!("Failed to spawn thread for recover: {e}").to_string();
                                                error!("{}", sm);
                                                error_msg_setter(sm);
                                            }
                                        }
                                    }
                                    else {
                                        info!("Starting UKM operation...");
                                        let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
                                        let pin_t = pin.clone();
                                        pin_setter(pin);
                                        let _ = tokio::spawn(async move {
                                            match ukm(&mut yubikey, &oai, pin_t.as_bytes(), &PB_MGMT_KEY.clone(), &environment).await {
                                                Ok(_) => {
                                                    info!("UKM completed successfully");
                                                    if let Err(e) = tx.send(None) {
                                                        error!("Failed to send UKM results to main thread: {e}");
                                                    }
                                                }
                                                Err(e) => {
                                                    let sm = format!("UKM failed: {:?}", e);
                                                    error!("{}", sm);
                                                    if let Err(e) = tx.send(Some(format!("{sm}. Make sure the UKM OTP are correct and try again."))) {
                                                        error!("Failed to send UKM results to main thread: {e}");
                                                    }
                                                }
                                            }
                                        }).await;
                                        match rx.recv() {
                                            Ok(result) => {
                                                if let Some(error) = result {
                                                    error_msg_setter(error);
                                                }
                                                else {
                                                    enter_ukm_or_recovery_phase!();
                                                    success_msg_setter("UKM completed successfully".to_string());
                                                }
                                            }
                                            Err(e) => {
                                                let sm = format!("Failed to spawn thread for UKM: {e}").to_string();
                                                error!("{}", sm);
                                                error_msg_setter(sm);
                                            }
                                        }
                                    }
                                    cursor_setter("default".to_string());
                                    disabled_setter(false);
                                }
                             }// end match phase
                        } // end async move
                    }, // end onsubmit
                    table {
                        class: "{s_cursor}",
                        tbody {
                            tr{
                                style: if *s_phase.get() != Enroll { "display:table-row;" } else {"display:none;"},
                                td{div{label {r#for: "multi_serial", "YubiKey Serial Number"}}}
                                td{select {
                                   oninput: move |evt| {
                                       println!("{evt:?}");
                                       serial_setter(evt.value.to_string());
                                       check_phase_setter(true);
                                   },
                                   name: "serials", value: "{s_serial}",
                                   serials.iter().map(|s|
                                       rsx!{ option {
                                           value : "{s}",
                                           label : "{s}",
                                           selected: if *s_serial.get() == *s {"true"} else {"false"}
                                       }
                                   })
                                }}
                            }
                            tr{
                                style: if *s_phase.get() == Enroll { "display:table-row;" } else {"display:none;"},
                                td{div{label {r#for: "serial", "YubiKey Serial Number"}}}
                                td{input { r#type: "text", name: "serial", readonly: true, value: "{s_serial}"}}
                            }
                            tr{
                                style: "{s_edipi_style}",
                                td{div{title: "EDIPI of the cooperating Purebred Agent.", label {r#for: "edipi", "Purebred Agent's EDIPI"}}}
                                td{input { disabled: "{s_disabled}", r#type: "text", name: "edipi", placeholder: "Enter Purebred Agent's EDIPI", value: "{s_edipi}", maxlength: "10"}}
                            }
                            tr{
                                style: "{s_pre_enroll_otp_style}",
                                td{div{label {r#for: "pre_enroll_otp", "Pre-enroll OTP"}}}
                                td{input { disabled: "{s_disabled}", r#type: "text", name: "pre_enroll_otp", placeholder: "Enter Pre-Enroll OTP", value: "{s_pre_enroll_otp}", maxlength: "8"}}
                            }
                            tr{
                                style: "{s_enroll_otp_style}",
                                td{div{label {r#for: "hash", "Hash"}}}
                                td{input { r#type: "text", name: "hash", readonly: true, value: "{s_hash}"}}
                            }
                            tr{
                                style: "{s_enroll_otp_style}",
                                td{div{label {r#for: "enroll_otp", "Enroll OTP"}}}
                                td{input { disabled: "{s_disabled}", r#type: "text", name: "enroll_otp", placeholder: "Enter Enroll OTP", value: "{s_enroll_otp}", maxlength: "8"}}
                            }
                            tr{
                                style: "{s_ukm_otp_style}",
                                td{div{label {r#for: "ukm_otp", "UKM OTP"}}}
                                td{input { disabled: "{s_disabled}", r#type: "text", name: "ukm_otp", placeholder: "Enter UKM OTP", value: "{s_ukm_otp}", minlength: "8", maxlength: "8"}}
                            }
                            tr{
                                style: "display:table-row;",
                                td{div{label {r#for: "pin", "YubiKey PIN"}}}
                                td{input { disabled: "{s_disabled}", r#type: "password", placeholder: "Enter YubiKey PIN", name: "pin", value: "{s_pin}", maxlength: "8"}}
                            }
                            tr{
                                style: "{s_multi_env_style}",
                                td{div{label {"Environment"}}}
                                table {
                                    class: "nested_table",
                                    tr {
                                        style: "{s_dev_style}",
                                        td{input { disabled: "{s_disabled}", r#type: "radio", id: "dev", name: "environment", value: "DEV", checked: "{s_dev_checked}" }}
                                        td{div{label {r#for: "dev", "Development"}}}
                                    }
                                    tr {
                                        style: "{s_om_nipr_style}",
                                        td{input { disabled: "{s_disabled}", r#type: "radio", id: "om_nipr", name: "environment", value: "OM_NIPR", checked: "{s_om_nipr_checked}" }}
                                        td{div{label {r#for: "om_nipr", "NIPR O&M"}}}
                                    }
                                    tr {
                                        style: "{s_nipr_style}",
                                        td{input { disabled: "{s_disabled}", r#type: "radio", id: "nipr", name: "environment", value: "NIPR", checked: "{s_nipr_checked}" }}
                                        td{div{label {r#for: "nipr", "NIPR"}}}
                                    }
                                    tr {
                                        style: "{s_om_sipr_style}",
                                        td{input { disabled: "{s_disabled}", r#type: "radio", id: "om_sipr", name: "environment", value: "OM_SIPR", checked: "{s_om_sipr_checked}" }}
                                        td{div{label {r#for: "om_sipr", "SIPR O&M"}}}
                                    }
                                    tr {
                                        style: "{s_sipr_style}",
                                        td{input { disabled: "{s_disabled}", r#type: "radio", id: "sipr", name: "environment", value: "SIPR", checked: "{s_sipr_checked}" }}
                                        td{div{label {r#for: "sipr", "SIPR"}}}
                                    }
                                }
                            }
                        }
                    }
                    dioxus_toast::ToastFrame {
                        manager: toast
                    }
                    div {
                        style: "text-align:center;",
                        div {
                            style: "text-align:center;",
                            div{
                                style: "text-align:center; display: inline-block; margin-right:5px;",
                                button { disabled: "{s_disabled}", r#type: "submit", value: "Submit", "{s_button_label}" }
                            }
                            div{
                                style: "text-align:center; display: {s_hide_recovery}; margin-right:5px;",
                                button { disabled: "{s_disabled}", r#type: "submit", onclick: move |_| s_recover.setter()(true), value: "Recovery", "Recover Old Decryption Keys" }
                            }
                        }
                        div{
                            style: "text-align:center; display: {s_hide_reset}; margin-right:5px;",
                            button { disabled: "{s_disabled}", value: "Reset",
                                onclick: move |_| {
                                    s_success_msg.setter()(String::new());
                                    s_error_msg.setter()(String::new());

                                    use native_dialog::{MessageDialog, MessageType};
                                    match MessageDialog::new()
                                        .set_type(MessageType::Info)
                                        .set_title("Reset?")
                                        .set_text(&format!("Are you sure you want to reset the YubiKey with serial number {s_serial} now?"))
                                        .show_confirm()
                                    {
                                        Ok(answer) => {
                                            if answer {
                                                reset_abandoned_setter(false);
                                                reset_setter(true);
                                            }
                                            else {
                                                reset_abandoned_setter(true);
                                            }
                                        },
                                        Err(e) => {
                                            error!("Failed to solicit reset answer from user: {e}");
                                        }
                                    }
                                },
                                "Reset"
                            }
                        }
                    }
                    div {
                        style: "text-align:center",
                        img {
                            src: "data:image/png;base64, {s_disa_icon}",
                            max_height: "25%",
                            max_width: "25%",
                            onclick: move |_| {
                                let click_count_setter = s_click_count.setter();
                                let click_start_setter = s_click_start.setter();
                                #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
                                let hide_reset_setter = s_hide_reset.setter();

                                let last_count = s_click_count.get();
                                let last_start = s_click_start.get();
                                let disabled = *s_disabled.get();
                                match SystemTime::now().duration_since(UNIX_EPOCH) {
                                    Ok(n) => {
                                        if !disabled {
                                            let secs = n.as_secs();
                                            if secs - last_start > 5 {
                                                click_count_setter(1);
                                                click_start_setter(secs);
                                            } else if *last_count >= 4 {
                                                #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
                                                hide_reset_setter("inline-block".to_string());
                                            }
                                            else {
                                                click_count_setter(last_count+1);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to get UNIX_EPOCH: {e}. Continuing...");
                                    },
                                }
                            }
                        }
                    }
                }
            }
        }) //end cx.render
    }
}
