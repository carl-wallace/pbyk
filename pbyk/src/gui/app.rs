//! User interface for Purebred workflow

#![cfg(feature = "gui")]
#![allow(non_snake_case)]
// todo: revisit
// onsubmit, onclick, etc. are causing these warnings
#![allow(unused_qualifications)]

use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dioxus::prelude::*;
use dioxus_toast::{Icon, ToastInfo, ToastManager};
use log::{debug, error, info};
use std::sync::LazyLock;
use zeroize::Zeroizing;

use base64ct::{Base64, Encoding};
use dioxus_desktop::use_window;
use pbyklib::{
    ota::{
        data::OtaActionInputs, enroll::enroll, pre_enroll::pre_enroll, recover::recover, ukm::ukm,
        CryptoModule,
    },
    utils::list_yubikeys::{get_pre_enroll_hash_yubikey, get_yubikey},
    PB_MGMT_KEY,
};

use crate::args::{num_environments, PbYkArgs};
use crate::gui::{
    gui_main::{Phase, Phase::*},
    reset::reset,
    utils::*,
};

#[cfg(all(target_os = "windows", feature = "vsc"))]
use pbyklib::utils::{
    get_pre_enroll_hash,
    list_vscs::{get_vsc, get_vsc_id_from_serial},
};

#[cfg(all(target_os = "windows", feature = "vsc"))]
use crate::determine_vsc_phase;

pub static DISA_ICON_BASE64: LazyLock<String> =
    LazyLock::new(|| Base64::encode_string(include_bytes!("../../assets/disa.png")));
pub static BURNED_OTPS: LazyLock<Mutex<BTreeMap<String, Duration>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

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

/// Update various UseState variables based on the phase value
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

/// app is the primary component of GUI mode. It draws the forms that comprise the Purebred workflow
/// and drives execution through the workflow.
pub(crate) fn app(
    mut s_phase: Signal<Phase>,
    mut s_serial: Signal<String>,
    mut s_reset_req: Signal<bool>,
    s_serials: Signal<Vec<String>>,
    mut s_fatal_error_val: Signal<String>,
    is_yubikey: bool,
) -> Element {
    // initialize plumbing for status dialogs

    let mut toast = use_signal(ToastManager::default);

    let s_disa_icon = use_signal(|| DISA_ICON_BASE64.clone());

    // State variables for input fields
    let mut s_edipi = use_signal(|| {
        // Only saved element at present is agent edipi
        let sa = read_saved_args_or_default();
        sa.agent_edipi.unwrap_or_default()
    });
    let mut s_pin = use_signal(String::new);
    let mut s_puk = use_signal(String::new);
    let s_pre_enroll_otp = use_signal(String::new);
    let s_enroll_otp = use_signal(String::new);
    let mut s_hash = use_signal(String::new);
    let s_ukm_otp = use_signal(String::new);
    let mut s_recover = use_signal(|| false);
    let (b_dev, b_om_nipr, b_om_sipr, b_nipr, b_sipr) = get_default_env_radio_selections();

    let s_dev_checked = use_signal(|| b_dev);
    let s_om_nipr_checked = use_signal(|| b_om_nipr);
    let s_om_sipr_checked = use_signal(|| b_om_sipr);
    let s_nipr_checked = use_signal(|| b_nipr);
    let s_sipr_checked = use_signal(|| b_sipr);

    let mut s_check_phase = use_signal(|| false);

    // Style variables for enabling/disabling UI elements. One governs the cursor. The other governs
    // elements that benefit from disabling, i.e., clickable elements and editable elements. Read-only
    // elements are not changed based on app state.
    let mut s_cursor = use_signal(|| "default".to_string());
    let mut s_disabled = use_signal(|| false);

    let mut s_reset_abandoned = use_signal(|| false);
    let mut s_reset_complete = use_signal(|| false);

    // icon click variables
    let mut s_click_count = use_signal(|| 0);
    let mut s_click_start = use_signal(|| 0);
    let mut s_hide_reset = use_signal(|| "none".to_string());

    // Style variables for impermanent UI elements
    let mut s_pin_style = use_signal(|| {
        if is_yubikey {
            "display:table-row;".to_string()
        } else {
            "display:none;".to_string()
        }
    });
    let (
        str_edipi_style,
        str_pre_enroll_otp_style,
        str_ukm_otp_style,
        str_hide_recovery,
        str_button_label,
        str_enroll_otp_style,
    ) = match *s_phase.read() {
        Ukm => (
            "display:none;".to_string(),       // edipi
            "display:none;".to_string(),       // pre-enroll otp
            "display:table-row;".to_string(),  // UKM otp
            "none".to_string(),                // hide recovery
            "User Key Management".to_string(), //label
            "display:none;".to_string(),
        ),
        UkmOrRecovery => (
            "display:none;".to_string(),
            "display:none;".to_string(),
            "display:table-row;".to_string(),
            "inline-block".to_string(),
            "User Key Management".to_string(),
            "display:none;".to_string(),
        ),
        Enroll => (
            "display:table-row;".to_string(),
            "display:none;".to_string(),
            "display:none;".to_string(),
            "none".to_string(),
            "Enroll".to_string(),
            "display:table-row;".to_string(),
        ),
        PreEnroll => (
            "display:table-row;".to_string(),
            "display:table-row;".to_string(),
            "display:none;".to_string(),
            "none".to_string(),
            "Pre-enroll".to_string(),
            "display:none;".to_string(),
        ),
    };

    let mut s_edipi_style = use_signal(|| str_edipi_style);
    let mut s_pre_enroll_otp_style = use_signal(|| str_pre_enroll_otp_style);
    let mut s_ukm_otp_style = use_signal(|| str_ukm_otp_style);
    let mut s_hide_recovery = use_signal(|| str_hide_recovery);
    let mut s_button_label = use_signal(|| str_button_label);
    let mut s_enroll_otp_style = use_signal(|| str_enroll_otp_style);

    if *s_phase.read() == Enroll && s_hash.read().is_empty() {
        if is_yubikey {
            match get_pre_enroll_hash_yubikey(&s_serial.read()) {
                Ok(hash) => {
                    s_hash.set(hash);
                }
                Err(_e) => {
                    error!("Failed to calculate pre-enroll. Consider resetting the device and restarting enrollment.");
                }
            }
        } else {
            #[cfg(all(target_os = "windows", feature = "vsc"))]
            {
                let vsc_serial = parse_reader_from_vsc_display(&s_serial.read());
                match get_pre_enroll_hash(&vsc_serial) {
                    Ok(hash) => s_hash.set(hash),
                    Err(_e) => {
                        error!("Failed to calculate pre-enroll. Consider resetting the device and restarting enrollment.");
                    }
                }
            }
        }
    }

    // Only show the environment row/table when there is more than one environment option available
    let str_multi_env_style = if 1 == num_environments() {
        "display:none;"
    } else {
        "display:table-row;"
    };
    let s_multi_env_style = use_signal(|| str_multi_env_style);

    #[cfg(feature = "dev")]
    let s_dev_style = use_signal(|| "display:table-row;");
    #[cfg(not(feature = "dev"))]
    let s_dev_style = use_signal(|| "display:none;");

    #[cfg(feature = "om_nipr")]
    let s_om_nipr_style = use_signal(|| "display:table-row;");
    #[cfg(not(feature = "om_nipr"))]
    let s_om_nipr_style = use_signal(|| "display:none;");

    #[cfg(feature = "om_sipr")]
    let s_om_sipr_style = use_signal(|| "display:table-row;");
    #[cfg(not(feature = "om_sipr"))]
    let s_om_sipr_style = use_signal(|| "display:none;");

    #[cfg(feature = "nipr")]
    let s_nipr_style = use_signal(|| "display:table-row;");
    #[cfg(not(feature = "nipr"))]
    let s_nipr_style = use_signal(|| "display:none;");

    #[cfg(feature = "sipr")]
    let s_sipr_style = use_signal(|| "display:table-row;");
    #[cfg(not(feature = "sipr"))]
    let s_sipr_style = use_signal(|| "display:none;");

    if *s_reset_complete.read() {
        s_pin.set("".to_string());
        s_reset_complete.set(false);
        s_edipi_style.set("display:table-row;".to_string());
        s_pre_enroll_otp_style.set("display:table-row;".to_string());
        s_ukm_otp_style.set("display:none;".to_string());
        s_hide_recovery.set("none".to_string());
        s_button_label.set("Pre-enroll".to_string());
        s_hide_reset.set("none".to_string());
        s_phase.set(PreEnroll);
    }

    if *s_check_phase.read() {
        s_pin.set("".to_string());
        let serial = s_serial.read().clone();
        match serial.parse::<u32>() {
            Ok(yks) => {
                s_pin_style.set("display:table-row;".to_string());
                debug!("Connecting to newly selected YubiKey: {serial}");
                let s = yubikey::Serial(yks);
                let yubikey = match get_yubikey(Some(s)) {
                    Ok(yk) => Some(yk),
                    Err(e) => {
                        error!("Failed to connect to YubiKey with serial {serial} with: {e}");
                        s_fatal_error_val.set(format!("Failed to connect to YubiKey with serial {serial} with: {}. Close the app, make sure one YubiKey is available then try again.", e).to_string());
                        None
                    }
                };

                if let Some(mut yubikey) = yubikey {
                    debug!("Determining phase of newly selected YubiKey: {serial}");
                    match yubikey.authenticate(PB_MGMT_KEY.clone()) {
                        Ok(_) => {
                            let phase = determine_phase(&mut yubikey);
                            if phase != *s_phase.read() {
                                s_phase.set(phase.clone());
                                update_phase(
                                    &phase,
                                    s_edipi_style,
                                    s_pre_enroll_otp_style,
                                    s_ukm_otp_style,
                                    s_hide_recovery,
                                    s_button_label,
                                    s_hide_reset,
                                    s_enroll_otp_style,
                                );
                            }
                        }
                        Err(e) => {
                            let err = format!("The YubiKey with serial number {serial} is not using the expected management key. Please reset the device then try again.");
                            error!("{err}: {e:?}");

                            #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
                            {
                                let (tx, rx) = std::sync::mpsc::channel();
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
                                            let _ = tx.send(None);
                                        } else {
                                            let _ = tx.send(Some(err.to_string()));
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to solicit reset answer from user: {e}");
                                    }
                                }
                                match rx.recv() {
                                    Ok(result) => match result {
                                        Some(err) => {
                                            if 1 == s_serials.len() {
                                                s_fatal_error_val.set(err);
                                            } else {
                                                let serial_str = s_serial.read().clone();
                                                for cur in s_serials.read().iter() {
                                                    if *cur != *serial_str {
                                                        info!("Resetting serial from {serial_str} to {cur}");
                                                        s_serial.set(cur.to_string());
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        None => s_reset_req.set(true),
                                    },
                                    Err(e) => {
                                        let sm = format!("Failed to spawn thread for reset: {e}")
                                            .to_string();
                                        error!("{}", sm);
                                        s_fatal_error_val.set(sm);
                                    }
                                }
                            }

                            #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
                            s_fatal_error_val.write()(err.to_string());
                        }
                    }
                }
            }
            Err(_e) => {
                s_pin_style.set("display:none;".to_string());
                #[cfg(all(target_os = "windows", feature = "vsc"))]
                match determine_vsc_phase(&serial) {
                    Ok(phase) => {
                        if phase != *s_phase.read() {
                            s_phase.set(phase.clone());
                            update_phase(
                                &phase,
                                s_edipi_style,
                                s_pre_enroll_otp_style,
                                s_ukm_otp_style,
                                s_hide_recovery,
                                s_button_label,
                                s_hide_reset,
                                s_enroll_otp_style,
                            );
                        }
                    }
                    Err(_e) => {
                        s_fatal_error_val.set(
                            "Could not determine the state of the VSC named {serial}".to_string(),
                        );
                    }
                };
            }
        };

        s_check_phase.set(false);
    }

    // Non-fatal error handling
    let mut s_error_msg = use_signal(String::new);
    let mut s_success_msg = use_signal(String::new);

    let s_reset_msg = use_signal(String::new);
    if *s_reset_req.read() {
        debug!("Showing reset view");
        if !s_pin.read().is_empty() || !s_puk.read().is_empty() {
            s_pin.set(String::new());
            s_puk.set(String::new());
        }
        reset(
            s_serial,
            s_reset_req,
            s_pin,
            s_puk,
            s_reset_msg,
            s_reset_complete,
            s_disa_icon,
            s_pin_style,
            is_yubikey,
        )
    } else {
        let css = include_str!("../../assets/pbyk.css");

        let copy = s_serials.read().clone();
        let serialRsx = copy.iter().map(|s| {
            rsx! { option {
                    value : "{s}",
                    label : "{s}",
                    selected: if *s_serial.read().clone() == *s {"true"} else {"false"}
                }
            }
        });

        macro_rules! show_message {
            () => {
                if !s_error_msg.read().is_empty() {
                    let _id = toast.write().popup(ToastInfo {
                        heading: Some("ERROR".to_string()),
                        context: s_error_msg.to_string(),
                        allow_toast_close: true,
                        position: dioxus_toast::Position::TopLeft,
                        icon: Some(Icon::Error),
                        hide_after: None,
                    });
                    s_error_msg.set(String::new());
                }
                if !s_success_msg.read().is_empty() {
                    let _id = toast.write().popup(ToastInfo {
                        heading: Some("SUCCESS".to_string()),
                        context: s_success_msg.to_string(),
                        allow_toast_close: true,
                        position: dioxus_toast::Position::TopLeft,
                        icon: Some(Icon::Success),
                        hide_after: None,
                    });
                    s_success_msg.set(String::new());
                }
            };
        }

        rsx! {
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
                                s_error_msg.set(sm.to_string());
                                String::new()
                            }
                        };

                        let p = s_phase.read().clone();

                        macro_rules! enter_enroll_phase {
                                () => {
                                    s_pre_enroll_otp_style.set("display:none;".to_string());
                                    s_enroll_otp_style.set("display:table-row;".to_string());
                                    s_phase.set(Enroll);
                                    s_button_label.set("Enroll".to_string());
                                };
                            }
                        macro_rules! enter_ukm_phase {
                                () => {
                                    s_pre_enroll_otp_style.set("display:none;".to_string());
                                    s_enroll_otp_style.set("display:none;".to_string());
                                    s_edipi_style.set("display:none;".to_string());
                                    s_ukm_otp_style.set("display:table-row;".to_string());
                                    s_phase.set(Ukm);
                                    s_button_label.set("User Key Management".to_string());
                                };
                            }
                        macro_rules! enter_ukm_or_recovery_phase {
                                () => {
                                    s_hide_recovery.set("inline-block".to_string());
                                    s_pre_enroll_otp_style.set("display:none;".to_string());
                                    s_enroll_otp_style.set("display:none;".to_string());
                                    s_edipi_style.set("display:none;".to_string());
                                    s_ukm_otp_style.set("display:table-row;".to_string());
                                    s_phase.set(UkmOrRecovery);
                                    s_button_label.set("User Key Management".to_string());
                                };
                            }

                        let recovery_active = *s_recover.read();
                        let reset_abandoned = *s_reset_abandoned.read();

                        if !reset_abandoned {
                            s_cursor.set("wait".to_string());
                            s_disabled.set(true);
                        }
                        else {
                            s_reset_abandoned.set(false);
                        }

                        #[cfg(all(target_os = "windows", feature = "vsc"))]
                        let mut serial_str_ota = s_serial.read().to_string();
                        #[cfg(not(all(target_os = "windows", feature = "vsc")))]
                        let serial_str_ota = s_serial.read().to_string();

                        let serial_u32 = match s_serial.read().parse::<u32>() {
                            Ok(serial_u32) => Some(serial_u32),
                            Err(e) => {
                                let sm = format!("Failed to process serial number as YubiKey serial number: {e}.");
                                error!("{}", sm);
                                // error_msg_setter(sm.to_string());
                                None
                            }
                        };

                        async move {
                            if reset_abandoned {
                                // if we arrive here due to an aborted reset, just bail out
                                return;
                            }

                            if PB_BASE_URL.is_empty() {
                                // error message is set up in match statement above if environment
                                // is unrecognized and PB_BASE_URL is set to empty
                                // todo revisit
                                s_cursor.set("default".to_string());
                                s_cursor.set("wait".to_string());
                                s_disabled.set(false);
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
                                            error!("{}", sm);
                                            s_error_msg.set(sm.to_string());
                                            s_cursor.set("default".to_string());
                                            s_disabled.set(false);
                                            return;
                                        }
                                    };

                                    if yubikey.authenticate(PB_MGMT_KEY.clone()).is_err() {
                                        let sm = format!("The YubiKey with serial number {} is not using the expected management key. Please reset the device then try again.", yubikey.serial());
                                        error!("{}", sm);
                                        s_error_msg.set(sm.to_string());
                                        s_cursor.set("default".to_string());
                                        s_disabled.set(false);
                                        return;
                                    }

                                    let pin = match string_or_none(&ev, "pin") {
                                        Some(str) => str,
                                        None => {
                                            let sm = format!("No PIN was provided. Please enter the PIN for the YubiKey with serial number {} and try again", yks);
                                            error!("{}", sm);
                                            s_error_msg.set(sm.to_string());
                                            s_cursor.set("default".to_string());
                                            s_disabled.set(false);
                                            return;
                                        }
                                    };
                                    s_pin.set("display:table-row;".to_string());
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
                                                error!("{}", sm);
                                                s_error_msg.set(sm.to_string());
                                                s_cursor.set("default".to_string());
                                                s_disabled.set(false);
                                                return;
                                            }
                                        };
                                        serial_str_ota = match get_vsc_id_from_serial(&vsc_serial) {
                                            Ok(s) => s,
                                            Err(e) => {
                                                let sm = format!("Could not get the VSC ID for VSC with serial number {serial_str_ota}. Error: {e:?}");
                                                error!("{}", sm);
                                                s_error_msg.set(sm.to_string());
                                                s_cursor.set("default".to_string());
                                                s_disabled.set(false);
                                                return;
                                            }
                                        };
                                        s_pin_style.set("display:none;".to_string());
                                        (CryptoModule::SmartCard(vsc), "".to_string())
                                    }
                                    #[cfg(not(all(target_os = "windows", feature = "vsc")))]
                                    {
                                        let sm = "Failed to process serial number as YubiKey serial number.";
                                        error!("{}", sm);
                                        error!("{}", sm);
                                        s_error_msg.set(sm.to_string());
                                        s_cursor.set("default".to_string());
                                        s_disabled.set(false);
                                        return;
                                    }
                                }
                            };

                            // let yks = match serial_u32 {
                            //     Some(serial_u32) => yubikey::Serial(serial_u32),
                            //     None => {
                            //         // error message is set up in match statement above if serial number
                            //         // conversion fails
                            //         *s_cursor.set("default".to_string());
                            //         *s_disabled.set(false);
                            //         return;
                            //     }
                            // };

                            match p {
                                PreEnroll => {
                                    info!("Starting Pre-enroll operation...");
                                    let agent_edipi = match string_or_none(&ev, "edipi") {
                                        Some(agent_edipi) => agent_edipi,
                                        None => {
                                            let sm = "No Agent EDIPI was provided. Please enter the EDIPI of the cooperating Purebred Agent and try again";
                                            error!("{}", sm);
                                            s_error_msg.set(sm.to_string());
                                            s_cursor.set("default".to_string());
                                            s_disabled.set(false);
                                            return;
                                        }
                                    };
                                    let pre_enroll_otp = match string_or_none(&ev, "pre_enroll_otp") {
                                        Some(pre_enroll_otp) => {
                                            if !pre_enroll_otp.chars().all(|c| c.is_numeric()) || 8 != pre_enroll_otp.len() {
                                                let sm = "OTP values MUST be exactly 8 characters long and only contain numeric values.";
                                                error!("{}", sm);
                                                s_error_msg.set(sm.to_string());
                                                s_cursor.set("default".to_string());
                                                s_disabled.set(false);
                                                return;
                                            }
                                            pre_enroll_otp
                                        },
                                        None => {
                                            let sm = "No pre-enroll OTP was provided. Please enter a pre-enroll OTP and try again";
                                            error!("{}", sm);
                                            s_error_msg.set(sm.to_string());
                                            s_cursor.set("default".to_string());
                                            s_disabled.set(false);
                                            return;
                                        }
                                    };
                                    if check_otp(&pre_enroll_otp) {
                                        let sm = "OTP values MUST NOT be reused. Please obtain a fresh OTP and try again.";
                                        error!("{}", sm);
                                        s_error_msg.set(sm.to_string());
                                        s_cursor.set("default".to_string());
                                        s_disabled.set(false);
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
                                    s_pin.set(pin);
                                    let agent_edipi_t = agent_edipi.clone();
                                    s_edipi.set(agent_edipi);
                                    //let mut cm = CryptoModule::YubiKey(yubikey);
                                    let _ = tokio::spawn(async move {
                                        match pre_enroll(
                                            &mut cm,
                                            &agent_edipi_t,
                                            &pre_enroll_otp,
                                            &PB_BASE_URL,
                                            pin_t,
                                            Some(&PB_MGMT_KEY.clone())
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
                                                s_hash.set(hash.clone());
                                                enter_enroll_phase!();
                                            }
                                            else {
                                                s_error_msg.set(result.1.unwrap_or_default());
                                            }
                                        }
                                        Err(e) => {
                                            let sm = format!("Failed to spawn thread for pre-enrollment: {e}").to_string();
                                            error!("{}", sm);
                                            s_error_msg.set(sm.to_string());
                                        }
                                    }
                                    s_cursor.set("default".to_string());
                                    s_disabled.set(false);
                                }
                                Enroll => {
                                    info!("Starting Enroll operation...");
                                    let agent_edipi = match string_or_none(&ev, "edipi") {
                                        Some(agent_edipi) => agent_edipi,
                                        None => {
                                            let sm = "No Agent EDIPI was provided. Please enter the EDIPI of the cooperating Purebred Agent and try again";
                                            error!("{}", sm);
                                            s_error_msg.set(sm.to_string());
                                            s_cursor.set("default".to_string());
                                            s_disabled.set(false);
                                            return;
                                        }
                                    };
                                    let enroll_otp = match string_or_none(&ev, "enroll_otp") {
                                        Some(enroll_otp) => {
                                            if !enroll_otp.chars().all(|c| c.is_numeric()) || 8 != enroll_otp.len() {
                                                let sm = "OTP values MUST be exactly 8 characters long and only contain numeric values.";
                                                error!("{}", sm);
                                                s_error_msg.set(sm.to_string());
                                                s_cursor.set("default".to_string());
                                                s_disabled.set(false);
                                                return;
                                            }
                                            enroll_otp
                                        },
                                        None => {
                                            let sm = "No enroll OTP was provided. Please enter an enroll OTP and try again";
                                            error!("{}", sm);
                                            s_error_msg.set(sm.to_string());
                                            s_cursor.set("default".to_string());
                                            s_disabled.set(false);
                                            return;
                                        }
                                    };
                                    if check_otp(&enroll_otp) {
                                        let sm = "OTP values MUST NOT be reused. Please obtain a fresh OTP and try again.";
                                        error!("{}", sm);
                                        s_error_msg.set(sm.to_string());
                                        s_cursor.set("default".to_string());
                                        s_disabled.set(false);
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
                                    s_pin.set(pin);
                                    let oai = OtaActionInputs::new(
                                        &serial_str_ota,
                                        &enroll_otp,
                                        &PB_BASE_URL.to_string(),
                                        &app,
                                    );
                                    //let mut cm = CryptoModule::YubiKey(yubikey);
                                    let _ = tokio::spawn(async move {
                                        match enroll(
                                            &mut cm,
                                            &agent_edipi,
                                            &oai,
                                            pin_t,
                                            Some(&PB_MGMT_KEY.clone()),
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
                                                s_error_msg.set(error.to_string());
                                            }
                                            else {
                                                enter_ukm_phase!();
                                            }
                                        }
                                        Err(e) => {
                                            let sm = format!("Failed to spawn thread for enrollment: {e}").to_string();
                                            error!("{}", sm);
                                            s_error_msg.set(sm.to_string());
                                        }
                                    }
                                    s_cursor.set("default".to_string());
                                    s_disabled.set(false);
                                }
                                Ukm | UkmOrRecovery => {
                                    info!("Ukm | UkmOrRecovery");
                                    // handle remaining phases (i.e., Ukm or UkmOrRecovery) with recover checkbox as governor
                                    let ukm_otp = match string_or_none(&ev, "ukm_otp") {
                                        Some(ukm_otp) => {
                                            if !ukm_otp.chars().all(|c| c.is_numeric()) || 8 != ukm_otp.len() {
                                                let sm = "OTP values MUST be exactly 8 characters long and only contain numeric values.";
                                                error!("{}", sm);
                                                s_error_msg.set(sm.to_string());
                                                s_cursor.set("default".to_string());
                                                s_disabled.set(false);
                                                return;
                                            }
                                            ukm_otp
                                        },
                                        None => {
                                            let sm = "No UKM OTP was provided. Please enter a UKM OTP and try again";
                                            error!("{}", sm);
                                            s_error_msg.set(sm.to_string());
                                            s_cursor.set("default".to_string());
                                            s_disabled.set(false);
                                            return;
                                        }
                                    };
                                    if check_otp(&ukm_otp) {
                                        let sm = "OTP values MUST NOT be reused. Please obtain a fresh OTP and try again.";
                                        error!("{}", sm);
                                        s_error_msg.set(sm.to_string());
                                        s_cursor.set("default".to_string());
                                        s_disabled.set(false);
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
                                        s_recover.set(false);
                                        info!("Starting recover operation...");
                                        let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
                                        let pin_t = if !pin.is_empty() {
                                            Some(Zeroizing::new(pin.clone()))
                                        }
                                        else {
                                            None
                                        };
                                        s_pin.set(pin);
                                        //let mut cm = CryptoModule::YubiKey(yubikey);
                                        let _ = tokio::spawn(async move {
                                            match recover(&mut cm, &oai, pin_t, Some(&PB_MGMT_KEY.clone()), &environment).await {
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
                                                    s_error_msg.set(error.to_string());
                                                }
                                                else {
                                                    s_recover.set(false);
                                                    s_success_msg.set("Recover completed successfully".to_string());
                                                }
                                            }
                                            Err(e) => {
                                                let sm = format!("Failed to spawn thread for recover: {e}").to_string();
                                                error!("{}", sm);
                                                s_error_msg.set(sm.to_string());
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
                                        s_pin.set(pin);
                                        //let mut cm = CryptoModule::YubiKey(yubikey);
                                        let _ = tokio::spawn(async move {
                                            match ukm(&mut cm, &oai, pin_t, Some(&PB_MGMT_KEY.clone()), &environment).await {
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
                                                    s_error_msg.set(error);
                                                }
                                                else {
                                                    enter_ukm_or_recovery_phase!();
                                                    s_success_msg.set("UKM completed successfully".to_string());
                                                }
                                            }
                                            Err(e) => {
                                                let sm = format!("Failed to spawn thread for UKM: {e}").to_string();
                                                error!("{}", sm);
                                                s_error_msg.set(sm.to_string());
                                            }
                                        }
                                    }
                                    s_cursor.set("default".to_string());
                                    s_disabled.set(false);
                                }
                             }// end match phase
                            show_message!();
                        } // end async move
                    }, // end onsubmit
                    table {
                        class: "{s_cursor}",
                        tbody {
                            tr{
                                style: if *s_phase.read() != Enroll { "display:table-row;" } else {"display:none;"},
                                td{div{label {r#for: "multi_serial", "Serial Number"}}}
                                td{select {
                                   disabled: "{s_disabled}",
                                   oninput: move |evt| {
                                       s_serial.set(evt.value().to_string());
                                       s_check_phase.set(true);
                                   },
                                   name: "serials", value: "{s_serial}",
                                   {serialRsx}
                                }}
                            }
                            tr{
                                style: if *s_phase.read() == Enroll { "display:table-row;" } else {"display:none;"},
                                td{div{label {r#for: "serial", "Serial Number"}}}
                                td{input { r#type: "text", disabled: "{s_disabled}", name: "serial", readonly: true, value: "{s_serial}"}}
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
                                style: "{s_pin_style}",
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
                                        td{input { disabled: "{s_disabled}", r#type: "radio", id: "dev", name: "environment", value: "DEV", onclick: move |_| {s_edipi.set( "".to_string());}, checked: "{s_dev_checked}" } }
                                        td{div{label {r#for: "dev", "Development"}}}
                                    }
                                    tr {
                                        style: "{s_om_nipr_style}",
                                        td{input { disabled: "{s_disabled}", r#type: "radio", id: "om_nipr", name: "environment", value: "OM_NIPR", onclick: move |_| {s_edipi.set( "".to_string());}, checked: "{s_om_nipr_checked}" } }
                                        td{div{label {r#for: "om_nipr", "NIPR O&M"}}}
                                    }
                                    tr {
                                        style: "{s_nipr_style}",
                                        td{input { disabled: "{s_disabled}", r#type: "radio", id: "nipr", name: "environment", value: "NIPR", onclick: move |_| {s_edipi.set( "".to_string());}, checked: "{s_nipr_checked}" } }
                                        td{div{label {r#for: "nipr", "NIPR"}}}
                                    }
                                    tr {
                                        style: "{s_om_sipr_style}",
                                        td{input { disabled: "{s_disabled}", r#type: "radio", id: "om_sipr", name: "environment", value: "OM_SIPR", onclick: move |_| {s_edipi.set( "".to_string());}, checked: "{s_om_sipr_checked}" } }
                                        td{div{label {r#for: "om_sipr", "SIPR O&M"}}}
                                    }
                                    tr {
                                        style: "{s_sipr_style}",
                                        td{input { disabled: "{s_disabled}", r#type: "radio", id: "sipr", name: "environment", value: "SIPR", onclick: move |_| {s_edipi.set( "".to_string());}, checked: "{s_sipr_checked}", }}
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
                                button { disabled: "{s_disabled}", r#type: "submit", onclick: move |_| s_recover.set(true), value: "Recovery", "Recover Old Decryption Keys" }
                            }
                        }
                        div{
                            style: "text-align:center; display: {s_hide_reset}; margin-right:5px;",
                            button { disabled: "{s_disabled}", value: "Reset",
                                onclick: move |_| {
                                    s_success_msg.set(String::new());
                                    s_error_msg.set(String::new());

                                    #[cfg(all(target_os = "windows", feature = "vsc", feature = "reset_vsc"))]
                                    let reset_supported = true;
                                    #[cfg(not(all(target_os = "windows", feature = "vsc", feature = "reset_vsc")))]
                                    let reset_supported = *s_pin_style.read() == "display:table-row;";
                                    if !reset_supported {
                                        s_reset_abandoned.set(true);
                                        s_error_msg.set("VSC reset support is not provided".to_string());
                                        show_message!();
                                        return;
                                    }

                                    use native_dialog::{MessageDialog, MessageType};
                                    let msg = format!("Are you sure you want to reset the device with serial number {s_serial} now?");
                                    match MessageDialog::new()
                                        .set_type(MessageType::Info)
                                        .set_title("Reset?")
                                        .set_text(&msg)
                                        .show_confirm()
                                    {
                                        Ok(answer) => {
                                            if answer {
                                                s_reset_abandoned.set(false);
                                                s_reset_req.set(true);
                                            }
                                            else {
                                                s_reset_abandoned.set(true);
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
                                // let click_count_setter = s_click_count.write();
                                // let click_start_setter = s_click_start.write();
                                // #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
                                // let hide_reset_setter = s_hide_reset.write();

                                let last_count = *s_click_count.read();
                                let last_start = *s_click_start.read();
                                let disabled = *s_disabled.read();
                                match SystemTime::now().duration_since(UNIX_EPOCH) {
                                    Ok(n) => {
                                        #[cfg(all(target_os = "windows", feature = "vsc", feature = "reset_vsc"))]
                                        let reset_supported = true;
                                        #[cfg(not(all(target_os = "windows", feature = "vsc", feature = "reset_vsc")))]
                                        let reset_supported = *s_pin_style.read() == "display:table-row;";

                                        if !disabled && reset_supported {
                                            let secs = n.as_secs();
                                            if secs - last_start > 5 {
                                                s_click_count.set(1);
                                                s_click_start.set(secs);
                                            } else if last_count >= 4 {
                                                #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
                                                {
                                                    s_hide_reset.set("inline-block".to_string());
                                                }
                                            }
                                            else {
                                                s_click_count.set(last_count+1);
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
        }
    }
}
