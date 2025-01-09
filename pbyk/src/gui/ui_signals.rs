//! Structure to contain signals primarily associated with UI rendering
//!
use crate::args::num_environments;
use crate::gui::app_signals::AppSignals;
use crate::gui::gui_main::Phase::{Enroll, PreEnroll, Ukm, UkmOrRecovery};
#[cfg(all(target_os = "windows", feature = "vsc", feature = "reset_vsc"))]
use crate::gui::utils::parse_reader_from_vsc_display;
use crate::gui::utils::{get_default_env_radio_selections, read_saved_args_or_default};
use base64ct::{Base64, Encoding};
use dioxus::hooks::use_signal;
use dioxus::prelude::Signal;
use dioxus::signals::{Readable, Writable};
use dioxus_toast::ToastManager;
use log::error;
use pbyklib::utils::get_pre_enroll_hash_yubikey;
use std::fmt::Display;
use std::sync::LazyLock;

#[cfg(all(target_os = "windows", feature = "vsc", feature = "reset_vsc"))]
use pbyklib::utils::get_pre_enroll_hash;

static DISA_ICON_BASE64: LazyLock<String> =
    LazyLock::new(|| Base64::encode_string(include_bytes!("../../assets/disa.png")));

pub struct UiSignals {
    pub toast: Signal<ToastManager>,
    pub s_disa_icon: Signal<String>,
    pub s_edipi: Signal<String>,
    pub s_pin: Signal<String>,
    pub s_puk: Signal<String>,
    pub s_pre_enroll_otp: Signal<String>,
    pub s_enroll_otp: Signal<String>,
    pub s_hash: Signal<String>,
    pub s_ukm_otp: Signal<String>,
    pub s_recover: Signal<bool>,
    pub s_dev_checked: Signal<bool>,
    pub s_om_nipr_checked: Signal<bool>,
    pub s_om_sipr_checked: Signal<bool>,
    pub s_nipr_checked: Signal<bool>,
    pub s_sipr_checked: Signal<bool>,
    pub s_check_phase: Signal<bool>,
    pub s_cursor: Signal<String>,
    pub s_disabled: Signal<bool>,
    pub s_reset_abandoned: Signal<bool>,
    pub s_reset_complete: Signal<bool>,
    pub s_click_count: Signal<i32>,
    pub s_click_start: Signal<u64>,
    pub s_hide_reset: Signal<String>,
    pub s_pin_style: Signal<String>,
    pub s_edipi_style: Signal<String>,
    pub s_pre_enroll_otp_style: Signal<String>,
    pub s_ukm_otp_style: Signal<String>,
    pub s_hide_recovery: Signal<String>,
    pub s_button_label: Signal<String>,
    pub s_enroll_otp_style: Signal<String>,
    pub s_multi_env_style: Signal<String>,
    pub s_dev_style: Signal<String>,
    pub s_om_nipr_style: Signal<String>,
    pub s_om_sipr_style: Signal<String>,
    pub s_nipr_style: Signal<String>,
    pub s_sipr_style: Signal<String>,
    pub s_error_msg: Signal<String>,
    pub s_success_msg: Signal<String>,
    pub s_reset_msg: Signal<String>,
}

impl Display for UiSignals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // write!(f, "s_disa_icon: {:?}; ", self.s_disa_icon)?;
        write!(f, "s_edipi: {:?}; ", self.s_edipi)?;
        write!(f, "s_pin: {:?}; ", self.s_pin)?;
        write!(f, "s_puk: {:?}; ", self.s_puk)?;
        write!(f, "s_pre_enroll_otp: {:?}; ", self.s_pre_enroll_otp)?;
        write!(f, "s_enroll_otp: {:?}; ", self.s_enroll_otp)?;
        write!(f, "s_hash: {:?}; ", self.s_hash)?;
        write!(f, "s_ukm_otp: {:?}; ", self.s_ukm_otp)?;
        write!(f, "s_recover: {:?}; ", self.s_recover)?;
        write!(f, "s_dev_checked: {:?}; ", self.s_dev_checked)?;
        write!(f, "s_om_nipr_checked: {:?}; ", self.s_om_nipr_checked)?;
        write!(f, "s_om_sipr_checked: {:?}; ", self.s_om_sipr_checked)?;
        write!(f, "s_nipr_checked: {:?}; ", self.s_nipr_checked)?;
        write!(f, "s_sipr_checked: {:?}; ", self.s_sipr_checked)?;
        write!(f, "s_check_phase: {:?}; ", self.s_check_phase)?;
        write!(f, "s_cursor: {:?}; ", self.s_cursor)?;
        write!(f, "s_disabled: {:?}; ", self.s_disabled)?;
        write!(f, "s_reset_abandoned: {:?}; ", self.s_reset_abandoned)?;
        write!(f, "s_reset_complete: {:?}; ", self.s_reset_complete)?;
        write!(f, "s_click_count: {:?}; ", self.s_click_count)?;
        write!(f, "s_click_start: {:?}; ", self.s_click_start)?;
        write!(f, "s_hide_reset: {:?}; ", self.s_hide_reset)?;
        write!(f, "s_pin_style: {:?}; ", self.s_pin_style)?;
        write!(f, "s_edipi_style: {:?}; ", self.s_edipi_style)?;
        write!(
            f,
            "s_pre_enroll_otp_style: {:?}; ",
            self.s_pre_enroll_otp_style
        )?;
        write!(f, "s_ukm_otp_style: {:?}; ", self.s_ukm_otp_style)?;
        write!(f, "s_hide_recovery: {:?}; ", self.s_hide_recovery)?;
        write!(f, "s_button_label: {:?}; ", self.s_button_label)?;
        write!(f, "s_enroll_otp_style: {:?}; ", self.s_enroll_otp_style)?;
        write!(f, "s_multi_env_style: {:?}; ", self.s_multi_env_style)?;
        write!(f, "s_dev_style: {:?}; ", self.s_dev_style)?;
        write!(f, "s_om_nipr_style: {:?}; ", self.s_om_nipr_style)?;
        write!(f, "s_om_sipr_style: {:?}; ", self.s_om_sipr_style)?;
        write!(f, "s_nipr_style: {:?}; ", self.s_nipr_style)?;
        write!(f, "s_sipr_style: {:?}; ", self.s_sipr_style)?;
        write!(f, "s_error_msg: {:?}; ", self.s_error_msg)?;
        write!(f, "s_success_msg: {:?}; ", self.s_success_msg)?;
        write!(f, "s_reset_msg: {:?}", self.s_reset_msg)?;
        Ok(())
    }
}

impl UiSignals {
    pub fn init(app_signals: &AppSignals, is_yubikey: bool, error_msg: Option<String>) -> Self {
        let toast = use_signal(ToastManager::default);

        let s_disa_icon = use_signal(|| DISA_ICON_BASE64.clone());

        // State variables for input fields
        let s_edipi = use_signal(|| {
            // Only saved element at present is agent edipi
            let sa = read_saved_args_or_default();
            let tmp = sa.agent_edipi.unwrap_or_default();
            tmp.trim().to_string()
        });
        let s_pin = use_signal(String::new);
        let s_puk = use_signal(String::new);
        let s_pre_enroll_otp = use_signal(String::new);
        let s_enroll_otp = use_signal(String::new);
        let mut s_hash = use_signal(String::new);
        let s_ukm_otp = use_signal(String::new);
        let s_recover = use_signal(|| false);
        let (b_dev, b_om_nipr, b_om_sipr, b_nipr, b_sipr) = get_default_env_radio_selections();

        let s_dev_checked = use_signal(|| b_dev);
        let s_om_nipr_checked = use_signal(|| b_om_nipr);
        let s_om_sipr_checked = use_signal(|| b_om_sipr);
        let s_nipr_checked = use_signal(|| b_nipr);
        let s_sipr_checked = use_signal(|| b_sipr);

        let s_check_phase = use_signal(|| false);

        // Style variables for enabling/disabling UI elements. One governs the cursor. The other governs
        // elements that benefit from disabling, i.e., clickable elements and editable elements. Read-only
        // elements are not changed based on app state.
        let s_cursor = use_signal(|| "default".to_string());
        let s_disabled = use_signal(|| false);

        let s_reset_abandoned = use_signal(|| false);
        let s_reset_complete = use_signal(|| false);

        // icon click variables
        let s_click_count = use_signal(|| 0);
        let s_click_start = use_signal(|| 0u64);
        let s_hide_reset = use_signal(|| "none".to_string());

        // Style variables for impermanent UI elements
        let s_pin_style = use_signal(|| {
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
        ) = match *app_signals.s_phase.read() {
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

        let s_edipi_style = use_signal(|| str_edipi_style);
        let s_pre_enroll_otp_style = use_signal(|| str_pre_enroll_otp_style);
        let s_ukm_otp_style = use_signal(|| str_ukm_otp_style);
        let s_hide_recovery = use_signal(|| str_hide_recovery);
        let s_button_label = use_signal(|| str_button_label);
        let s_enroll_otp_style = use_signal(|| str_enroll_otp_style);

        if *app_signals.s_phase.read() == Enroll && s_hash.read().is_empty() {
            if is_yubikey {
                match get_pre_enroll_hash_yubikey(&app_signals.s_serial.read()) {
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
                    let vsc_serial = parse_reader_from_vsc_display(&app_signals.s_serial.read());
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
            "display:none;".to_string()
        } else {
            "display:table-row;".to_string()
        };
        let s_multi_env_style = use_signal(|| str_multi_env_style);

        #[cfg(feature = "dev")]
        let s_dev_style = use_signal(|| "display:table-row;".to_string());
        #[cfg(not(feature = "dev"))]
        let s_dev_style = use_signal(|| "display:none;".to_string());

        #[cfg(feature = "om_nipr")]
        let s_om_nipr_style = use_signal(|| "display:table-row;".to_string());
        #[cfg(not(feature = "om_nipr"))]
        let s_om_nipr_style = use_signal(|| "display:none;".to_string());

        #[cfg(feature = "om_sipr")]
        let s_om_sipr_style = use_signal(|| "display:table-row;".to_string());
        #[cfg(not(feature = "om_sipr"))]
        let s_om_sipr_style = use_signal(|| "display:none;".to_string());

        #[cfg(feature = "nipr")]
        let s_nipr_style = use_signal(|| "display:table-row;".to_string());
        #[cfg(not(feature = "nipr"))]
        let s_nipr_style = use_signal(|| "display:none;".to_string());

        #[cfg(feature = "sipr")]
        let s_sipr_style = use_signal(|| "display:table-row;".to_string());
        #[cfg(not(feature = "sipr"))]
        let s_sipr_style = use_signal(|| "display:none;".to_string());

        // Non-fatal error handling
        let s_error_msg = use_signal(|| error_msg.unwrap_or_default());
        let s_success_msg = use_signal(String::new);

        let s_reset_msg = use_signal(String::new);

        UiSignals {
            toast,
            s_disa_icon,
            s_edipi,
            s_pin,
            s_puk,
            s_pre_enroll_otp,
            s_enroll_otp,
            s_hash,
            s_ukm_otp,
            s_recover,
            s_dev_checked,
            s_om_nipr_checked,
            s_om_sipr_checked,
            s_nipr_checked,
            s_sipr_checked,
            s_check_phase,
            s_cursor,
            s_disabled,
            s_reset_abandoned,
            s_reset_complete,
            s_click_count,
            s_click_start,
            s_hide_reset,
            s_pin_style,
            s_edipi_style,
            s_pre_enroll_otp_style,
            s_ukm_otp_style,
            s_hide_recovery,
            s_button_label,
            s_enroll_otp_style,
            s_multi_env_style,
            s_dev_style,
            s_om_nipr_style,
            s_om_sipr_style,
            s_nipr_style,
            s_sipr_style,
            s_error_msg,
            s_success_msg,
            s_reset_msg,
        }
    }
}
