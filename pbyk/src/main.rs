#![doc = include_str!("../README.md")]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
// unsafe is permitted on windows to allow hiding the terminal window in GUI mode
#![cfg_attr(not(target_os = "windows"), allow(unsafe_code))]

// commented out when GUI mode was added, can likely be deleted entirely
//#![windows_subsystem = "windows"]

#[macro_use]
extern crate cfg_if;

use clap::{CommandFactory, Parser};

#[cfg(target_os = "windows")]
use crate::no_bold::NoBold;
#[cfg(not(target_os = "windows"))]
use colored::Colorize;
#[cfg(feature = "gui")]
use dioxus_desktop::tao::menu::{MenuBar, MenuItem};

#[cfg(feature = "gui")]
use dioxus_desktop::tao::window::Icon;

use pbyklib::{
    ota::{enroll, pre_enroll, recover, ukm, OtaActionInputs},
    utils::{
        get_yubikey, list_yubikeys, num_yubikeys, portal_status_check, reset_yubikey, scep_check,
    },
    Error, PB_MGMT_KEY,
};

mod args;
use args::{num_environments, Environment, PbYkArgs};

#[cfg(feature = "gui")]
mod gui;
#[cfg(target_os = "windows")]
mod no_bold;
mod utils;

#[cfg(feature = "gui")]
use crate::gui::utils::{get_default_env, read_saved_window_size};
use utils::configure_logging;

/// Confirms provided arguments include at least one Action, Diagnostic or Utility argument
fn sanity_check(args: &PbYkArgs) -> bool {
    if !args.portal_status_check
        && !args.scep_check
        && !args.list_yubikeys
        && !args.reset_yubikey
        && args.pre_enroll_otp.is_none()
        && args.enroll_otp.is_none()
        && args.ukm_otp.is_none()
        && args.recover_otp.is_none()
    {
        println!(
            "{}: at least one Action, Diagnostic or Utility argument must be provided\n",
            "ERROR".bold()
        );
        let _ = PbYkArgs::command().print_help();
        false
    } else {
        true
    }
}

/// Confirms only logging arguments are provided when running as GUI app.
#[cfg(feature = "gui")]
fn gui_sanity_check(args: &PbYkArgs) -> bool {
    if !args.interactive
        && (args.portal_status_check
            || args.scep_check
            || args.agent_edipi.is_some()
            || args.serial.is_some()
            || args.environment.is_some()
            || args.list_yubikeys
            || args.reset_yubikey
            || args.pre_enroll_otp.is_some()
            || args.enroll_otp.is_some()
            || args.ukm_otp.is_some()
            || args.recover_otp.is_some())
    {
        println!(
            "{}: only logging options may be provided when running as a GUI app. Use --interactive to run as a command line app\n",
            "ERROR".bold()
        );
        let _ = PbYkArgs::command().print_help();
        false
    } else {
        true
    }
}

cfg_if! {
    if #[cfg(feature = "gui")] {
        use crate::gui::gui_main::*;
        use dioxus_desktop::Config;
        use dioxus_desktop::WindowBuilder;
        /// Point of entry for `pbyk` application.
        ///
        /// See [PbYkArgs] for usage details.
        fn main() {
            use std::env;
            let e = env::args_os();
            let mut show_gui = true;
            if 1 != e.len() {
                let args = PbYkArgs::parse();
                if !gui_sanity_check(&args) {
                    return;
                }

                if !args.interactive {
                    configure_logging(&args);
                }
                else {
                    show_gui = false;
                }
            }

            if show_gui {
                #[cfg(target_os = "windows")]
                hide_console_window();

                let icon_bytes = include_bytes!("../assets/keys-arrow-256.ico");
                let icon = Icon::from_rgba(icon_bytes.to_vec(), 256, 256).unwrap();

                let sws = read_saved_window_size();

                let title = if 1 == num_environments() {
                    format!("Purebred/YubiKey (pbyk) v{} - {}", env!("CARGO_PKG_VERSION"), get_default_env())
                }
                else {
                    format!("Purebred/YubiKey (pbyk) v{}", env!("CARGO_PKG_VERSION"))
                };

                // TODO: add means of determining what max height ought be (i.e., based on number of
                // available environments).
                let window = WindowBuilder::new().with_resizable(true)
                                .with_title(title).with_window_icon(Some(icon))
                                .with_inner_size(dioxus_desktop::LogicalSize::new(sws.width, sws.height),).with_menu({
                                let mut menu = MenuBar::new();

                                let mut app_menu = MenuBar::new();
                                app_menu.add_native_item(MenuItem::Minimize);
                                app_menu.add_native_item(MenuItem::Quit);

                                menu.add_submenu("&pbyk", true, app_menu);
                                menu
                            });
                let config = Config::new().with_window(window);
                dioxus_desktop::launch_cfg(GuiMain, config,);
            }
            else {
                match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                    Ok(rt) => {rt.block_on(async { interactive_main().await; })}
                    Err(e) => {
                        let err = format!("Failed to create runtime: {e}");
                        log::error!("{}", err);
                        println!("ERROR: {err}");
                        std::process::exit(-1)
                    }
                }
            }
        }
    }
    else {
        /// Point of entry for `pbyk` application.
        ///
        /// See [PbYkArgs] for usage details.
        #[tokio::main]
        async fn main() {
            interactive_main().await;
        }
    }
}

// poached from <https://github.com/DioxusLabs/dioxus/blob/544ca5559654c8490ce444c3cbd85c1bfb8479da/packages/desktop/src/cfg.rs#L177>
// dirty trick, avoid introducing `image` at runtime
// #[test]
// #[ignore]
// fn prepare_default_icon() {
//     use image::io::Reader as ImageReader;
//     use image::ImageFormat;
//     use std::fs::File;
//     use std::io::Cursor;
//     use std::io::Write;
//     use std::path::PathBuf;
//     let png: &[u8] = include_bytes!("../assets/keys-arrow-256.png");
//     let mut reader = ImageReader::new(Cursor::new(png));
//     reader.set_format(ImageFormat::Png);
//     let icon = reader.decode().unwrap();
//     let y = std::env::current_dir().unwrap();
//     let bin = PathBuf::from(y).join("assets").join("keys-arrow-256.ico");
//     println!("{:?}", bin);
//     let mut file = File::create(bin).unwrap();
//     file.write_all(icon.as_bytes()).unwrap();
//     println!("({}, {})", icon.width(), icon.height())
// }

/// `interactive_main` provides the command line interface for the application when built as a
/// command line-only utility or when built as a GUI application but run using the \-\-interactive
/// option.
///
/// See [PbYkArgs] for usage details.
async fn interactive_main() {
    use yubikey::Serial;

    let mut args = PbYkArgs::parse();
    configure_logging(&args);

    let app = format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    if !sanity_check(&args) {
        return;
    }

    // ----------------------------------------------------------------------------------
    // operations that are independent of environment (utilities)
    //  - list_yubikeys
    //  - reset_yubikey
    // ----------------------------------------------------------------------------------
    if args.list_yubikeys {
        match list_yubikeys() {
            Ok(readers) => {
                for reader in readers {
                    println!(
                        "{}: {}; {}: {}",
                        "Name".bold(),
                        reader.name(),
                        "Serial".bold(),
                        reader.serial()
                    );
                }
            }
            Err(e) => {
                println!("{}: failed to detect YubiKeys: {e}", "ERROR".bold());
            }
        }
        return;
    }

    if args.serial.is_none() && !args.portal_status_check && !args.scep_check {
        // if there's only one YubiKey present, read its serial number and use it.
        // if there's more than one YubiKey present, set list_yubikeys to true and admonish user to specific a serial number
        let count = match num_yubikeys() {
            Ok(c) => c,
            Err(e) => {
                println!("{}: failed to detect YubiKeys: {e}", "ERROR".bold());
                return;
            }
        };
        if 1 == count {
            let list = match list_yubikeys() {
                Ok(list) => list,
                Err(e) => {
                    println!("{}: no --serial argument was provided and failed to detect any available YubiKeys: {e}", "ERROR".bold());
                    return;
                }
            };
            match list.first() {
                Some(yk) => args.serial = Some(yk.serial().to_string()),
                None => {
                    println!("{}: no --serial argument was provided and failed to read serial number of an available YubiKey", "ERROR".bold());
                    return;
                }
            };
        } else {
            args.list_yubikeys = true;
            println!("{}: more than one YubiKey was detected but no --serial argument was provided. Please try again providing a --serial argument corresponding to an available YubiKey or when only one YubiKey is available.", "ERROR".bold());
            return;
        }
    }

    let serial = match &args.serial {
        Some(serial) => match serial.parse::<u32>() {
            Ok(s) => Some(Serial(s)),
            Err(e) => {
                println!("ERROR: failed to parse serial number: {:?}", e);
                return;
            }
        },
        None => None,
    };

    if args.reset_yubikey {
        let mut yubikey = match get_yubikey(serial) {
            Ok(yk) => yk,
            Err(e) => {
                println!("{}: {:?}", "ERROR".bold(), e);
                return;
            }
        };

        println!(
            "Starting reset of YubiKey with serial number {}. Use Ctrl+C to cancel.",
            yubikey.serial()
        );

        // The rules below are culled from here: https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html
        let pin = loop {
            let pin = rpassword::prompt_password(
                format!(
                    "{}: ",
                    "Enter new PIN; PINs must contain 6 to 8 ASCII characters".bold()
                )
                .to_string(),
            )
            .unwrap();
            let pin2 =
                rpassword::prompt_password(format!("{}: ", "Re-enter new PIN".bold()).to_string())
                    .unwrap();
            if pin != pin2 {
                println!("{}: PINs do not match", "ERROR".bold());
            } else if pin.len() < 6 {
                println!("{}: PIN is not at least 6 characters long", "ERROR".bold());
            } else if pin.len() > 8 {
                println!("{}: PIN is longer than 8 characters long", "ERROR".bold());
            } else if !pin.is_ascii() {
                println!("{}: PIN contains non-ASCII characters", "ERROR".bold());
            } else {
                break pin;
            }
        };
        let puk = loop {
            let puk = rpassword::prompt_password(
                format!(
                    "{}: ",
                    "Enter new PIN Unlock Key (PUK); PUKs must be 6 to 8 bytes in length".bold()
                )
                .to_string(),
            )
            .unwrap();
            let puk2 = rpassword::prompt_password(
                format!("{}: ", "Re-enter new PIN Unlock Key (PUK)".bold()).to_string(),
            )
            .unwrap();
            if puk != puk2 {
                println!("{}: PUKs do not match", "ERROR".bold());
            } else if puk.len() < 6 {
                println!("{}: PUK is not at least 6 characters long", "ERROR".bold());
            } else if puk.len() > 8 {
                println!("{}: PUK is longer than 8 characters long", "ERROR".bold());
            } else {
                break puk;
            }
        };
        // comment out above two loops and uncomment below to run in debugger
        // let pin = "123456".to_string();
        // let puk = "12345678".to_string();

        if let Err(e) = reset_yubikey(&mut yubikey, &pin, &puk, &PB_MGMT_KEY) {
            println!("{}: reset failed with: {e}", "ERROR".bold());
        }
        return;
    }

    // ----------------------------------------------------------------------------------
    // operations that require an environment but no YubiKey (diagnostics)
    //  - portal_status_check
    // ----------------------------------------------------------------------------------
    if args.environment.is_none() && num_environments() > 1 {
        println!(
            "{}: you must specify an --environment value",
            "ERROR".bold()
        );
        return;
    } else if args.environment.is_none() {
        #[cfg(feature = "dev")]
        {
            args.environment = Some(Environment::DEV);
        }
        #[cfg(feature = "om_nipr")]
        {
            args.environment = Some(Environment::OM_NIPR);
        }
        #[cfg(feature = "om_sipr")]
        {
            args.environment = Some(Environment::OM_SIPR);
        }
        #[cfg(feature = "nipr")]
        {
            args.environment = Some(Environment::NIPR);
        }
        #[cfg(feature = "sipr")]
        {
            args.environment = Some(Environment::SIPR);
        }
    }

    let env = match &args.environment {
        Some(x) => x.to_string(),
        _ => {
            println!("{}: unrecognized environment", "ERROR".bold());
            return;
        }
    };

    let pb_base_url = match args.environment {
        #[cfg(feature = "dev")]
        Some(Environment::DEV) => "https://pb2.redhoundsoftware.net".to_string(),
        #[cfg(feature = "om_nipr")]
        Some(Environment::OM_NIPR) => "https://purebred.c3pki.oandm.disa.mil".to_string(),
        #[cfg(feature = "om_sipr")]
        Some(Environment::OM_SIPR) => "https://purebred.snipr.disa.mil".to_string(),
        #[cfg(feature = "nipr")]
        Some(Environment::NIPR) => "https://purebred.csd.disa.mil".to_string(),
        #[cfg(feature = "sipr")]
        Some(Environment::SIPR) => "https://purebred.csd.disa.smil.mil".to_string(),
        _ => {
            println!("{}: unrecognized environment", "ERROR".bold());
            return;
        }
    };

    let ca_base_url = match args.environment {
        #[cfg(feature = "dev")]
        Some(Environment::DEV) => "https://ee-sw-ca-53.redhoundsoftware.net".to_string(),
        #[cfg(feature = "om_nipr")]
        Some(Environment::OM_NIPR) => "https://ee-derility-ca-1.c3pki.oandm.disa.mil".to_string(),
        #[cfg(feature = "om_sipr")]
        Some(Environment::OM_SIPR) => "https://ee-nss-derility-ca-1.snipr.disa.mil".to_string(),
        #[cfg(feature = "nipr")]
        Some(Environment::NIPR) => "https://ee-derility-ca-1.csd.disa.mil".to_string(),
        #[cfg(feature = "sipr")]
        Some(Environment::SIPR) => "https://ee-nss-derility-ca-1.csd.disa.smil.mil".to_string(),
        _ => {
            println!("{}: unrecognized environment", "ERROR".bold());
            return;
        }
    };

    if args.portal_status_check {
        match portal_status_check(&pb_base_url).await {
            Ok(_) => {
                println!("{}", "SUCCESS".bold())
            }
            Err(e) => {
                println!(
                    "{}: status check failed for {} with: {:?}",
                    pb_base_url,
                    "ERROR".bold(),
                    e
                );
            }
        };
        return;
    }

    if args.scep_check {
        match scep_check(&ca_base_url).await {
            Ok(_) => {
                println!("{}", "SUCCESS".bold())
            }
            Err(e) => {
                println!(
                    "{}: status check failed for {} with: {:?}",
                    "ERROR".bold(),
                    ca_base_url,
                    e
                );
            }
        };
        return;
    }

    // ----------------------------------------------------------------------------------
    // operations that require an environment and a YubiKey (actions)
    //  - pre_enroll
    //  - enroll
    //  - ukm
    //  - recover
    // ----------------------------------------------------------------------------------
    let mut yubikey = match get_yubikey(serial) {
        Ok(yk) => yk,
        Err(e) => {
            println!("{}: {e}", "ERROR".bold());
            return;
        }
    };

    if yubikey.authenticate(PB_MGMT_KEY.clone()).is_err() {
        println!("{}: this YubiKey is not using the expected management key. Please reset the device then try again.", "ERROR".bold());
        return;
    }

    let pin = loop {
        let pin = rpassword::prompt_password(
            format!(
                "Enter PIN for YubiKey with serial number {}: ",
                yubikey.serial()
            )
            .bold(),
        )
        .unwrap();
        match yubikey.verify_pin(pin.as_bytes()) {
            Ok(_) => break pin,
            Err(_) => {
                println!("{}: PIN verification failed. Try again.", "ERROR".bold())
            }
        };
    };
    // comment out above loop and uncomment below to run in debugger
    // let pin = "123456";

    let mgmt_key = PB_MGMT_KEY.clone();
    assert!(yubikey.authenticate(mgmt_key.clone()).is_ok());

    if args.pre_enroll_otp.is_some() {
        match pre_enroll(
            &mut yubikey,
            &args.agent_edipi.unwrap(),
            &args.pre_enroll_otp.unwrap(),
            &pb_base_url,
            pin.as_bytes(),
            &mgmt_key,
        )
        .await
        {
            Ok(hash) => {
                println!("Pre-enroll completed successfully: {}", hash.bold());
            }
            Err(Error::Forbidden) => {
                println!(
                    "{}: pre-enroll failed with 403 Forbidden. Make sure the OTP is correct, has not been used before and is not stale.",
                    "ERROR".bold()
                );
            }
            Err(Error::UnexpectedDeviceState) => {
                println!(
                    "{}: pre-enroll failed with 409 Conflict. Have a Purebred Agent reset the device on the portal then re-enroll.",
                    "ERROR".bold()
                );
            }
            Err(e) => {
                println!("{}: pre-enroll failed: {e:?}", "ERROR".bold());
            }
        }
    } else if args.enroll_otp.is_some() {
        let oai = OtaActionInputs::new(
            &args.serial.as_ref().unwrap().to_string(),
            &args.enroll_otp.unwrap(),
            &pb_base_url,
            &app,
        );

        match enroll(
            &mut yubikey,
            &args.agent_edipi.unwrap().to_string(),
            &oai,
            pin.as_bytes(),
            &mgmt_key,
            &env,
        )
        .await
        {
            Ok(_) => {
                println!("Enroll completed successfully");
            }
            Err(Error::Forbidden) => {
                println!(
                    "{}: enroll failed with 403 Forbidden. Make sure the OTP is correct, is for this device, has not been used before and is not stale.",
                    "ERROR".bold()
                );
            }
            Err(Error::UnexpectedDeviceState) => {
                println!(
                    "{}: enroll failed with 409 Conflict. Have a Purebred Agent reset the device on the portal then re-enroll.",
                    "ERROR".bold()
                );
            }
            Err(e) => {
                println!("{}: enroll failed: {e:?}", "ERROR".bold());
            }
        }
    } else if args.ukm_otp.is_some() {
        let oai = OtaActionInputs::new(
            &args.serial.as_ref().unwrap().to_string(),
            &args.ukm_otp.unwrap(),
            &pb_base_url,
            &app,
        );

        match ukm(&mut yubikey, &oai, pin.as_bytes(), &mgmt_key, &env).await {
            Ok(_) => {
                println!("UKM completed successfully");
            }
            Err(Error::Forbidden) => {
                println!(
                    "{}: user key management failed with 403 Forbidden. Make sure the OTP is correct, is for this device, has not been used before and is not stale.",
                    "ERROR".bold()
                );
            }
            Err(Error::UnexpectedDeviceState) => {
                println!(
                    "{}: user key management failed with 409 Conflict. Have a Purebred Agent reset the device on the portal then re-enroll.",
                    "ERROR".bold()
                );
            }
            Err(e) => {
                println!("{}: user key management failed: {e:?}", "ERROR".bold());
            }
        }
    } else if args.recover_otp.is_some() {
        let oai = OtaActionInputs::new(
            &args.serial.as_ref().unwrap().to_string(),
            &args.recover_otp.unwrap(),
            &pb_base_url,
            &app,
        );

        match recover(&mut yubikey, &oai, pin.as_bytes(), &mgmt_key, &env).await {
            Ok(_) => {
                println!("Recover completed successfully");
            }
            Err(Error::Forbidden) => {
                println!(
                    "{}: recover failed with 403 Forbidden. Make sure the OTP is correct, is for this device, has not been used before and is not stale.",
                    "ERROR".bold()
                );
            }
            Err(Error::UnexpectedDeviceState) => {
                println!(
                    "{}: recover failed with 409 Conflict. Have a Purebred Agent reset the device on the portal then re-enroll.",
                    "ERROR".bold()
                );
            }
            Err(e) => {
                println!("{}: recover failed with: {e:?}", "ERROR".bold());
            }
        }
    } else {
        println!("{}: unrecognized action", "ERROR".bold());
    }
}
