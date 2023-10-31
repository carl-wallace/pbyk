#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

use clap::{CommandFactory, Parser};

#[cfg(target_os = "windows")]
use crate::no_bold::NoBold;
#[cfg(not(target_os = "windows"))]
use colored::Colorize;

use pbyklib::{
    ota::{enroll, pre_enroll, recover, ukm, OtaActionInputs},
    utils::{
        get_yubikey, list_yubikeys, num_yubikeys, portal_status_check, reset_yubikey, scep_check,
    },
    Error, PB_MGMT_KEY,
};

mod args;
use args::{num_environments, Environment, PbYkArgs};
mod utils;

mod no_bold;

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

/// Point of entry for `pbyk` application.
///
/// See [PbYkArgs] for usage details.
#[tokio::main]
async fn main() {
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
                println!("{}: {e}", "ERROR".bold());
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
                Some(yk) => args.serial = Some(yk.serial()),
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

    if args.reset_yubikey {
        let mut yubikey = match get_yubikey(args.serial) {
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

    let pb_host = match args.environment {
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

    let ca_host = match args.environment {
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
        match portal_status_check(&pb_host).await {
            Ok(_) => {
                println!("{}", "SUCCESS".bold())
            }
            Err(e) => {
                println!(
                    "{}: status check failed for {} with: {:?}",
                    pb_host,
                    "ERROR".bold(),
                    e
                );
            }
        };
        return;
    }

    if args.scep_check {
        match scep_check(&ca_host).await {
            Ok(_) => {
                println!("{}", "SUCCESS".bold())
            }
            Err(e) => {
                println!(
                    "{}: status check failed for {} with: {:?}",
                    "ERROR".bold(),
                    ca_host,
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
    let mut yubikey = match get_yubikey(args.serial) {
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
            &args.serial.unwrap().to_string(),
            &args.pre_enroll_otp.unwrap(),
            &pb_host,
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
            &pb_host,
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
            &pb_host,
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
            &pb_host,
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
