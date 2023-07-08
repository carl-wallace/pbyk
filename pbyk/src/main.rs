#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

use clap::Parser;

use pbyklib::data::OtaActionInputs;
use pbyklib::{
    list_yubikeys::{get_yubikey, list_yubikeys},
    reset_yubikey::reset_yubikey,
    PB_HOST, PB_MGMT_KEY,
};

use pbyklib::enroll::enroll;
use pbyklib::pre_enroll::pre_enroll;
use pbyklib::recover::recover;
use pbyklib::ukm::ukm;

use crate::args::PbYkArgs;
mod args;
mod utils;
use utils::configure_logging;

/// Point of entry for pbyk application.
#[tokio::main]
async fn main() {
    let args = PbYkArgs::parse();
    configure_logging(&args);

    let app = format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    if args.list_yubikeys {
        match list_yubikeys() {
            Ok(readers) => {
                for reader in readers {
                    println!("Name: {}; Serial: {}", reader.name(), reader.serial());
                }
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    } else {
        let mut yubikey = match get_yubikey(args.serial) {
            Ok(yk) => yk,
            Err(e) => {
                println!("ERROR: {:?}", e);
                return;
            }
        };
        if !args.reset_yubikey && yubikey.authenticate(PB_MGMT_KEY.clone()).is_err() {
            println!("This YubiKey is not using the expected management key. Please reset the device then try again.");
            return;
        }

        if args.reset_yubikey {
            let pin = loop {
                let pin = rpassword::prompt_password("Enter new PIN: ").unwrap();
                let pin2 = rpassword::prompt_password("Re-enter new PIN: ").unwrap();
                if pin != pin2 || pin.len() < 6 {
                    println!("ERROR: pins do not match or are not at least 6 characters long");
                } else {
                    break pin;
                }
            };
            let puk = loop {
                let puk = rpassword::prompt_password("Enter new PUK: ").unwrap();
                let puk2 = rpassword::prompt_password("Re-enter new PUK: ").unwrap();
                if puk != puk2 || puk.len() < 8 {
                    println!("ERROR: PUKs do not match or are not at least 8 characters long");
                } else {
                    break puk;
                }
            };
            // comment out above two loops and uncomment below to run in debugger
            // let pin = "123456".to_string();
            // let puk = "12345678".to_string();
            let _ = reset_yubikey(&mut yubikey, &pin, &puk, &PB_MGMT_KEY);
        } else {
            let pin = loop {
                let pin = rpassword::prompt_password("Enter PIN: ").unwrap();
                match yubikey.verify_pin(pin.as_bytes()) {
                    Ok(_) => break pin,
                    Err(_) => {
                        println!("PIN verification failed. Try again.")
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
                    &PB_HOST,
                )
                .await
                {
                    Ok(hash) => {
                        println!("Pre-enroll completed successfully: {hash}");
                    }
                    Err(e) => {
                        println!("ERROR: pre-enroll failed: {:?}", e);
                    }
                }
                // todo display hash
            } else if args.enroll_otp.is_some() {
                let oai = OtaActionInputs::new(
                    &args.serial.as_ref().unwrap().to_string(),
                    &args.enroll_otp.unwrap(),
                    &PB_HOST.to_string(),
                    &app,
                );

                match enroll(
                    &mut yubikey,
                    &args.agent_edipi.unwrap().to_string(),
                    &oai,
                    pin.as_bytes(),
                    &mgmt_key,
                )
                .await
                {
                    Ok(_) => {
                        println!("Enroll completed successfully");
                    }
                    Err(e) => {
                        println!("ERROR: enroll failed: {:?}", e);
                    }
                }
            } else if args.ukm_otp.is_some() {
                let oai = OtaActionInputs::new(
                    &args.serial.as_ref().unwrap().to_string(),
                    &args.ukm_otp.unwrap(),
                    &PB_HOST.to_string(),
                    &app,
                );

                match ukm(&mut yubikey, &oai, pin.as_bytes(), &mgmt_key).await {
                    Ok(_) => {
                        println!("UKM completed successfully");
                    }
                    Err(e) => {
                        println!("ERROR: UKM failed: {:?}", e);
                    }
                }
            } else if args.recover_otp.is_some() {
                let oai = OtaActionInputs::new(
                    &args.serial.as_ref().unwrap().to_string(),
                    &args.recover_otp.unwrap(),
                    &PB_HOST.to_string(),
                    &app,
                );

                match recover(&mut yubikey, &oai, pin.as_bytes(), &mgmt_key).await {
                    Ok(_) => {
                        println!("Recover completed successfully");
                    }
                    Err(e) => {
                        println!("ERROR: recover failed: {:?}", e);
                    }
                }
            }
        }
    }
}
