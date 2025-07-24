//! Interacts with Purebred portal to recover escrowed keys to a virtual smart card device
//!
#![cfg(all(target_os = "windows", feature = "vsc"))]

use log::{error, info};
use windows::Devices::SmartCards::SmartCard;

use pbykcorelib::misc::network::get_profile;

use crate::misc_win::utils::{process_payloads_vsc, verify_and_decrypt_vsc};
use crate::misc_win::vsc_signer::CertContext;
use crate::ota::OtaActionInputs;

/// Recovers keys for storage on the indicated virtual smart card (VSC) device using the URL obtained from `recover_inputs`
///
/// # Arguments
/// * `vsc` - handle to VSC to provision
/// * `cred` - handle to device credential to use when decrypting profile received from portal
/// * `recover_inputs` - structure containing information used to prepare URI to execute recovery action
/// * `env` - identifies the environment in which enrollment is being performed, i.e., DEV, NIPR, SIPR, OM_NIPR, OM_SIPR
pub async fn recover(
    vsc: &mut SmartCard,
    cred: &CertContext,
    recover_inputs: &OtaActionInputs,
    env: &str,
) -> crate::Result<()> {
    info!(
        "Begin recover operation for VSC with serial {}",
        recover_inputs.serial
    );

    let profile = get_profile(&recover_inputs.to_recover_url()).await?;
    let dec = verify_and_decrypt_vsc(cred, &profile, true, env).await?;
    match process_payloads_vsc(vsc, &dec, env, true).await {
        Ok(_) => {
            info!(
                "Recovery operation for VSC with serial {} succeeded",
                recover_inputs.serial
            );
            Ok(())
        }
        Err(e) => {
            error!(
                "Recovery operation failed for VSC with serial {}",
                recover_inputs.serial
            );
            Err(e)
        }
    }
}
