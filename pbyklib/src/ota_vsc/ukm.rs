//! Interacts with Purebred portal to provision fresh PIV and signature credentials and current recovered encryption credential to a virtual smart card device

#![cfg(all(target_os = "windows", feature = "vsc"))]

use log::{error, info};
use windows::Devices::SmartCards::SmartCard;

use crate::misc_win::vsc_signer::CertContext;
use crate::ota::OtaActionInputs;
use crate::{
    misc::network::get_profile,
    misc_win::utils::{process_payloads_vsc, verify_and_decrypt_vsc},
};

/// Obtains fresh PIV and signature credentials and current encryption credential using the indicted
/// virtual smart card device using the URL obtained from `ukm_inputs`
///
/// # Arguments
/// * `smartcard` - handle to virtual smart card to enroll
/// * `ukm_inputs` - structure containing information used to prepare URI to execute UKM action
/// * `pin` - YubiKey PIN required to provision user-related slots on the given YubiKey device (may be omitted for VSC enrollments)
/// * `mgmt_key` - YubiKey management key value (may be omitted for VSC enrollments)/// * `env` - identifies the environment in which enrollment is being performed, i.e., DEV, NIPR, SIPR, OM_NIPR, OM_SIPR
pub async fn ukm(
    smartcard: &mut SmartCard,
    cred: &CertContext,
    ukm_inputs: &OtaActionInputs,
    env: &str,
) -> crate::Result<()> {
    info!(
        "Begin user key management operation for VSC with serial {}",
        ukm_inputs.serial
    );

    let profile = get_profile(&ukm_inputs.to_ukm_url()).await?;
    let dec = verify_and_decrypt_vsc(cred, &profile, true, env).await?;
    match process_payloads_vsc(smartcard, &dec, env, true).await {
        Ok(_) => {
            info!(
                "User key management operation for VSC with serial {} succeeded",
                ukm_inputs.serial
            );
            Ok(())
        }
        Err(e) => {
            error!(
                "User key management operation failed for VSC with serial {}",
                ukm_inputs.serial
            );
            Err(e)
        }
    }
}
