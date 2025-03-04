//! Interacts with Purebred portal to provision fresh PIV and signature credentials and current recovered encryption credential to a YubiKey device

use log::{error, info};
use yubikey::{MgmKey, YubiKey, piv::SlotId};

use crate::{
    Result,
    misc_yubikey::utils::{process_payloads, verify_and_decrypt},
    ota::OtaActionInputs,
};
use pbykcorelib::misc::network::get_profile;

/// Obtains fresh PIV and signature credentials and current encryption credential using the indicted
/// YubiKey device using the URL obtained from `ukm_inputs`
///
/// # Arguments
/// * `yubikey` - handle to YubiKey to enroll
/// * `ukm_inputs` - structure containing information used to prepare URI to execute UKM action
/// * `pin` - YubiKey PIN required to provision user-related slots on the given YubiKey device (may be omitted for VSC enrollments)
/// * `mgmt_key` - YubiKey management key value (may be omitted for VSC enrollments)/// * `env` - identifies the environment in which enrollment is being performed, i.e., DEV, NIPR, SIPR, OM_NIPR, OM_SIPR
pub async fn ukm(
    yubikey: &mut YubiKey,
    ukm_inputs: &OtaActionInputs,
    pin: &[u8],
    mgmt_key: &MgmKey,
    env: &str,
) -> Result<()> {
    info!(
        "Begin user key management operation for YubiKey with serial {}",
        ukm_inputs.serial
    );

    let profile = get_profile(&ukm_inputs.to_ukm_url()).await?;
    let dec = verify_and_decrypt(
        yubikey,
        SlotId::CardAuthentication,
        &profile,
        true,
        pin,
        mgmt_key,
        env,
    )
    .await?;
    match process_payloads(yubikey, &dec, pin, mgmt_key, env, true).await {
        Ok(_) => {
            info!(
                "User key management operation for YubiKey with serial {} succeeded",
                ukm_inputs.serial
            );
            Ok(())
        }
        Err(e) => {
            error!(
                "User key management operation failed for YubiKey with serial {}",
                ukm_inputs.serial
            );
            Err(e)
        }
    }
}
