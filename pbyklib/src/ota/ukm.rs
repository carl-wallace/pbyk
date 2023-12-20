//! Interacts with Purebred portal to obtain fresh PIV and signature credentials and current recovered encryption credential

use log::{error, info};
use yubikey::{piv::SlotId, MgmKey, YubiKey};

use crate::{
    misc::internal_utils::{process_payloads, verify_and_decrypt},
    misc::network::get_profile,
    ota::OtaActionInputs,
    Result,
};

/// Obtains fresh PIV and signature credentials and current encryption credential using the indicted
/// YubiKey device using the URL obtained from `ukm_inputs`
///
/// # Arguments
/// * `yubikey` - handle to YubiKey to enroll
/// * `ukm_inputs` - structure containing information used to prepare URI to execute UKM action
/// * `pin` - PIN required to provision user-related slots on the given YubiKey device
/// * `mgmt_key` - management key required to provision the given YubiKey device
/// * `env` - identifies the environment in which enrollment is being performed, i.e., DEV, NIPR, SIPR, OM_NIPR, OM_SIPR
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
                "Begin user key management operation for YubiKey with serial {}",
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
