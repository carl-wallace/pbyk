//! Interacts with Purebred portal to recover escrowed keys to a YubiKey device

use log::{error, info};
use yubikey::{piv::SlotId, MgmKey, YubiKey};

use crate::{
    misc::network::get_profile,
    misc_yubikey::utils::{process_payloads, verify_and_decrypt},
    ota::OtaActionInputs,
    Result,
};

/// Recovers keys for storage on the indicated YubiKey device using the URL obtained from `recover_inputs`
///
/// # Arguments
/// * `yubikey` - handle to YubiKey to provision
/// * `recover_inputs` - structure containing information used to prepare URI to execute recovery action
/// * `pin` - YubiKey PIN required to provision user-related slots on the given YubiKey device (may be omitted for VSC enrollments)
/// * `mgmt_key` - YubiKey management key value (may be omitted for VSC enrollments)
/// * `env` - identifies the environment in which enrollment is being performed, i.e., DEV, NIPR, SIPR, OM_NIPR, OM_SIPR
pub async fn recover(
    yubikey: &mut YubiKey,
    recover_inputs: &OtaActionInputs,
    pin: &[u8],
    mgmt_key: &MgmKey,
    env: &str,
) -> Result<()> {
    info!(
        "Begin recover operation for YubiKey with serial {}",
        recover_inputs.serial
    );

    let profile = get_profile(&recover_inputs.to_recover_url()).await?;
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
                "Recovery operation for YubiKey with serial {} succeeded",
                recover_inputs.serial
            );
            Ok(())
        }
        Err(e) => {
            error!(
                "Recover operation failed for YubiKey with serial {}",
                recover_inputs.serial
            );
            Err(e)
        }
    }
}
