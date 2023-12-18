//! Interacts with Purebred portal to recover escrowed keys

use log::info;
use yubikey::{piv::SlotId, MgmKey, YubiKey};

use crate::{
    misc::internal_utils::{process_payloads, verify_and_decrypt},
    misc::network::get_profile,
    ota::OtaActionInputs,
    Result,
};

/// Recovers keys for storage on the indicted YubiKey device using the URL obtained from `recover_inputs`
///
/// # Arguments
/// * `yubikey` - handle to YubiKey to enroll
/// * `recover_inputs` - structure containing information used to prepare URI to execute UKM action
/// * `pin` - PIN required to provision user-related slots on the given YubiKey device
/// * `mgmt_key` - management key required to provision the given YubiKey device
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
    process_payloads(yubikey, &dec, pin, mgmt_key, env, true).await
}
