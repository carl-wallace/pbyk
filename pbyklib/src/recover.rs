//! Interacts with Purebred portal to recover escrowed keys

use yubikey::{piv::SlotId, MgmKey, YubiKey};

use crate::{
    data::OtaActionInputs,
    log_info,
    network::get_profile,
    utils::{process_payloads, verify_and_decrypt},
    Result,
};

/// Recovers keys for storage on the indicted YubiKey device using the URL obtained from `recover_inputs`
pub async fn recover(
    yubikey: &mut YubiKey,
    recover_inputs: &OtaActionInputs,
    pin: &[u8],
    mgmt_key: &MgmKey,
) -> Result<()> {
    log_info(&format!(
        "Begin recover for YubiKey with serial {}",
        recover_inputs.serial
    ));

    let profile = get_profile(&recover_inputs.to_recover_url()).await?;
    let dec = verify_and_decrypt(
        yubikey,
        SlotId::CardAuthentication,
        &profile,
        true,
        pin,
        mgmt_key,
    )?;
    process_payloads(yubikey, &dec, pin, mgmt_key).await
}
