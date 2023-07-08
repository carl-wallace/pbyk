//! Interacts with Purebred portal to obtain fresh PIV and signature credentials and current recovered encryption credential

use yubikey::{piv::SlotId, MgmKey, YubiKey};

use crate::{
    data::OtaActionInputs,
    log_info,
    network::get_profile,
    utils::{process_payloads, verify_and_decrypt},
    Result,
};

/// Obtains fresh PIV and signature credentials and current encryption credential using the indicted
/// YubiKey device using the URL obtained from `ukm_inputs`
pub async fn ukm(
    yubikey: &mut YubiKey,
    ukm_inputs: &OtaActionInputs,
    pin: &[u8],
    mgmt_key: &MgmKey,
) -> Result<()> {
    log_info(&format!(
        "Begin ukm for YubiKey with serial {}",
        ukm_inputs.serial
    ));

    let profile = get_profile(&ukm_inputs.to_ukm_url()).await?;
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
