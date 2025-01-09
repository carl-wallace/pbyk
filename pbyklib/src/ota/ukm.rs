//! Interacts with Purebred portal to obtain fresh PIV and signature credentials and current recovered encryption credential

use log::error;
use yubikey::MgmKey;
use zeroize::Zeroizing;

use crate::ota::{get_device_cred_from_smartcard, CryptoModule};
use crate::{ota::OtaActionInputs, Error, Result, PB_MGMT_KEY};

/// Obtains fresh PIV and signature credentials and current encryption credential using the indicted
/// YubiKey device using the URL obtained from `ukm_inputs`
///
/// # Arguments
/// * `yubikey` - handle to YubiKey to enroll
/// * `ukm_inputs` - structure containing information used to prepare URI to execute UKM action
/// * `pin` - YubiKey PIN required to provision user-related slots on the given YubiKey device (may be omitted for VSC enrollments)
/// * `mgmt_key` - YubiKey management key value (may be omitted for VSC enrollments)
/// * `env` - identifies the environment in which enrollment is being performed, i.e., DEV, NIPR, SIPR, OM_NIPR, OM_SIPR
pub async fn ukm(
    cm: &mut CryptoModule,
    ukm_inputs: &OtaActionInputs,
    pin: Option<Zeroizing<String>>,
    mgmt_key: Option<&MgmKey>,
    env: &str,
) -> Result<()> {
    match cm {
        CryptoModule::YubiKey(yk) => {
            use crate::ota_yubikey::ukm::ukm;
            let pin = match pin {
                Some(pin) => pin,
                None => {
                    error!("PIN value must be provided when enrolling a YubiKey device");
                    return Err(Error::BadInput);
                }
            };
            ukm(
                yk,
                ukm_inputs,
                pin.as_bytes(),
                mgmt_key.unwrap_or(&PB_MGMT_KEY),
                env,
            )
            .await
        }
        #[cfg(all(target_os = "windows", feature = "vsc"))]
        CryptoModule::SmartCard(sc) => {
            use crate::ota_vsc::ukm::ukm;

            let cred = get_device_cred_from_smartcard(sc)?;
            ukm(sc, &cred, ukm_inputs, env).await
        }
    }
}
