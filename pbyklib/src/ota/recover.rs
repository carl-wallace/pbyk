//! Interacts with Purebred portal to recover escrowed keys

use log::error;
use yubikey::MgmKey;
use zeroize::Zeroizing;

use crate::ota::CryptoModule;
use crate::{ota::OtaActionInputs, Error, Result, PB_MGMT_KEY};

/// Recovers keys for storage on the indicted YubiKey device using the URL obtained from `recover_inputs`
///
/// # Arguments
/// * `yubikey` - handle to YubiKey to enroll
/// * `recover_inputs` - structure containing information used to prepare URI to execute UKM action
/// * `pin` - YubiKey PIN required to provision user-related slots on the given YubiKey device (may be omitted for VSC enrollments)
/// * `mgmt_key` - YubiKey management key value (may be omitted for VSC enrollments)
/// * `env` - identifies the environment in which enrollment is being performed, i.e., DEV, NIPR, SIPR, OM_NIPR, OM_SIPR
pub async fn recover(
    cm: &mut CryptoModule,
    recover_inputs: &OtaActionInputs,
    pin: Option<Zeroizing<String>>,
    mgmt_key: Option<&MgmKey>,
    env: &str,
) -> Result<()> {
    match cm {
        CryptoModule::YubiKey(yk) => {
            use crate::ota_yubikey::recover::recover;
            let pin = match pin {
                Some(pin) => pin,
                None => {
                    error!("PIN value must be provided when enrolling a YubiKey device");
                    return Err(Error::BadInput);
                }
            };
            recover(
                yk,
                recover_inputs,
                pin.as_bytes(),
                mgmt_key.unwrap_or(&PB_MGMT_KEY),
                env,
            )
            .await
        }
        #[cfg(all(target_os = "windows", feature = "vsc"))]
        CryptoModule::SmartCard(sc) => {
            use crate::misc_win::vsc_state::get_vsc_id;
            use crate::ota_vsc::recover::recover;
            use crate::utils::list_vscs::get_device_cred;

            let vsc_id = get_vsc_id(&sc.Reader().unwrap().Name().unwrap()).unwrap();
            let cred = get_device_cred(&vsc_id, false).unwrap();
            recover(sc, &cred, recover_inputs, env).await
        }
    }
}
