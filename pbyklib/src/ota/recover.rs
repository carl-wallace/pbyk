//! Interacts with Purebred portal to recover escrowed keys

use log::error;
use yubikey::MgmKey;
use zeroize::Zeroizing;

#[cfg(all(target_os = "windows", feature = "vsc"))]
use windows::Devices::SmartCards::SmartCard;

use crate::ota::CryptoModule;
use crate::{Error, Result, get_pb_default, ota::OtaActionInputs};

#[cfg(all(target_os = "windows", feature = "vsc"))]
use crate::misc_win::vsc_signer::CertContext;

#[cfg(all(target_os = "windows", feature = "vsc"))]
use crate::utils::get_device_cred;

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
    mgmt_key: Option<MgmKey>,
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
                &mgmt_key.unwrap_or(get_pb_default(yk)),
                env,
            )
            .await
        }
        #[cfg(all(target_os = "windows", feature = "vsc"))]
        CryptoModule::SmartCard(sc) => {
            use crate::ota_vsc::recover::recover;
            let cred = get_device_cred_from_smartcard(sc)?;
            recover(sc, &cred, recover_inputs, env).await
        }
    }
}

/// Retrieve the device credential from the provided SmartCard
#[cfg(all(target_os = "windows", feature = "vsc"))]
pub(crate) fn get_device_cred_from_smartcard(sc: &SmartCard) -> Result<CertContext> {
    use crate::misc_win::vsc_state::get_vsc_id;

    let reader = match sc.Reader() {
        Ok(reader) => reader,
        Err(e) => {
            error!("Failed to get reader instance from SmartCard object: {e}");
            return Err(Error::Vsc);
        }
    };

    let name = match reader.Name() {
        Ok(name) => name,
        Err(e) => {
            error!("Failed to get name of reader instance from SmartCard object: {e}");
            return Err(Error::Vsc);
        }
    };

    let vsc_id = match get_vsc_id(&name) {
        Ok(vsc_id) => vsc_id,
        Err(e) => {
            error!("Failed to get vsc_id from SmartCard object: {e:?}");
            return Err(Error::Vsc);
        }
    };
    match get_device_cred(&vsc_id, false) {
        Ok(cred) => Ok(cred),
        Err(e) => {
            error!("Failed to get device cred from SmartCard object: {e:?}");
            Err(e)
        }
    }
}
