//! Executes Pre-enroll (i.e., Phase 0) in preparation for Purebred enrollment

use log::error;
use yubikey::MgmKey;
use zeroize::Zeroizing;

use crate::ota::CryptoModule;
use crate::{get_pb_default, Error, Result};

/// Executes "Phase 0" to prepare a device for enrollment
///
/// Upon success a string containing a hash of the self-signed certificate is returned.
///
/// # Arguments
/// * `cm` - reference to [CryptoModule] to enroll
/// * `agent_edipi` - string containing 10 digit EDIPI of Purebred Agent who provided the `pre_enroll_otp` parameter
/// * `pre_enroll_otp`- string containing 8 digit time-limited one-time password value provided by Purebred Agent identified by the `agent_edipi` parameter
/// * `base_url` - base URI of Purebred portal to use to enroll YubiKey, for example, `https://pb2.redhoundsoftware.net`
/// * `pin` - YubiKey PIN required to provision user-related slots on the given YubiKey device (may be omitted for VSC enrollments)
/// * `mgmt_key` - YubiKey management key value (may be omitted for VSC enrollments)
pub async fn pre_enroll(
    cm: &mut CryptoModule,
    agent_edipi: &str,
    pre_enroll_otp: &str,
    base_url: &str,
    pin: Option<Zeroizing<String>>,
    mgmt_key: Option<MgmKey>,
) -> Result<String> {
    match cm {
        CryptoModule::YubiKey(yk) => {
            use crate::ota_yubikey::pre_enroll::pre_enroll;
            let pin = match pin {
                Some(pin) => pin,
                None => {
                    error!("PIN value must be provided when enrolling a YubiKey device");
                    return Err(Error::BadInput);
                }
            };
            pre_enroll(
                yk,
                agent_edipi,
                pre_enroll_otp,
                base_url,
                pin.as_bytes(),
                &mgmt_key.unwrap_or(get_pb_default(yk)),
            )
            .await
        }
        #[cfg(all(target_os = "windows", feature = "vsc"))]
        CryptoModule::SmartCard(sc) => {
            use crate::ota_vsc::pre_enroll::pre_enroll;
            pre_enroll(sc, agent_edipi, pre_enroll_otp, base_url).await
        }
    }
}
