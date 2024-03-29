//! Executes OTA protocol in support of Purebred enrollment

use std::io::Cursor;
use zeroize::Zeroizing;

use log::{error, info};
use plist::Value;

use signature::{Keypair, Signer};
use spki::DynSignatureAlgorithmIdentifier;
use x509_cert::Certificate;
use yubikey::MgmKey;

use crate::misc::utils::purebred_authorize_request;
use crate::{
    misc::network::{post_body, post_no_body},
    misc::utils::get_signed_data,
    ota::{CryptoModule, OtaActionInputs},
    Error, Result, PB_MGMT_KEY,
};

//------------------------------------------------------------------------------------
// Local methods
//------------------------------------------------------------------------------------
/// Retrieves Phase 1 response, verifies it and returns result as a plist::Value.
async fn fetch_phase1(url: &str, env: &str) -> Result<Value> {
    let p1resp = post_no_body(url).await?;
    let xml = purebred_authorize_request(&p1resp, env).await?;

    let xml_cursor = Cursor::new(xml);
    match Value::from_reader(xml_cursor) {
        Ok(profile) => Ok(profile),
        Err(e) => {
            error!(
                "Failed to parse Phase 1 encapsulated content as a configuration profile: {e:?}"
            );
            Err(Error::Plist)
        }
    }
}

//------------------------------------------------------------------------------------
// Public methods
//------------------------------------------------------------------------------------
/// Execute the phase 1 portion of the OTA protocol as part of Purebred enrollment. Logs error
/// details before returning.
pub(crate) async fn phase1(url: &str, env: &str) -> Result<(String, String)> {
    info!("Executing Phase 1");
    let p1_resp = fetch_phase1(url, env).await?;

    let p1_resp_dict = match p1_resp.as_dictionary() {
        Some(d) => d,
        None => {
            error!("Failed to parse Phase 1 response as a configuration profile");
            return Err(Error::Plist);
        }
    };

    let p1_resp_payload = match p1_resp_dict.get("PayloadContent") {
        Some(p) => match p.as_dictionary() {
            Some(payload) => payload,
            None => {
                error!("Failed to parse PayloadContent from Phase 1 response as a dictionary");
                return Err(Error::Plist);
            }
        },
        None => {
            error!("Failed to extract PayloadContent from Phase 1 response");
            return Err(Error::Plist);
        }
    };

    let p1_challenge = match p1_resp_payload.get("Challenge") {
        Some(challenge) => match challenge.as_string() {
            Some(s) => s.to_string(),
            None => {
                error!("Failed to read Challenge value from Phase 1 response as a string");
                return Err(Error::ParseError);
            }
        },
        None => return Err(Error::ParseError),
    };

    let p1_resp_url = match p1_resp_payload.get("URL") {
        Some(url) => match url.as_string() {
            Some(s) => s.to_string(),
            None => {
                error!("Failed to read URL value from Phase 1 response as a string");
                return Err(Error::ParseError);
            }
        },
        None => return Err(Error::ParseError),
    };
    Ok((p1_challenge, p1_resp_url))
}

/// Execute Phase 3 of OTA protocol as part of Purebred enrollment.
pub(crate) async fn phase3<S>(
    signer: &S,
    phase3_req: &[u8],
    ca_issued_device_cert: &Certificate,
    phase3_url: &str,
) -> Result<()>
where
    S: Keypair + DynSignatureAlgorithmIdentifier + Signer<rsa::pkcs1v15::Signature>,
{
    info!("Executing Phase 3");
    let signed_data_pkcs7_der = get_signed_data(signer, ca_issued_device_cert, phase3_req)?;
    match post_body(
        phase3_url,
        &signed_data_pkcs7_der,
        "application/pkcs7-signature; charset=utf-8",
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("Failed to submit Phase 3 request: {e:?}");
            Err(Error::Network)
        }
    }
}

/// Executes the OTA protocol (with encrypted phase 2 response) to complete Purebred enrollment, which
/// includes issuance of a certificate for the device. User keys are provisioned via [ukm](crate::ota::ukm::ukm()) and [recover](crate::ota::recover::recover()).
///
/// # Arguments
/// * `yubikey` - handle to YubiKey to enroll
/// * `agent_edipi` - string containing 10 digit EDIPI of Purebred Agent who provided the `otp` field of the `oai` parameter
/// * `oai` - structure containing information used to prepare URI to execute OTA protocol
/// * `pin` - YubiKey PIN required to provision user-related slots on the given YubiKey device (may be omitted for VSC enrollments)
/// * `mgmt_key` - YubiKey management key value (may be omitted for VSC enrollments)
/// * `env` - identifies the environment in which enrollment is being performed, i.e., DEV, NIPR, SIPR, OM_NIPR, OM_SIPR
pub async fn enroll(
    cm: &mut CryptoModule,
    agent_edipi: &str,
    oai: &OtaActionInputs,
    pin: Option<Zeroizing<String>>,
    mgmt_key: Option<&MgmKey>,
    env: &str,
) -> Result<()> {
    match cm {
        CryptoModule::YubiKey(yk) => {
            use crate::ota_yubikey::enroll::enroll;
            let pin = match pin {
                Some(pin) => pin,
                None => {
                    error!("PIN value must be provided when enrolling a YubiKey device");
                    return Err(Error::BadInput);
                }
            };
            enroll(
                yk,
                agent_edipi,
                oai,
                pin.as_bytes(),
                mgmt_key.unwrap_or(&PB_MGMT_KEY),
                env,
            )
            .await
        }
        #[cfg(all(target_os = "windows", feature = "vsc"))]
        CryptoModule::SmartCard(sc) => {
            use crate::ota_vsc::enroll::enroll;
            enroll(sc, agent_edipi, oai, env).await
        }
    }
}
