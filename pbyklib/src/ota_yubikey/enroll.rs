//! Executes OTA protocol in support of Purebred enrollment of a YubiKey device

use std::io::Cursor;

use log::{error, info};
use plist::Value;

use der::{Decode, Encode};
use spki::SubjectPublicKeyInfoRef;
use x509_cert::Certificate;
use yubikey::certificate::yubikey_signer::{Rsa2048, YubiRsa};
use yubikey::{piv::SlotId::CardAuthentication, MgmKey, YubiKey};

use crate::misc_yubikey::yk_signer::YkSigner;
use crate::ota::phase3;
use crate::{
    misc::{
        network::post_body,
        utils::{get_as_string, get_signed_data},
    },
    misc_yubikey::{
        p12::import_p12,
        scep::process_scep_payload,
        utils::{get_uuid_from_cert, verify_and_decrypt},
    },
    ota::{phase1, OtaActionInputs, Phase2Request, Phase3Request},
    utils::get_cert_from_slot,
    Error, Result,
};

/// Execute the phase 2 portion of the OTA protocol as part of Purebred enrollment
async fn phase2(
    yubikey: &mut YubiKey,
    phase2_req: &[u8],
    self_signed_cert: &Certificate,
    url: &str,
    pin: &[u8],
    mgmt_key: &MgmKey,
    env: &str,
) -> Result<Vec<u8>> {
    info!("Executing Phase 2");

    let enc_spki = self_signed_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()?;
    let spki_ref = SubjectPublicKeyInfoRef::from_der(&enc_spki)?;

    let signer: yubikey::certificate::yubikey_signer::Signer<'_, YubiRsa<Rsa2048>> =
        yubikey::certificate::yubikey_signer::Signer::new(yubikey, CardAuthentication, spki_ref)
            .map_err(|_| Error::Unrecognized)?;

    let signed_data_pkcs7_der = match get_signed_data(&signer, self_signed_cert, phase2_req) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to generate SignedData for Phase 2 request: {e:?}");
            return Err(e);
        }
    };

    let p2resp = post_body(
        url,
        &signed_data_pkcs7_der,
        "application/pkcs7-signature; charset=utf-8",
    )
    .await?;

    let phase2_resp_xml = verify_and_decrypt(
        yubikey,
        CardAuthentication,
        &p2resp,
        true,
        pin,
        mgmt_key,
        env,
    )
    .await?;

    let pt_cursor = Cursor::new(phase2_resp_xml);
    let profile2 = match Value::from_reader(pt_cursor) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to parse Phase2 response as a configuration profile: {e:?}");
            return Err(Error::Plist);
        }
    };

    let profile2_array = match profile2.as_array() {
        Some(p) => p,
        None => {
            error!("Failed to parse Phase2 configuration profile as an array");
            return Err(Error::Plist);
        }
    };

    if profile2_array.is_empty() {
        error!("Phase2 configuration profile array is empty");
        return Err(Error::Plist);
    }

    let profile2_dict = match profile2_array[0].as_dictionary() {
        Some(d) => d,
        None => {
            error!("Failed to parse Phase2 payload as a dictionary");
            return Err(Error::Plist);
        }
    };

    let payload_type = match profile2_dict.get("PayloadType") {
        Some(pt) => match pt.as_string() {
            Some(s) => {
                if "com.apple.security.scep" != s && "com.apple.security.pkcs12" != s {
                    error!("Unexpected PayloadType read from Phase2 response: {s}");
                    return Err(Error::Plist);
                }
                s
            }
            None => {
                error!("Failed to parse PayloadType from Phase2 response as a string");
                return Err(Error::Plist);
            }
        },
        None => {
            error!("Failed to read PayloadType from Phase2 response");
            return Err(Error::Plist);
        }
    };

    if "com.apple.security.scep" == payload_type {
        let pc = match profile2_dict.get("PayloadContent") {
            Some(v) => match v.as_dictionary() {
                Some(pc) => pc,
                None => {
                    error!("Failed to parse Phase2 SCEP payload content as a dictionary");
                    return Err(Error::Plist);
                }
            },
            None => {
                error!("Failed to read payload content from Phase2 SCEP payload");
                return Err(Error::Plist);
            }
        };

        process_scep_payload(
            yubikey,
            pc,
            true,
            pin,
            mgmt_key,
            get_as_string(profile2_dict, "PayloadDisplayName"),
            env,
        )
        .await
    } else {
        let payload_content = match profile2_dict.get("PayloadContent") {
            Some(pc) => match pc.as_data() {
                Some(d) => d,
                None => {
                    error!("Failed to parse PayloadContent as a data for PKCS #12 payload.");
                    return Err(Error::Plist);
                }
            },
            None => {
                error!("PKCS #12 payload missing PayloadContent.");
                return Err(Error::Plist);
            }
        };
        let password = match profile2_dict.get("Password") {
            Some(pc) => match pc.as_string() {
                Some(d) => d,
                None => {
                    error!("Failed to parse Password as a data for PKCS #12 payload.");
                    return Err(Error::Plist);
                }
            },
            None => {
                error!("PKCS #12 payload missing Password.");
                return Err(Error::Plist);
            }
        };
        import_p12(
            yubikey,
            payload_content,
            password,
            u8::MAX,
            Some(CardAuthentication),
        )
        .await
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
    yubikey: &mut YubiKey,
    agent_edipi: &str,
    oai: &OtaActionInputs,
    pin: &[u8],
    mgmt_key: &MgmKey,
    env: &str,
) -> Result<()> {
    info!(
        "Enrolling YubiKey with serial {} for the {env} environment",
        yubikey.serial()
    );

    let uuid = match get_uuid_from_cert(yubikey) {
        Ok(uuid) => uuid,
        Err(e) => {
            error!("Failed to read UUID from device certificate in CardAuthentication slot. Try resetting the device and re-enrolling: {e:?}");
            return Err(e);
        }
    };

    //----------------------------------------------------------------------------------
    // Phase 1
    //----------------------------------------------------------------------------------
    let (p1_challenge, p1_resp_url) = phase1(&oai.to_enroll_url(&uuid, agent_edipi), env).await?;

    //----------------------------------------------------------------------------------
    // Phase 2
    //----------------------------------------------------------------------------------
    let p2 = Phase2Request {
        CHALLENGE: p1_challenge.to_string(),
        SERIAL: yubikey.serial().to_string(),
        PRODUCT: yubikey.name().to_string(),
        VERSION: yubikey.version().to_string(),
        UDID: uuid.to_string(),
    };
    let mut p2_xml = vec![];
    if let Err(e) = plist::to_writer_xml(&mut p2_xml, &p2) {
        error!("Failed to encode Phase2 request: {e:?}");
        return Err(Error::Plist);
    }

    let cert = get_cert_from_slot(yubikey, CardAuthentication)?;

    let new_cert_bytes = phase2(yubikey, &p2_xml, &cert, &p1_resp_url, pin, mgmt_key, env).await?;
    let new_cert = match Certificate::from_der(&new_cert_bytes) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse new device certificate: {e:?}");
            return Err(Error::Asn1(e));
        }
    };

    //----------------------------------------------------------------------------------
    // Phase 3
    //----------------------------------------------------------------------------------
    let p3 = Phase3Request {
        SERIAL: yubikey.serial().to_string(),
        PRODUCT: yubikey.name().to_string(),
        VERSION: yubikey.version().to_string(),
        UDID: uuid.to_string(),
    };
    let mut p3_xml = vec![];
    if let Err(e) = plist::to_writer_xml(&mut p3_xml, &p3) {
        error!("Failed to encode Phase3 request: {e:?}");
        return Err(Error::Plist);
    }

    let enc_spki = new_cert.tbs_certificate.subject_public_key_info.to_der()?;
    let spki_ref = SubjectPublicKeyInfoRef::from_der(&enc_spki)?;

    let signer: YkSigner<'_, YubiRsa<Rsa2048>> =
        YkSigner::new(yubikey, CardAuthentication, spki_ref).map_err(|_| Error::Unrecognized)?;

    phase3(&signer, &p3_xml, &new_cert, &p1_resp_url).await
}
