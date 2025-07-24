//! Executes OTA protocol in support of Purebred enrollment of a virtual smart card device

#![cfg(all(target_os = "windows", feature = "vsc"))]

use std::io::Cursor;

use log::error;
use plist::Value;
use windows::{Devices::SmartCards::SmartCard, Win32::Security::Cryptography::CERT_CONTEXT};

use der::Decode;
use x509_cert::Certificate;

use certval::PDVCertificate;

use pbykcorelib::misc::{
    network::post_body,
    utils::{get_as_string, get_signed_data},
};

use crate::misc_win::cert_store::delete_cert_from_store;
use crate::ota::phase3;
use crate::{
    Error,
    misc_win::{
        csr::get_credential_list,
        scep::process_scep_payload_vsc,
        utils::{import_p12_vsc, verify_and_decrypt_vsc},
        vsc_signer::CertContext,
        vsc_state::{get_version_and_product, get_vsc_id_and_uuid},
    },
    ota::{OtaActionInputs, Phase2Request, Phase3Request, phase1},
    utils::list_vscs::get_device_cred,
};

//------------------------------------------------------------------------------------
// Local methods
//------------------------------------------------------------------------------------
/// Execute the phase 2 portion of the OTA protocol as part of Purebred enrollment
async fn phase2(
    smart_card: &mut SmartCard,
    phase2_req: &[u8],
    signer: &CertContext,
    url: &str,
    env: &str,
) -> crate::Result<Vec<u8>> {
    let self_signed_cert = signer.cert();
    let signed_data_pkcs7_der =
        match get_signed_data(signer, self_signed_cert, phase2_req, None, true) {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to generate SignedData for Phase 2 request: {e:?}");
                return Err(Error::Pbykcorelib(e));
            }
        };

    let p2resp = post_body(
        url,
        &signed_data_pkcs7_der,
        "application/pkcs7-signature; charset=utf-8",
    )
    .await?;

    let phase2_resp_xml = verify_and_decrypt_vsc(signer, &p2resp, true, env).await?;

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

        process_scep_payload_vsc(
            smart_card,
            pc,
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
        let friendly_name = match profile2_dict.get("DisplayName") {
            Some(pc) => match pc.as_string() {
                Some(d) => d,
                None => {
                    error!("Failed to parse Password as a data for PKCS #12 payload.");
                    return Err(Error::Plist);
                }
            },
            None => "PKCS #12",
        };
        import_p12_vsc(smart_card, payload_content, password, friendly_name).await
    }
}

//------------------------------------------------------------------------------------
// Local methods
//------------------------------------------------------------------------------------

/// Executes OTA protocol to obtain a CA-issued certificate for the given virtual smartcard (VSC).
///
/// # Arguments
/// * `smartcard` - handle to SmartCard to enroll
/// * `agent_edipi` - string containing 10 digit EDIPI of Purebred Agent who provided the `otp` field of the `oai` parameter
/// * `oai` - structure containing information used to prepare URI to execute OTA protocol
/// * `env` - identifies the environment in which enrollment is being performed, i.e., DEV, NIPR, SIPR, OM_NIPR, OM_SIPR
pub async fn enroll(
    smartcard: &mut SmartCard,
    agent_edipi: &str,
    oai: &OtaActionInputs,
    env: &str,
) -> crate::Result<()> {
    let reader = smartcard.Reader()?.Name()?;
    let (vsc_id, uuid) = get_vsc_id_and_uuid(&reader)?;
    let (os_version, _os_version_short, product) = get_version_and_product()?;

    //----------------------------------------------------------------------------------
    // Phase 1
    //----------------------------------------------------------------------------------
    let (p1_challenge, p1_resp_url) = phase1(&oai.to_enroll_url(&uuid, agent_edipi), env).await?;

    //----------------------------------------------------------------------------------
    // Phase 2
    //----------------------------------------------------------------------------------
    let p2 = Phase2Request {
        CHALLENGE: p1_challenge.to_string(),
        SERIAL: vsc_id.clone(),
        PRODUCT: product.clone(),
        VERSION: os_version.clone(),
        UDID: uuid.to_string(),
    };
    let mut p2_xml = vec![];
    if let Err(e) = plist::to_writer_xml(&mut p2_xml, &p2) {
        error!("Failed to encode Phase2 request: {e:?}");
        return Err(Error::Plist);
    }

    let cert = get_device_cred(&uuid, true)?;
    let new_cert_bytes = phase2(smartcard, &p2_xml, &cert, &p1_resp_url, env).await?;

    unsafe {
        let ctx = cert.cert_ctx.as_ptr() as *const CERT_CONTEXT;
        let self_signed_bytes =
            std::slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize);
        delete_cert_from_store(self_signed_bytes);
    }

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
        SERIAL: vsc_id,
        PRODUCT: product,
        VERSION: os_version,
        UDID: uuid.to_string(),
    };
    let mut p3_xml = vec![];
    if let Err(e) = plist::to_writer_xml(&mut p3_xml, &p3) {
        error!("Failed to encode Phase3 request: {e:?}");
        return Err(Error::Plist);
    }

    let ccc = match PDVCertificate::try_from(new_cert.clone()) {
        Ok(ccc) => ccc,
        Err(e) => {
            error!("Failed to parse certificate obtained following Phase 2 with: {e:?}");
            return Err(Error::Asn1(e));
        }
    };
    let cc = match get_credential_list(Some(ccc)) {
        Ok(cc) => cc,
        Err(e) => {
            error!(
                "Failed to get credential corresponding to certificate obtained following Phase 2 with: {e:?}"
            );
            return Err(e);
        }
    };

    let wcc = match cc.first() {
        Some(wcc) => wcc,
        None => {
            error!(
                "Failed to select credential corresponding to certificate obtained following Phase 2."
            );
            return Err(Error::Vsc);
        }
    };
    phase3(wcc, &p3_xml, &new_cert, &p1_resp_url).await
}
