//! Executes OTA protocol in support of Purebred enrollment

use std::io::Cursor;

use log::{error, info};
use plist::Value;

use cms::{content_info::ContentInfo, signed_data::SignedData};
use der::{Decode, Encode};
use x509_cert::Certificate;
use yubikey::{
    piv::{SlotId, SlotId::CardAuthentication},
    MgmKey, YubiKey,
};

use crate::{
    misc::{
        internal_utils::{get_as_string, get_encap_content, get_signed_data, verify_and_decrypt},
        network::{post_body, post_no_body},
        p12::import_p12,
        scep::process_scep_payload,
        yubikey_utils::{get_cert_from_slot, get_uuid_from_cert},
    },
    ota::{OtaActionInputs, Phase2Request, Phase3Request},
    Error, Result,
};

/// Execute the phase 1 portion of the OTA protocol as part of Purebred enrollment. Logs error
/// details before returning.
async fn phase1(url: &str) -> Result<Value> {
    info!("Executing Phase 1");

    let p1resp = post_no_body(url).await?;
    let ci = match ContentInfo::from_der(&p1resp) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse Phase 1 response as a ContentInfo: {e:?}");
            return Err(Error::Asn1(e));
        }
    };

    if ci.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        error!(
            "Phase 1 response contained unexpected content type: {:?}",
            ci.content_type
        );
        return Err(Error::ParseError);
    }

    let bytes = match ci.content.to_der() {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to encode Phase 1 content: {e:?}");
            return Err(Error::Asn1(e));
        }
    };

    let sd = match SignedData::from_der(bytes.as_slice()) {
        Ok(sd) => sd,
        Err(e) => {
            error!("Failed to parse Phase 1 content as SignedData: {e:?}");
            return Err(Error::Asn1(e));
        }
    };

    let xml = match get_encap_content(&sd.encap_content_info) {
        Ok(xml) => xml,
        Err(e) => {
            error!("Failed to read Phase 1 encapsulated content: {e:?}");
            return Err(e);
        }
    };

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

    let signed_data_pkcs7_der = match get_signed_data(
        yubikey,
        SlotId::CardAuthentication,
        self_signed_cert,
        phase2_req,
    ) {
        Ok(d) => d,
        Err(e) => {
            error! {"Failed to generate SignedData for Phase 2 request: {e:?}"};
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
        SlotId::CardAuthentication,
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

/// Execute the phase 3 portion of the OTA protocol to complete Purebred enrollment
async fn phase3(
    yubikey: &mut YubiKey,
    phase3_req: &[u8],
    ca_issued_device_cert: &Certificate,
    phase3_url: &str,
) -> Result<()> {
    info!("Executing Phase 3");
    let signed_data_pkcs7_der = get_signed_data(
        yubikey,
        SlotId::CardAuthentication,
        ca_issued_device_cert,
        phase3_req,
    )?;
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

/// Executes the OTA protocol (with encrypted phase 2 response) to complete Purebred enrollment
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
    let p1_resp = phase1(&oai.to_enroll_url(&uuid, agent_edipi)).await?;

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
            Some(s) => s,
            None => {
                error!("Failed to read Challenge value from Phase 1 response as a string");
                return Err(Error::ParseError);
            }
        },
        None => return Err(Error::ParseError),
    };

    let p1_resp_url = match p1_resp_payload.get("URL") {
        Some(url) => match url.as_string() {
            Some(s) => s,
            None => {
                error!("Failed to read URL value from Phase 1 response as a string");
                return Err(Error::ParseError);
            }
        },
        None => return Err(Error::ParseError),
    };

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

    let cert = get_cert_from_slot(yubikey, SlotId::CardAuthentication)?;

    let new_cert_bytes = phase2(yubikey, &p2_xml, &cert, p1_resp_url, pin, mgmt_key, env).await?;
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

    phase3(yubikey, &p3_xml, &new_cert, p1_resp_url).await
}
