//! Executed Pre-enroll (i.e., Phase 0) in preparation for Purebred enrollment

use log::{debug, info};

use sha1::Sha1;
use sha2::Digest;

use base64ct::{Base64, Encoding};
use der::Encode;

use yubikey::{
    piv::{AlgorithmId, SlotId},
    Uuid, YubiKey,
};

use crate::{
    misc::{
        internal_utils::{buffer_to_hex, generate_self_signed_cert},
        network::post_body,
        yubikey_utils::get_attestation_p7,
    },
    ota::Preenroll,
    Error, Result,
};

/// The `pre_enroll` function interacts with the Purebred portal to prepare a YubiKey for enrollment
pub async fn pre_enroll(
    yubikey: &mut YubiKey,
    agent_edipi: &str,
    serial: &str,
    pre_enroll_otp: &str,
    host: &str,
) -> Result<String> {
    info!("Pre-enrolling YubiKey with serial {serial}");

    let uuid = Uuid::new_v4();

    debug!("Generating self-signed device certificate");
    let self_signed_cert = generate_self_signed_cert(
        yubikey,
        SlotId::CardAuthentication,
        AlgorithmId::Rsa2048,
        format!("c=US,cn={uuid}").as_str(),
    )?;

    debug!(
        "Generating attestation for self-signed certificate in {} slot",
        SlotId::CardAuthentication
    );
    let attestation_p7 = get_attestation_p7(yubikey, SlotId::CardAuthentication)?;
    let yubikey_attestation = Base64::encode_string(attestation_p7.as_slice());

    let cder = match self_signed_cert.to_der() {
        Ok(cder) => cder,
        Err(e) => return Err(Error::Asn1(e)),
    };
    let cb64 = Base64::encode_string(cder.as_slice());
    let hash = Sha1::digest(cder.as_slice()).to_vec();

    let preenroll = Preenroll {
        uuid: uuid.to_string(),
        edipi: agent_edipi.to_string(),
        serial: serial.to_string(),
        certificate: cb64,
        otp: pre_enroll_otp.to_string(),
        device_type: "Yubikey".to_string(),
        os: yubikey.version().to_string(),
        product: yubikey.name().to_string(),
        yubikey_attestation,
        version: yubikey.version().to_string(),
    };

    let json_preenroll = match serde_json::to_string(&preenroll) {
        Ok(json) => json,
        Err(_e) => return Err(Error::Unrecognized),
    };

    debug!("Submitting pre-enrollment request");
    match post_body(
        format!("{host}/pb/admin_submit").as_str(),
        json_preenroll.as_bytes(),
        "application/json",
    )
    .await
    {
        Ok(_) => Ok(buffer_to_hex(hash.as_slice())),
        Err(e) => Err(e),
    }
}
