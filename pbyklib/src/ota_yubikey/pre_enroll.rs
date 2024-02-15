//! Executes Pre-enroll (i.e., Phase 0) in preparation for Purebred enrollment of a YubiKey device

use log::{debug, info};

use sha1::Sha1;
use sha2::Digest;

use base64ct::{Base64, Encoding};
use der::Encode;

use yubikey::{
    piv::{AlgorithmId, SlotId},
    MgmKey, Uuid, YubiKey,
};

use crate::{
    misc::{network::post_body, utils::buffer_to_hex},
    misc_yubikey::utils::{generate_self_signed_cert, get_attestation_p7},
    ota::Preenroll,
    Error, Result,
};

/// Executes "Phase 0" to prepare a YubiKey for enrollment
///
/// A new key pair and self-signed certificate are generated using the [CardAuthentication](SlotId::CardAuthentication)
/// slot and an [attestation](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html)
/// is obtained for the new key. The new self-signed certificate and attestation are encoded as a
/// Preenroll message along with various other information, including the pre-enroll OTP, agent
/// EDIPI and information read from the YubiKey. The message is then sent to the portal identified
/// by the `base_url` parameter.
///
/// Upon success a string containing a hash of the self-signed certificate is returned.
///
/// # Arguments
/// * `yubikey` - handle to YubiKey to enroll
/// * `agent_edipi` - string containing 10 digit EDIPI of Purebred Agent who provided the `pre_enroll_otp` parameter
/// * `pre_enroll_otp`- string containing 8 digit time-limited one-time password value provided by Purebred Agent identified by the `agent_edipi` parameter
/// * `base_url` - base URI of Purebred portal to use to enroll YubiKey, for example, `https://pb2.redhoundsoftware.net`
pub async fn pre_enroll(
    yubikey: &mut YubiKey,
    agent_edipi: &str,
    pre_enroll_otp: &str,
    base_url: &str,
    pin: &[u8],
    mgmt_key: &MgmKey,
) -> Result<String> {
    info!("Pre-enrolling YubiKey with serial {}", yubikey.serial());

    let uuid = Uuid::new_v4();

    debug!("Generating self-signed device certificate");
    let self_signed_cert = generate_self_signed_cert(
        yubikey,
        SlotId::CardAuthentication,
        AlgorithmId::Rsa2048,
        format!("cn={uuid},c=US").as_str(),
        pin,
        mgmt_key,
    )?;

    debug!(
        "Generating attestation for self-signed certificate in {} slot",
        SlotId::CardAuthentication
    );
    let attestation_p7 = get_attestation_p7(yubikey, SlotId::CardAuthentication)?;
    let yubikey_attestation = Base64::encode_string(attestation_p7.as_slice());

    let der_cert = match self_signed_cert.to_der() {
        Ok(der_cert) => der_cert,
        Err(e) => return Err(Error::Asn1(e)),
    };
    let cb64 = Base64::encode_string(der_cert.as_slice());
    let hash = Sha1::digest(der_cert.as_slice()).to_vec();

    let preenroll = Preenroll {
        uuid: uuid.to_string(),
        edipi: agent_edipi.to_string(),
        serial: yubikey.serial().to_string(),
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
        Err(e) => return Err(e.into()),
    };

    debug!("Submitting pre-enrollment request");
    match post_body(
        format!("{base_url}/pb/admin_submit").as_str(),
        json_preenroll.as_bytes(),
        "application/json",
    )
    .await
    {
        Ok(_) => Ok(buffer_to_hex(hash.as_slice())),
        Err(e) => Err(e),
    }
}
