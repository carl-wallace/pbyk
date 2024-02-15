//! Executes Pre-enroll (i.e., Phase 0) in preparation for Purebred enrollment of a virtual smart card device

#![cfg(all(target_os = "windows", feature = "vsc"))]

use log::{debug, info};
use windows::Devices::SmartCards::SmartCard;

use base64ct::{Base64, Encoding};
use sha1::Sha1;
use sha2::Digest;

use crate::{
    misc::{network::post_body, utils::buffer_to_hex},
    misc_win::utils::generate_self_signed_cert_vsc,
    misc_win::vsc_state::{get_version_and_product, get_vsc_id_and_uuid},
    ota::VscPreenroll,
    Result,
};

/// Executes "Phase 0" to prepare a TPM-based virtual smart card (VSC) for enrollment
///
/// A new key pair and self-signed certificate are generated using the provided SmartCard object and, if possible, an
/// is obtained for the new key. Attestation generation is inconsistent. On Windows 10 systems, it generally works but
/// on Windows 11 systems, elevated permissions appear to be required. Attestation support is described in these sources:
///    - <https://msdn.microsoft.com/en-us/library/mt242068.aspx>
///    - <https://msdn.microsoft.com/en-us/library/dn408990.aspx>
///    - Section 10.1.1.8 of <https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.99.pdf>
///    - <https://github.com/Microsoft/TSS.MSR/blob/master/PCPTool.v11/inc/TpmAtt.h>
///
/// The new self-signed certificate and attestation are encoded as a Preenroll message along with various other
/// information, including the pre-enroll OTP, agent EDIPI and information read from the YubiKey. The message is then
/// sent to the portal identified by the `base_url` parameter.
///
/// Upon success a string containing a hash of the self-signed certificate is returned.
///
/// # Arguments
/// * `smartcard` - handle to SmartCard to enroll
/// * `agent_edipi` - string containing 10 digit EDIPI of Purebred Agent who provided the `pre_enroll_otp` parameter
/// * `pre_enroll_otp`- string containing 8 digit time-limited one-time password value provided by Purebred Agent identified by the `agent_edipi` parameter
/// * `base_url` - base URI of Purebred portal to use to enroll YubiKey, for example, `https://pb2.redhoundsoftware.net`
pub async fn pre_enroll(
    smartcard: &mut SmartCard,
    agent_edipi: &str,
    pre_enroll_otp: &str,
    base_url: &str,
) -> Result<String> {
    let reader = smartcard.Reader()?.Name()?;
    info!("Pre-enrolling VSC with name {}", reader);

    let (os_version, os_version_short, product) = get_version_and_product()?;
    let (vsc_id, uuid) = get_vsc_id_and_uuid(&reader)?;
    debug!("vsc_id: {vsc_id}; uuid: {uuid}");

    debug!("Generating self-signed device certificate");
    let (der_cert, microsoft_attestation) =
        generate_self_signed_cert_vsc(format!("cn={uuid},c=US").as_str(), smartcard).await?;

    let pre_enroll = VscPreenroll {
        uuid,
        edipi: agent_edipi.to_string(),
        serial: vsc_id,
        certificate: Base64::encode_string(der_cert.as_slice()),
        otp: pre_enroll_otp.to_string(),
        device_type: "Windows".to_string(),
        os: os_version_short.clone(),
        product,
        microsoft_attestation,
        version: os_version,
    };

    let json_pre_enroll = match serde_json::to_string(&pre_enroll) {
        Ok(json) => json,
        Err(e) => return Err(e.into()),
    };

    debug!("Submitting pre-enrollment request");
    match post_body(
        format!("{base_url}/pb/admin_submit").as_str(),
        json_pre_enroll.as_bytes(),
        "application/json",
    )
    .await
    {
        Ok(_) => Ok(buffer_to_hex(&Sha1::digest(der_cert))),
        Err(e) => Err(e),
    }
}
