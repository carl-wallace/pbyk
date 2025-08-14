//! General-purpose SCEP-related utility functions

use log::{debug, error, info};
use plist::Dictionary;

use pbykcorelib::misc::scep::{
    get_challenge_and_url, post_scep_request, prepare_attributes, prepare_enveloped_data,
};
use signature::Signer as OtherSigner;

use cms::{cert::CertificateChoices, content_info::ContentInfo, signed_data::SignedData};
use der::{
    Decode, Encode,
    asn1::{BitString, SetOfVec},
};
use spki::SignatureBitStringEncoding;
use x509_cert::{
    Certificate,
    attr::Attribute,
    request::{CertReq, CertReqInfo},
    spki::SubjectPublicKeyInfoRef,
};
use yubikey::{
    MgmKeyOps, YubiKey,
    certificate::{
        CertInfo,
        yubikey_signer::{Rsa2048, YubiRsa},
    },
    piv::{AlgorithmId, SlotId},
};

use crate::{
    Error, ID_PUREBRED_YUBIKEY_ATTESTATION_ATTRIBUTE, Result,
    misc_yubikey::{
        utils::{generate_self_signed_cert, get_attestation_p7, verify_and_decrypt},
        yk_signer::YkSigner,
    },
};
use pbykcorelib::misc::utils::{get_email_addresses, get_subject_name};
use pbykcorelib::misc::{network::get_ca_cert, scep::prepare_scep_signed_data};

//------------------------------------------------------------------------------------
// Local methods
//------------------------------------------------------------------------------------
/// Generate signature over presented data using provided YubiKey, slot and public key from `cert`
/// with the Sha256 hash algorithm
fn sign_request(
    yubikey: &mut YubiKey,
    slot_id: SlotId,
    cert: &Certificate,
    data: &[u8],
) -> Result<BitString> {
    let enc_spki = cert.tbs_certificate().subject_public_key_info().to_der()?;
    let spki_ref = SubjectPublicKeyInfoRef::from_der(&enc_spki)?;
    let signer: yubikey::certificate::yubikey_signer::Signer<'_, YubiRsa<Rsa2048>> =
        yubikey::certificate::yubikey_signer::Signer::new(yubikey, slot_id, spki_ref)
            .map_err(|_| Error::Unrecognized)?;

    match signer.try_sign(data) {
        Ok(sig) => match sig.to_bitstring() {
            Ok(res) => Ok(res),
            Err(e) => {
                error!("Failed to encode signature as a BitString: {e:?}");
                Err(Error::Asn1(e))
            }
        },
        Err(e) => {
            error!("Failed to generate signature using slot {slot_id}: {e:?}");
            Err(Error::Signature)
        }
    }
}

/// Returns a DER-encoded CertReq containing the provided `attributes` and information from `self_signed_cert`.
fn prepare_csr<K: MgmKeyOps>(
    yubikey: &mut YubiKey,
    slot_id: SlotId,
    self_signed_cert: &Certificate,
    attrs: SetOfVec<Attribute>,
    pin: &[u8],
    mgmt_key: &K,
) -> Result<Vec<u8>> {
    let cert_req_info = CertReqInfo {
        version: Default::default(),
        subject: self_signed_cert.tbs_certificate().subject().clone(),
        public_key: self_signed_cert
            .tbs_certificate()
            .subject_public_key_info()
            .clone(),
        attributes: attrs,
    };

    let enc_cri = cert_req_info.to_der()?;

    if let Err(e) = yubikey.verify_pin(pin) {
        error!("Failed to verify PIN in prepare_csr: {e:?}");
        return Err(Error::YubiKey(e));
    }
    if let Err(e) = yubikey.authenticate(mgmt_key) {
        error!("Failed to authenticate using management key in prepare_csr: {e:?}");
        return Err(Error::YubiKey(e));
    }

    let sig = match sign_request(yubikey, slot_id, self_signed_cert, &enc_cri) {
        Ok(sig) => sig,
        Err(e) => {
            error!("Failed to sign CSR: {e:?}");
            return Err(Error::Unrecognized);
        }
    };

    let cert_req = CertReq {
        info: cert_req_info,
        algorithm: self_signed_cert.signature_algorithm().clone(),
        signature: sig,
    };

    Ok(cert_req.to_der()?)
}

//------------------------------------------------------------------------------------
// Public methods
//------------------------------------------------------------------------------------
/// Processes a dictionary containing SCEP instructions and generates a fresh key and obtains a certificate
/// using a slot based on the `is_phase2` value and email addresses present in `scep_instructions`.
///
/// Where `is_phase2` is true, the CardAuthentication slot is used. If `is_phase2` is false the
/// `SubjectAltName` field in `scep_instructions` is searched for `rfc822Name` values. If any are
/// found, the Signature slot is used. Otherwise, the Authentication slot is used.
///
/// `scep_instructions` MUST contain `Challenge`, `URL` and `Subject` values.
pub(crate) async fn process_scep_payload<K: MgmKeyOps>(
    yubikey: &mut YubiKey,
    scep_instructions: &Dictionary,
    is_phase2: bool,
    pin: &[u8],
    mgmt_key: &K,
    display: Option<String>,
    env: &str,
) -> Result<Vec<u8>> {
    if !scep_instructions.contains_key("Challenge")
        || !scep_instructions.contains_key("URL")
        || !scep_instructions.contains_key("Subject")
    {
        error!("scep_instructions was missing one or more of Challenge, URL or Subject");
        return Err(Error::ParseError);
    }

    if let Some(display) = &display {
        info!("Processing SCEP payload {display}");
    } else {
        info!("Processing SCEP payload");
    }

    let (challenge, url) = get_challenge_and_url(scep_instructions)?;
    let email_addresses = get_email_addresses(scep_instructions);
    let subject_name = get_subject_name(scep_instructions)?;

    let slot_id = match is_phase2 {
        true => SlotId::CardAuthentication,
        false => {
            if email_addresses.is_empty() {
                SlotId::Authentication
            } else {
                SlotId::Signature
            }
        }
    };

    let ss = match generate_self_signed_cert(
        yubikey,
        slot_id,
        AlgorithmId::Rsa2048,
        &subject_name.to_string(),
        pin,
        mgmt_key,
    ) {
        Ok(c) => c,
        Err(e) => {
            error!(
                "Failed to generate self-signed certificate for {subject_name} using slot {slot_id}: {e:?}"
            );
            return Err(e);
        }
    };

    let attestation_p7 = get_attestation_p7(yubikey, slot_id)?;
    let get_ca_url = format!("{url}?operation=GetCACert");
    let pki_op_url = format!("{url}?operation=PKIOperation");
    debug!("Obtaining RA certificate from {get_ca_url}");
    let ca_cert = get_ca_cert(&get_ca_url).await?;
    let attrs = prepare_attributes(
        &challenge,
        &email_addresses,
        Some(&attestation_p7),
        &ID_PUREBRED_YUBIKEY_ATTESTATION_ATTRIBUTE,
    )?;
    let csr_der = prepare_csr(yubikey, slot_id, &ss, attrs, pin, mgmt_key)?;
    let enc_ed = prepare_enveloped_data(&csr_der, &ca_cert)?;

    if let Err(e) = yubikey.verify_pin(pin) {
        error!("Failed to verify PIN in process_scep_payload: {e:?}");
        return Err(Error::YubiKey(e));
    }
    if let Err(e) = yubikey.authenticate(mgmt_key) {
        error!("Failed to authenticate using management key in process_scep_payload: {e:?}");
        return Err(Error::YubiKey(e));
    }
    let enc_spki = ss.tbs_certificate().subject_public_key_info().to_der()?;
    let spki_ref = SubjectPublicKeyInfoRef::from_der(&enc_spki)?;

    let signer: YkSigner<'_, YubiRsa<Rsa2048>> = match YkSigner::new(yubikey, slot_id, spki_ref) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to created YubiKey signer: {e:?}");
            return Err(Error::YubiKey(e));
        }
    };

    let signed_data_pkcs7_der = prepare_scep_signed_data(&signer, ss, &enc_ed)?;

    debug!("Submitting SCEP request to {pki_op_url}");
    let result = post_scep_request(&pki_op_url, &signed_data_pkcs7_der).await?;
    let dec_content = verify_and_decrypt(
        yubikey,
        slot_id,
        result.as_slice(),
        false,
        pin,
        mgmt_key,
        env,
    )
    .await?;

    let ci = ContentInfo::from_der(&dec_content)?;
    if ci.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        error!(
            "Unexpected content type in SCEP response (expected ID_SIGNED_DATA): {:?}",
            ci.content_type
        );
        return Err(Error::ParseError);
    }

    let bytes = ci.content.to_der()?;
    let sd = SignedData::from_der(bytes.as_slice())?;

    if let Some(certs) = sd.certificates {
        if let Some(cert_choice) = certs.0.iter().next() {
            return match cert_choice {
                CertificateChoices::Certificate(c) => {
                    let enc_cert = c.to_der()?;
                    let yc = yubikey::certificate::Certificate { cert: c.clone() };
                    let _ = yc.write(yubikey, slot_id, CertInfo::Uncompressed);
                    Ok(enc_cert)
                }
                _ => {
                    error!("Unexpected CertificateChoice in SCEP response");
                    Err(Error::Unrecognized)
                }
            };
        }
    }

    error!("CertificateChoice not found in SCEP response");
    Err(Error::Unrecognized)
}
