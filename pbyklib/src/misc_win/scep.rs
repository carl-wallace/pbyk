//! Windows-specific utility functions related to SCEP processing for use within pbyklib

use log::{debug, error, info};
use plist::Dictionary;
use windows::{
    Devices::SmartCards::SmartCard,
    Security::Cryptography::Certificates::{CertificateEnrollmentManager, InstallOptions},
    core::HSTRING,
};

use base64ct::{Base64, Encoding};
use cms::{cert::CertificateChoices, content_info::ContentInfo, signed_data::SignedData};
use der::{
    Decode, Encode,
    asn1::{BitString, SetOfVec},
};
use signature::Signer;
use spki::SignatureBitStringEncoding;
use x509_cert::{
    Certificate,
    attr::Attribute,
    request::{CertReq, CertReqInfo},
};

#[cfg(all(feature = "vsc", feature = "reset_vsc"))]
use crate::misc_win::vsc_state::{read_saved_state_or_default, save_state};
#[cfg(all(feature = "vsc", feature = "reset_vsc"))]
use crate::utils::get_vsc_id_from_serial;
use certval::PDVCertificate;
#[cfg(all(feature = "vsc", feature = "reset_vsc"))]
use certval::buffer_to_hex;
use der::zeroize::Zeroize;
#[cfg(all(feature = "vsc", feature = "reset_vsc"))]
use sha2::{Digest, Sha256};

use crate::misc_win::cert_store::delete_cert_from_store;
use crate::{
    Error, ID_PUREBRED_MICROSOFT_ATTESTATION_ATTRIBUTE, Result,
    misc_win::{
        csr::{get_credential_list, get_key_provider_info, prepare_base64_certs_only_p7},
        utils::{generate_csr, generate_self_signed_cert_vsc, verify_and_decrypt_vsc},
        vsc_signer::CertContext,
    },
};
use pbykcorelib::misc::{
    network::get_ca_cert,
    scep::{
        get_challenge_and_url, post_scep_request, prepare_attributes, prepare_enveloped_data,
        prepare_scep_signed_data,
    },
    utils::{get_email_addresses, get_subject_name},
};

/// Generate signature over presented data using provided YubiKey, slot and public key from `cert`
/// with the Sha256 hash algorithm
fn sign_scep_request_vsc(signer: &CertContext, data: &[u8]) -> Result<BitString> {
    match signer.try_sign(data) {
        Ok(sig) => match sig.to_bitstring() {
            Ok(res) => Ok(res),
            Err(e) => {
                error!("Failed to encode signature as a BitString: {e:?}");
                Err(Error::Asn1(e))
            }
        },
        Err(e) => {
            error!("Failed to generate signature using VSC: {e:?}");
            Err(Error::Signature)
        }
    }
}

/// Gets VSC ID or an empty string
#[cfg(all(feature = "vsc", feature = "reset_vsc"))]
pub(crate) fn get_vsc_id_from_smartcard(sc: &SmartCard) -> String {
    match sc.Reader() {
        Ok(r) => match r.Name() {
            Ok(n) => {
                return get_vsc_id_from_serial(&n.to_string()).unwrap_or("".to_string());
            }
            Err(e) => {
                error!("Failed to read smart card reader name: {e:?}");
            }
        },
        Err(e) => {
            error!("Failed to read smart card reader: {e:?}");
        }
    }
    "".to_string()
}

/// Returns a DER-encoded CertReq containing the provided `attributes` and information from `self_signed_cert`.
fn prepare_scep_request_vsc(
    cred: &CertContext,
    self_signed_cert: &Certificate,
    attrs: SetOfVec<Attribute>,
) -> Result<Vec<u8>> {
    let cert_req_info = CertReqInfo {
        version: Default::default(),
        subject: self_signed_cert.tbs_certificate.subject.clone(),
        public_key: self_signed_cert
            .tbs_certificate
            .subject_public_key_info
            .clone(),
        attributes: attrs,
    };

    let enc_cri = cert_req_info.to_der()?;

    let sig = match sign_scep_request_vsc(cred, &enc_cri) {
        Ok(sig) => sig,
        Err(e) => {
            error!("Failed to sign CSR: {e:?}");
            return Err(Error::Unrecognized);
        }
    };

    let cert_req = CertReq {
        info: cert_req_info,
        algorithm: self_signed_cert.signature_algorithm.clone(),
        signature: sig,
    };

    Ok(cert_req.to_der()?)
}

/// Processes a dictionary containing SCEP instructions and generates a fresh key and obtains a certificate
/// using a slot based on the `is_phase2` value and email addresses present in `scep_instructions`.
///
/// Where `is_phase2` is true, the CardAuthentication slot is used. If `is_phase2` is false the
/// `SubjectAltName` field in `scep_instructions` is searched for `rfc822Name` values. If any are
/// found, the Signature slot is used. Otherwise, the Authentication slot is used.
///
/// `scep_instructions` MUST contain `Challenge`, `URL` and `Subject` values.
pub(crate) async fn process_scep_payload_vsc(
    sc: &mut SmartCard,
    scep_instructions: &Dictionary,
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

    let friendly_name = if let Some(display) = &display {
        info!("Processing SCEP payload {display}");
        display.clone()
    } else {
        // only hit here if the SCEP payload has not display name (this ought not happen)
        info!("Processing SCEP payload");
        "Purebred Certificate".to_string()
    };

    let (challenge, url) = get_challenge_and_url(scep_instructions)?;
    let email_addresses = get_email_addresses(scep_instructions);
    let subject_name = get_subject_name(scep_instructions)?;

    let (self_signed_bytes, attestation) =
        match generate_self_signed_cert_vsc(&subject_name.to_string(), sc).await {
            Ok(c) => c,
            Err(e) => {
                error!(
                    "Failed to generate self-signed certificate for {subject_name} using VSC: {e:?}"
                );
                return Err(e);
            }
        };

    let ssc = Certificate::from_der(&self_signed_bytes)?;
    let ssc2 = Certificate::from_der(&self_signed_bytes)?;
    let ss_cert = PDVCertificate::try_from(ssc)?;
    let cred = get_credential_list(Some(ss_cert))?;

    let attestation_bytes = match attestation {
        Some(attestation_p7) => {
            let stripped = attestation_p7.replace(['\r', '\n'], "");
            Some(Base64::decode_vec(&stripped)?)
        }
        None => None,
    };

    // let attestation_p7 = get_attestation_p7(yubikey, slot_id)?;
    let get_ca_url = format!("{url}?operation=GetCACert");
    let pki_op_url = format!("{url}?operation=PKIOperation");
    debug!("Obtaining RA certificate from {get_ca_url}");
    let ca_cert = get_ca_cert(&get_ca_url).await?;
    let attrs = prepare_attributes(
        &challenge,
        &email_addresses,
        attestation_bytes.as_deref(),
        &ID_PUREBRED_MICROSOFT_ATTESTATION_ATTRIBUTE,
    )?;
    let cred = match cred.first() {
        Some(cred) => cred,
        None => {
            error!("Failed to retrieve signing credential for self-signed certificate");
            return Err(Error::Unrecognized);
        }
    };
    let csr_der = prepare_scep_request_vsc(cred, &ssc2, attrs)?;
    let enc_ed = prepare_enveloped_data(&csr_der, &ca_cert)?;

    let signed_data_pkcs7_der = prepare_scep_signed_data(cred, ssc2, &enc_ed)?;

    debug!("Submitting SCEP request to {pki_op_url}");
    let result = post_scep_request(&pki_op_url, &signed_data_pkcs7_der).await?;
    let dec_content = verify_and_decrypt_vsc(cred, result.as_slice(), false, env).await?;

    let ci = ContentInfo::from_der(&dec_content)?;
    if ci.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        error!(
            "Unexpected content type in SCEP response (expected ID_SIGNED_DATA): {:?}",
            ci.content_type
        );
        return Err(Error::ParseError);
    }

    let mut der_signed_data = ci.content.to_der()?;
    let sd = SignedData::from_der(der_signed_data.as_slice())?;
    der_signed_data.zeroize();

    #[cfg(all(feature = "vsc", feature = "reset_vsc"))]
    let mut win_state = read_saved_state_or_default();
    #[cfg(all(feature = "vsc", feature = "reset_vsc"))]
    let reader = get_vsc_id_from_smartcard(sc);
    if let Some(certs) = sd.certificates {
        if let Some(cert_choice) = certs.0.iter().next() {
            match cert_choice {
                CertificateChoices::Certificate(c) => {
                    let enc_cert = c.to_der()?;

                    #[cfg(all(feature = "vsc", feature = "reset_vsc"))]
                    if !reader.is_empty() {
                        let hash = Sha256::digest(&enc_cert);
                        let hex_hash = buffer_to_hex(&hash);
                        win_state.add_cert_hash_for_reader(&reader, &hex_hash);
                        let _ = save_state(&win_state);
                    }

                    let container_name = get_key_provider_info(cred)?.get_container_name()?;

                    // generate a CSR so we can try to install again
                    let _csr_to_discard = generate_csr(
                        &subject_name.to_string(),
                        sc,
                        false,
                        Some(container_name.clone()),
                        &friendly_name,
                    )
                    .await?;

                    let ss_p7 = prepare_base64_certs_only_p7(c)?;
                    if let Err(e) =
                        CertificateEnrollmentManager::UserCertificateEnrollmentManager()?
                            .InstallCertificateAsync(
                                &HSTRING::from(ss_p7),
                                InstallOptions::DeleteExpired,
                            )?
                            .get()
                    {
                        error!(
                            "Failed to install self-signed certificate in generate_self_signed_cert: {e:?}"
                        );
                        return Err(Error::Unrecognized);
                    }

                    delete_cert_from_store(&self_signed_bytes);

                    return Ok(enc_cert);
                }
                _ => {
                    error!("Unexpected CertificateChoice in SCEP response");
                    return Err(Error::Unrecognized);
                }
            }
        }
    }

    error!("CertificateChoice not found in SCEP response");
    Err(Error::Unrecognized)
}
