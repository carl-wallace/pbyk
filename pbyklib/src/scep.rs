use plist::Dictionary;

use rsa::RsaPublicKey;
use sha2::Sha256;
use signature::Signer;

use cms::signed_data::SignedData;
use cms::{
    builder::{
        ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyEncryptionInfo,
        KeyTransRecipientInfoBuilder, SignedDataBuilder, SignerInfoBuilder,
    },
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::EncapsulatedContentInfo,
};
use const_oid::{
    db::rfc5912::{ID_CE_SUBJECT_ALT_NAME, ID_EXTENSION_REQ},
    ObjectIdentifier,
};
use der::{
    asn1::{BitString, Ia5String, OctetString, PrintableString, SetOfVec},
    Any, AnyRef, Decode, Encode, Tag,
};
use spki::SignatureBitStringEncoding;
use x509_cert::{
    attr::{Attribute, AttributeValue},
    ext::{
        pkix::{name::GeneralName, SubjectAltName},
        Extension,
    },
    request::{CertReq, CertReqInfo},
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoRef},
    Certificate,
};
use yubikey::{
    certificate::{write, CertInfo},
    piv::{AlgorithmId, SlotId},
    MgmKey, YubiKey, YubiKeySigningKey,
};

use crate::utils::{recipient_identifier_from_cert, signer_identifier_from_cert};
use crate::yubikey_utils::get_attestation_p7;
use crate::{
    log_debug, log_error,
    network::{get_ca_cert, post_body},
    utils::{generate_self_signed_cert, get_email_addresses, get_subject_name, verify_and_decrypt},
    Error, Result,
};

/// Generate signature over presented data using provided YubiKey, slot and public key from `cert`
/// with the Sha256 hash algorithm
fn sign_request(
    yubikey: &mut YubiKey,
    slot_id: SlotId,
    cert: &Certificate,
    data: &[u8],
) -> crate::Result<BitString> {
    let signer: YubiKeySigningKey<'_, Sha256> = YubiKeySigningKey::new(
        yubikey,
        slot_id,
        cert.tbs_certificate.subject_public_key_info.clone(),
    );

    match signer.try_sign(data) {
        Ok(sig) => match sig.to_bitstring() {
            Ok(res) => Ok(res),
            Err(e) => {
                log_error(&format!(
                    "Failed to encode signature as a BitString: {:?}",
                    e
                ));
                Err(Error::Asn1(e))
            }
        },
        Err(e) => {
            log_error(&format!(
                "Failed to generate signature using slot {slot_id}: {:?}",
                e
            ));
            Err(Error::Signature)
        }
    }
}

/// Returns tuple containing `Challenge` and `URL` values extracted from `scep_instructions`
fn get_challenge_and_url(scep_instructions: &Dictionary) -> Result<(String, String)> {
    let challenge = match scep_instructions.get("Challenge") {
        Some(challenge) => match challenge.as_string() {
            Some(s) => s,
            None => {
                log_error("Failed to read Challenge value as a string");
                return Err(Error::ParseError);
            }
        },
        None => return Err(Error::ParseError),
    };
    let url = match scep_instructions.get("URL") {
        Some(url) => match url.as_string() {
            Some(s) => s,
            None => {
                log_error("Failed to read URL value as a string");
                return Err(Error::ParseError);
            }
        },
        None => return Err(Error::ParseError),
    };
    Ok((challenge.to_string(), url.to_string()))
}

/// Returns set of attributes for inclusion in CSR
fn prepare_attributes(
    challenge: &str,
    email_addresses: &Vec<String>,
    attestation_p7: &[u8],
) -> Result<SetOfVec<Attribute>> {
    pub const ID_CHALLENGE_PASSWORD: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.7");
    pub const ID_PUREBRED_YUBIKEY_ATTESTATION_ATTRIBUTE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37623.26.4");

    // two attributes for Phase 2 (challenge and attestation), three for Phase 3 (also extension request with SKID and SAN)
    let mut challenge_value: SetOfVec<AttributeValue> = Default::default();
    let ps = PrintableString::try_from(String::from(challenge)).map_err(Error::Asn1)?;
    challenge_value
        .insert(Any::from(&ps))
        .map_err(Error::Asn1)?;
    let challenge_attr = Attribute {
        oid: ID_CHALLENGE_PASSWORD,
        values: challenge_value,
    };

    let mut attestation_value: SetOfVec<AttributeValue> = Default::default();
    attestation_value
        .insert(Any::from_der(attestation_p7).map_err(Error::Asn1)?)
        .map_err(Error::Asn1)?;
    let attestation_attr = Attribute {
        oid: ID_PUREBRED_YUBIKEY_ATTESTATION_ATTRIBUTE,
        values: attestation_value,
    };

    let mut attrs: SetOfVec<Attribute> = Default::default();
    let _ = attrs.insert(challenge_attr);
    let _ = attrs.insert(attestation_attr);

    if !email_addresses.is_empty() {
        let mut san_parts = vec![];
        for email in email_addresses {
            san_parts.push(GeneralName::Rfc822Name(
                Ia5String::new(&email).map_err(Error::Asn1)?,
            ));
        }
        let sans: Option<SubjectAltName> = match san_parts.is_empty() {
            true => None,
            false => Some(SubjectAltName(san_parts)),
        };

        let enc_san = sans.to_der().map_err(Error::Asn1)?;
        let exts = vec![Extension {
            extn_id: ID_CE_SUBJECT_ALT_NAME,
            critical: false,
            extn_value: OctetString::new(enc_san).map_err(Error::Asn1)?,
        }];
        let enc_exts = exts.to_der().map_err(Error::Asn1)?;

        let mut ext_req_value: SetOfVec<AttributeValue> = Default::default();
        ext_req_value
            .insert(Any::from_der(&enc_exts).map_err(Error::Asn1)?)
            .map_err(Error::Asn1)?;
        let ext_req_attr = Attribute {
            oid: ID_EXTENSION_REQ,
            values: ext_req_value,
        };
        let _ = attrs.insert(ext_req_attr);
    }
    Ok(attrs)
}

/// Returns a DER-encoded CertReq containing the provided `attributes` and information from `self_signed_cert`.
fn prepare_csr(
    yubikey: &mut YubiKey,
    slot_id: SlotId,
    self_signed_cert: &Certificate,
    attrs: SetOfVec<Attribute>,
    pin: &[u8],
    mgmt_key: &MgmKey,
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

    let enc_cri = cert_req_info.to_der().map_err(Error::Asn1)?;

    assert!(yubikey.verify_pin(pin).is_ok());
    assert!(yubikey.authenticate(mgmt_key.clone()).is_ok());

    let sig = match sign_request(yubikey, slot_id, self_signed_cert, &enc_cri) {
        Ok(sig) => sig,
        Err(e) => {
            log_error(&format!("Failed to sign CSR: {:?}", e));
            return Err(Error::Unrecognized);
        }
    };

    let cert_req = CertReq {
        info: cert_req_info,
        algorithm: self_signed_cert.signature_algorithm.clone(),
        signature: sig,
    };

    cert_req.to_der().map_err(Error::Asn1)
}

fn get_rsa_key_from_cert(cert: &Certificate) -> Result<RsaPublicKey> {
    let spki_bytes = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(Error::Asn1)?;
    let spki_ref = SubjectPublicKeyInfoRef::from_der(&spki_bytes).map_err(Error::Asn1)?;
    match RsaPublicKey::try_from(spki_ref) {
        Ok(r) => Ok(r),
        Err(e) => {
            log_error(&format!(
                "Failed to prepare RsaPublicKey from certificate: {:?}",
                e
            ));
            Err(Error::Unrecognized)
        }
    }
}

fn prepare_enveloped_data(csr_der: &[u8], ca_cert: &Certificate) -> Result<Vec<u8>> {
    let recipient_identifier = recipient_identifier_from_cert(ca_cert)?;
    let recipient_public_key = get_rsa_key_from_cert(ca_cert)?;

    let recipient_info_builder = KeyTransRecipientInfoBuilder::new(
        recipient_identifier,
        KeyEncryptionInfo::Rsa(recipient_public_key),
    )
    .map_err(|_| Error::Unrecognized)?;

    let mut enveloped_data_builder = EnvelopedDataBuilder::new(
        None,
        csr_der,                               // data to be encrypted...
        ContentEncryptionAlgorithm::Aes256Cbc, // ... with this algorithm
        None,
    )
    .map_err(|_| Error::Unrecognized)?;

    // Add recipient info. Multiple recipients are possible, but not used here.
    let enveloped_data = enveloped_data_builder
        .add_recipient_info(recipient_info_builder)
        .map_err(|_| Error::Unrecognized)?
        .build()
        .map_err(|_| Error::Unrecognized)?;

    let enveloped_data_der = enveloped_data.to_der().map_err(Error::Asn1)?;
    let content = AnyRef::try_from(enveloped_data_der.as_slice()).map_err(Error::Asn1)?;
    let content_info = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_ENVELOPED_DATA,
        content: Any::from(content),
    };

    content_info.to_der().map_err(Error::Asn1)
}

fn prepare_signed_data(
    yubikey: &mut YubiKey,
    slot_id: SlotId,
    self_signed_cert: Certificate,
    enc_ed: &[u8],
) -> Result<Vec<u8>> {
    let si = signer_identifier_from_cert(&self_signed_cert)?;

    let content = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: Some(Any::new(Tag::OctetString, enc_ed).map_err(Error::Asn1)?),
    };
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };

    let signer: YubiKeySigningKey<'_, Sha256> = YubiKeySigningKey::new(
        yubikey,
        slot_id,
        self_signed_cert
            .tbs_certificate
            .subject_public_key_info
            .clone(),
    );

    let external_message_digest = None;
    let mut signer_info_builder = SignerInfoBuilder::new(
        &signer,
        si,
        digest_algorithm.clone(),
        &content,
        external_message_digest,
    )
    .map_err(|_| Error::Unrecognized)?;

    const RFC8894_ID_MESSAGE_TYPE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.2");
    const RFC8894_ID_SENDER_NONCE: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.5");
    const RFC8894_ID_TRANSACTION_ID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.7");

    let mut message_type_value: SetOfVec<AttributeValue> = Default::default();
    let id = PrintableString::try_from(String::from("19")).map_err(Error::Asn1)?;
    message_type_value
        .insert(Any::from(&id))
        .map_err(Error::Asn1)?;
    let message_type = Attribute {
        oid: RFC8894_ID_MESSAGE_TYPE,
        values: message_type_value,
    };
    let mut sender_nonce_value: SetOfVec<AttributeValue> = Default::default();
    let nonce = OctetString::new([42; 32]).map_err(Error::Asn1)?;
    sender_nonce_value
        .insert(Any::new(Tag::OctetString, nonce.as_bytes()).map_err(Error::Asn1)?)
        .map_err(Error::Asn1)?;
    let sender_nonce = Attribute {
        oid: RFC8894_ID_SENDER_NONCE,
        values: sender_nonce_value,
    };
    let mut transaction_id_value: SetOfVec<AttributeValue> = Default::default();
    let id = PrintableString::try_from(String::from("Test Transaction ID")).map_err(Error::Asn1)?;
    transaction_id_value
        .insert(Any::from(&id))
        .map_err(Error::Asn1)?;
    let transaction_id = Attribute {
        oid: RFC8894_ID_TRANSACTION_ID,
        values: transaction_id_value,
    };

    signer_info_builder
        .add_signed_attribute(message_type)
        .map_err(|_| Error::Unrecognized)?;
    signer_info_builder
        .add_signed_attribute(sender_nonce)
        .map_err(|_| Error::Unrecognized)?;
    signer_info_builder
        .add_signed_attribute(transaction_id)
        .map_err(|_| Error::Unrecognized)?;

    let mut builder = SignedDataBuilder::new(&content);

    let signed_data_pkcs7 = builder
        .add_digest_algorithm(digest_algorithm)
        .map_err(|_| Error::Unrecognized)?
        .add_certificate(CertificateChoices::Certificate(self_signed_cert))
        .map_err(|_| Error::Unrecognized)?
        .add_signer_info(signer_info_builder)
        .map_err(|_| Error::Unrecognized)?
        .build()
        .map_err(|_| Error::Unrecognized)?;
    signed_data_pkcs7.to_der().map_err(Error::Asn1)
}

/// Processes a dictionary containing SCEP instructions and generates a fresh key and obtains a certificate
/// using a slot based on the `is_phase2` value and email addresses present in `scep_instructions`.
///
/// Where `is_phase2` is true, the CardAuthentication slot is used. If `is_phase2` is false the
/// `SubjectAltName` field in `scep_instructions` is searched for `rfc822Name` values. If any are
/// found, the Signature slot is used. Otherwise, the Authentication slot is used.
///
/// `scep_instructions` MUST contain `Challenge`, `URL` and `Subject` values.
pub async fn process_scep_payload(
    yubikey: &mut YubiKey,
    scep_instructions: &Dictionary,
    is_phase2: bool,
    pin: &[u8],
    mgmt_key: &MgmKey,
) -> crate::Result<Vec<u8>> {
    log_debug("Being process_scep_payload");
    if !scep_instructions.contains_key("Challenge")
        || !scep_instructions.contains_key("URL")
        || !scep_instructions.contains_key("Subject")
    {
        log_error("scep_instructions was missing one or more of Challenge, URL or Subject");
        return Err(Error::ParseError);
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
    ) {
        Ok(c) => c,
        Err(e) => {
            log_error(&format!(
                "Failed to generate self-signed certificate for {} using slot {slot_id}: {:?}",
                subject_name, e
            ));
            return Err(e);
        }
    };

    let attestation_p7 = get_attestation_p7(yubikey, slot_id)?;
    let get_ca_url = format!("{url}?operation=GetCACert");
    let pki_op_url = format!("{url}?operation=PKIOperation");
    let ca_cert = get_ca_cert(&get_ca_url).await?;
    let attrs = prepare_attributes(&challenge, &email_addresses, &attestation_p7)?;
    let csr_der = prepare_csr(yubikey, slot_id, &ss, attrs, pin, mgmt_key)?;
    let enc_ed = prepare_enveloped_data(&csr_der, &ca_cert)?;

    assert!(yubikey.verify_pin(pin).is_ok());
    assert!(yubikey.authenticate(mgmt_key.clone()).is_ok());
    let signed_data_pkcs7_der = prepare_signed_data(yubikey, slot_id, ss, &enc_ed)?;

    let result = match post_body(
        &pki_op_url,
        &signed_data_pkcs7_der,
        "application/x-pki-message",
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            log_error(&format!(
                "Failed to submit SCEP request to {pki_op_url}: {:?}",
                e
            ));
            return Err(Error::Network);
        }
    };

    let dec_content =
        verify_and_decrypt(yubikey, slot_id, result.as_slice(), false, pin, mgmt_key)?;

    let ci = ContentInfo::from_der(&dec_content).map_err(Error::Asn1)?;
    if ci.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        log_error(&format!(
            "Unexpected content type in SCEP response (expected ID_SIGNED_DATA): {:?}",
            ci.content_type
        ));
        return Err(Error::ParseError);
    }

    let bytes = ci.content.to_der().map_err(Error::Asn1)?;
    let sd = SignedData::from_der(bytes.as_slice()).map_err(Error::Asn1)?;

    if let Some(certs) = sd.certificates {
        if let Some(cert_choice) = certs.0.iter().next() {
            match cert_choice {
                CertificateChoices::Certificate(c) => {
                    let enc_cert = c.to_der().map_err(Error::Asn1)?;
                    let _ = write(
                        yubikey,
                        slot_id,
                        CertInfo::Uncompressed,
                        enc_cert.as_slice(),
                    );
                    return Ok(enc_cert);
                }
                _ => {
                    log_error("Unexpected CertificateChoice in SCEP response");
                    return Err(Error::Unrecognized);
                }
            }
        }
    }

    log_error("CertificateChoice not found in SCEP response");
    Err(Error::Unrecognized)
}
