//! General-purpose SCEP-related utility functions

use log::error;
use plist::Dictionary;
use rand::rngs::OsRng;
use rand_core::TryRngCore;
use spki::EncodePublicKey;

use rsa::RsaPublicKey;

use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::CertificateChoices;
use cms::signed_data::EncapsulatedContentInfo;
use cms::{
    builder::{
        ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyEncryptionInfo,
        KeyTransRecipientInfoBuilder,
    },
    content_info::ContentInfo,
};
use const_oid::{
    db::rfc5912::{ID_CE_SUBJECT_ALT_NAME, ID_EXTENSION_REQ},
    ObjectIdentifier,
};
use der::{
    asn1::{Ia5String, OctetString, PrintableString, SetOfVec},
    Any, AnyRef, Decode, Encode, Tag,
};
use signature::{Keypair, Signer};
use spki::{AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier};
use x509_cert::{
    attr::{Attribute, AttributeValue},
    ext::{
        pkix::{name::GeneralName, SubjectAltName},
        Extension,
    },
    spki::SubjectPublicKeyInfoRef,
    Certificate,
};

use crate::misc::network::post_body;
use crate::misc::utils::recipient_identifier_from_cert;
use crate::misc::utils::signer_identifier_from_cert;
use crate::{
    Error, Result, ID_CHALLENGE_PASSWORD, RFC8894_ID_MESSAGE_TYPE, RFC8894_ID_SENDER_NONCE,
    RFC8894_ID_TRANSACTION_ID,
};

/// Returns tuple containing `Challenge` and `URL` values extracted from `scep_instructions`
pub fn get_challenge_and_url(scep_instructions: &Dictionary) -> Result<(String, String)> {
    let challenge = match scep_instructions.get("Challenge") {
        Some(challenge) => match challenge.as_string() {
            Some(s) => s,
            None => {
                error!("Failed to read Challenge value as a string");
                return Err(Error::ParseError);
            }
        },
        None => return Err(Error::ParseError),
    };
    let url = match scep_instructions.get("URL") {
        Some(url) => match url.as_string() {
            Some(s) => s,
            None => {
                error!("Failed to read URL value as a string");
                return Err(Error::ParseError);
            }
        },
        None => return Err(Error::ParseError),
    };
    Ok((challenge.to_string(), url.to_string()))
}

/// Returns set of attributes for inclusion in CSR
pub fn prepare_attributes(
    challenge: &str,
    email_addresses: &Vec<String>,
    attestation_p7: Option<&[u8]>,
    attestation_oid: &ObjectIdentifier,
) -> Result<SetOfVec<Attribute>> {
    // two attributes for Phase 2 (challenge and attestation), three for Phase 3 (also extension request with SKID and SAN)
    let mut challenge_value: SetOfVec<AttributeValue> = Default::default();
    let ps = PrintableString::try_from(String::from(challenge))?;
    challenge_value.insert(Any::from(&ps))?;
    let challenge_attr = Attribute {
        oid: *ID_CHALLENGE_PASSWORD,
        values: challenge_value,
    };

    let mut attrs: SetOfVec<Attribute> = Default::default();
    let _ = attrs.insert(challenge_attr);
    if let Some(attestation_p7) = attestation_p7 {
        let mut attestation_value: SetOfVec<AttributeValue> = Default::default();
        attestation_value.insert(Any::from_der(attestation_p7)?)?;
        let attestation_attr = Attribute {
            oid: *attestation_oid,
            values: attestation_value,
        };
        let _ = attrs.insert(attestation_attr);
    }

    if !email_addresses.is_empty() {
        let mut san_parts = vec![];
        for email in email_addresses {
            san_parts.push(GeneralName::Rfc822Name(Ia5String::new(&email)?));
        }
        let sans: Option<SubjectAltName> = match san_parts.is_empty() {
            true => None,
            false => Some(SubjectAltName(san_parts)),
        };

        let enc_san = sans.to_der()?;
        let exts = vec![Extension {
            extn_id: ID_CE_SUBJECT_ALT_NAME,
            critical: false,
            extn_value: OctetString::new(enc_san)?,
        }];
        let enc_exts = exts.to_der()?;

        let mut ext_req_value: SetOfVec<AttributeValue> = Default::default();
        ext_req_value.insert(Any::from_der(&enc_exts)?)?;
        let ext_req_attr = Attribute {
            oid: ID_EXTENSION_REQ,
            values: ext_req_value,
        };
        let _ = attrs.insert(ext_req_attr);
    }
    Ok(attrs)
}

/// Returns public key from a certificate as an RsaPublicKey
pub fn get_rsa_key_from_cert(cert: &Certificate) -> Result<RsaPublicKey> {
    let spki_bytes = cert.tbs_certificate().subject_public_key_info().to_der()?;
    let spki_ref = SubjectPublicKeyInfoRef::from_der(&spki_bytes)?;
    match RsaPublicKey::try_from(spki_ref) {
        Ok(r) => Ok(r),
        Err(e) => {
            error!("Failed to prepare RsaPublicKey from certificate: {e:?}");
            Err(Error::Unrecognized)
        }
    }
}

/// Prepares an EnvelopedData containing the given CSR with a key transport recipient based on given certificate.
pub fn prepare_enveloped_data(csr_der: &[u8], ca_cert: &Certificate) -> Result<Vec<u8>> {
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
    let mut rng = OsRng.unwrap_err();
    let enveloped_data = enveloped_data_builder
        .add_recipient_info(recipient_info_builder)
        .map_err(|_| Error::Unrecognized)?
        .build_with_rng(&mut rng)
        .map_err(|_| Error::Unrecognized)?;

    let enveloped_data_der = enveloped_data.to_der()?;
    let content = AnyRef::try_from(enveloped_data_der.as_slice())?;
    let content_info = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_ENVELOPED_DATA,
        content: Any::from(content),
    };

    Ok(content_info.to_der()?)
}

/// Prepares a SignedData object containing the given data, with SCEP-appropriate signer info, a signature generated
/// using the given signer and with the given certificate in the certificates bag.
pub fn prepare_scep_signed_data<S>(
    signer: &S,
    self_signed_cert: Certificate,
    enc_ed: &[u8],
) -> Result<Vec<u8>>
where
    S: Keypair + DynSignatureAlgorithmIdentifier + Signer<rsa::pkcs1v15::Signature>,
    <S as Keypair>::VerifyingKey: EncodePublicKey,
{
    let si = signer_identifier_from_cert(&self_signed_cert, true)?;

    let content = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: Some(Any::new(Tag::OctetString, enc_ed)?),
    };
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };

    let external_message_digest = None;
    let mut signer_info_builder = SignerInfoBuilder::new(
        si,
        digest_algorithm.clone(),
        &content,
        external_message_digest,
    )
    .map_err(|_| Error::Unrecognized)?;

    let mut message_type_value: SetOfVec<AttributeValue> = Default::default();
    let id = PrintableString::try_from(String::from("19"))?;
    message_type_value.insert(Any::from(&id))?;
    let message_type = Attribute {
        oid: *RFC8894_ID_MESSAGE_TYPE,
        values: message_type_value,
    };
    let mut sender_nonce_value: SetOfVec<AttributeValue> = Default::default();
    let nonce = OctetString::new([42; 32])?;
    sender_nonce_value.insert(Any::new(Tag::OctetString, nonce.as_bytes())?)?;
    let sender_nonce = Attribute {
        oid: *RFC8894_ID_SENDER_NONCE,
        values: sender_nonce_value,
    };
    let mut transaction_id_value: SetOfVec<AttributeValue> = Default::default();
    let id = PrintableString::try_from(String::from("Test Transaction ID"))?;
    transaction_id_value.insert(Any::from(&id))?;
    let transaction_id = Attribute {
        oid: *RFC8894_ID_TRANSACTION_ID,
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
        .add_signer_info(signer_info_builder, signer)
        .map_err(|_| Error::Unrecognized)?
        .build()
        .map_err(|_| Error::Unrecognized)?;
    Ok(signed_data_pkcs7.to_der()?)
}

/// Posts the given SCEP request to the given URL
pub async fn post_scep_request(pki_op_url: &str, signed_data_pkcs7_der: &[u8]) -> Result<Vec<u8>> {
    match post_body(
        pki_op_url,
        signed_data_pkcs7_der,
        "application/x-pki-message",
    )
    .await
    {
        Ok(r) => Ok(r),
        Err(e) => {
            error!("Failed to submit SCEP request to {pki_op_url}: {e:?}");
            Err(e)
        }
    }
}
