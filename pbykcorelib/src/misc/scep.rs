//! General-purpose SCEP-related utility functions

use log::error;
use plist::Dictionary;

use crate::misc::rng::pb_rng;

use rsa::PublicKey as RsaPublicKey;

use certval_cms::{
    ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyTransRecipient, KeyTransportAlgorithm,
};
use const_oid::{
    ObjectIdentifier,
    db::{
        rfc5911::ID_DATA,
        rfc5912::{ID_CE_SUBJECT_ALT_NAME, ID_EXTENSION_REQ},
    },
};
use der::{
    Any, Decode, Encode, Tag,
    asn1::{Ia5String, OctetString, PrintableString, SetOfVec},
};
use signature::Signer;
use spki::{DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding};
use x509_cert::{
    Certificate,
    attr::{Attribute, AttributeValue},
    ext::{
        Extension,
        pkix::{SubjectAltName, name::GeneralName},
    },
    spki::SubjectPublicKeyInfoRef,
};

use crate::{
    Error, ID_CHALLENGE_PASSWORD, RFC8894_ID_MESSAGE_TYPE, RFC8894_ID_SENDER_NONCE,
    RFC8894_ID_TRANSACTION_ID, Result,
    misc::{
        network::post_body,
        pki::{new_cms_environment, new_pki_environment},
        utils::build_signed_data,
    },
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
    // Refuse anything but HTTPS. The reqwest client used downstream is not
    // built with `https_only(true)`, enrollment could run in
    // cleartext. Compare-ignore-ascii-case because URI schemes are
    // case-insensitive per RFC 3986.
    if !url
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
    {
        error!("Refusing non-HTTPS SCEP URL: {url}");
        return Err(Error::BadInput);
    }
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
///
/// The content is encrypted with AES-256-CBC and the key transported with RSAES-PKCS1-v1_5, which
/// is what the RA decrypts. The certificate is not vetted here: `get_ca_cert` validated it when it
/// was fetched.
pub fn prepare_enveloped_data(csr_der: &[u8], ca_cert: &Certificate) -> Result<Vec<u8>> {
    let env = new_cms_environment(new_pki_environment());
    let recipient = KeyTransRecipient::from_certificate(
        &env,
        ca_cert,
        None,
        KeyTransportAlgorithm::RsaPkcs1v15,
    )
    .map_err(|e| {
        error!("Failed to prepare the RA certificate as a key transport recipient: {e}");
        Error::from(e)
    })?;
    let content_info = EnvelopedDataBuilder::new(csr_der, ContentEncryptionAlgorithm::Aes256Cbc)?
        .add_recipient(recipient)
        .build_content_info(&env, &mut pb_rng())
        .map_err(|e| {
            error!("Failed to build EnvelopedData: {e}");
            Error::from(e)
        })?;
    Ok(content_info.to_der()?)
}

/// Prepares a SignedData object containing the given data, with SCEP-appropriate signer info, a signature generated
/// using the given signer and with the given certificate in the certificates bag.
pub fn prepare_scep_signed_data<S, Sig>(
    signer: &S,
    self_signed_cert: Certificate,
    enc_ed: &[u8],
) -> Result<Vec<u8>>
where
    S: Signer<Sig> + DynSignatureAlgorithmIdentifier,
    Sig: SignatureBitStringEncoding,
{
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

    build_signed_data(
        signer,
        self_signed_cert,
        enc_ed,
        ID_DATA,
        vec![message_type, sender_nonce, transaction_id],
    )
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
