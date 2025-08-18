//! Utility functions for use within pbyklib

use std::{collections::BTreeMap, io::Cursor, str::FromStr};

use log::error;
use plist::Dictionary;
use subtle_encoding::hex;

use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::{Keypair, Signer};

use cms::{
    builder::{SignedDataBuilder, SignerInfoBuilder},
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::ContentInfo,
    enveloped_data::RecipientIdentifier,
    signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo},
};
use const_oid::{
    db::{
        rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER, rfc5911::ID_MESSAGE_DIGEST,
        rfc5912::ID_CE_BASIC_CONSTRAINTS,
    },
    ObjectIdentifier,
};
use der::{asn1::OctetString, Any, AnyRef, Decode, Encode, Tag};
use spki::{AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey};
use x509_cert::{
    ext::pkix::{BasicConstraints, SubjectKeyIdentifier},
    name::Name,
    Certificate,
};

use certval::PkiEnvironment;

use crate::{misc::pki::validate_cert, Error, Result};

//------------------------------------------------------------------------------------
// Local methods
//------------------------------------------------------------------------------------
/// Takes a buffer containing hash of content to compare to value in message digest attribute. Returns
/// Ok if the value matches and an Err if it does not match or there is no message digest attribute.
fn check_message_digest_attr(
    hash: &BTreeMap<ObjectIdentifier, Vec<u8>>,
    si: &SignerInfo,
) -> Result<()> {
    if let Some(attrs) = &si.signed_attrs {
        for attr in attrs.iter() {
            if attr.oid == ID_MESSAGE_DIGEST {
                for value in attr.values.iter() {
                    if value.value() == hash[&si.digest_alg.oid] {
                        return Ok(());
                    }
                }
                error!("Message digest attribute did not contain expected value");
                return Err(Error::UnexpectedValue);
            }
        }
    }
    error!("No message digest attribute was found");
    Err(Error::MissingAttribute)
}

/// Accepts a SignedData object and some content to hash. Generates a hash for each hash algorithm
/// indicated in the digest_algorithms field and returns a map containing with results with an
/// ObjectIdentifier that identifies the hash algorithm used as map key.
///
/// Supports SHA256, SHA384 and SHA512. Ignores other values and logs an error.
fn hash_content(sd: &SignedData, content: &[u8]) -> Result<BTreeMap<ObjectIdentifier, Vec<u8>>> {
    let mut map = BTreeMap::new();
    for alg in sd.digest_algorithms.iter() {
        match alg.oid {
            const_oid::db::rfc5912::ID_SHA_256 => {
                let mut hasher = Sha256::new();
                hasher.update(content);
                let hash = hasher.finalize().to_vec();
                map.insert(alg.oid, hash);
            }
            const_oid::db::rfc5912::ID_SHA_384 => {
                let mut hasher = Sha384::new();
                hasher.update(content);
                let hash = hasher.finalize().to_vec();
                map.insert(alg.oid, hash);
            }
            const_oid::db::rfc5912::ID_SHA_512 => {
                let mut hasher = Sha512::new();
                hasher.update(content);
                let hash = hasher.finalize().to_vec();
                map.insert(alg.oid, hash);
            }
            _ => {
                error!(
                    "Unexpected hash algorithm found in SignedData::digest_algorithms field: {}",
                    alg.oid
                );
            }
        }
    }
    Ok(map)
}

/// Accepts a cert and returns true if BasicConstraints is found with isCA set to true, false if
/// BasicConstraints is found with isCA set to false or no BasicConstraints is found, and an error
/// if BasicConstraints is found but cannot be parsed.
fn is_ca(cert: &Certificate) -> Result<bool> {
    match cert.tbs_certificate().extensions() {
        Some(extensions) => {
            for ext in extensions {
                if ext.extn_id == ID_CE_BASIC_CONSTRAINTS {
                    let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())?;
                    return Ok(bc.ca);
                }
            }
            Ok(false)
        }
        None => Ok(false),
    }
}
/// Accepts a SignedData that is expected to have only one SignerInfo. It traverses the list of
/// certificates in the certificates field and returns a tuple containing a (possibly empty) vector
/// of CA certificates and an end entity certificate, if present. BasicConstraints is used to
/// categorize certificates. If more than one end entity certificate is encountered, the last one in
/// the list is returned.
fn get_candidate_signer_cert(sd: &SignedData) -> Result<(Vec<Certificate>, Certificate)> {
    let mut cas = vec![];
    let mut candidate_signer_cert = None;

    match &sd.certificates {
        Some(certs) => {
            for cert_choice in certs.0.iter() {
                match cert_choice {
                    CertificateChoices::Certificate(cert) => {
                        if is_ca(cert)? {
                            cas.push(cert.clone());
                        } else {
                            candidate_signer_cert = Some(cert.clone());
                        }
                    }
                    _ => {
                        error!(
                            "SignedData contains unrecognized certificate choice type. Ignoring."
                        );
                    }
                }
            }
        }
        None => {
            error!("SignedData does not contain any certificates");
            return Err(Error::BadInput);
        }
    }

    match candidate_signer_cert {
        Some(cert) => Ok((cas, cert)),
        None => {
            error!("SignedData does not contain any end entity certificates");
            Err(Error::BadInput)
        }
    }
}

//------------------------------------------------------------------------------------
// Public methods
//------------------------------------------------------------------------------------
/// Accepts a buffer that notionally contains a PList containing a Dictionary with an
/// EncryptedPayloadContent entry. Returns the contents of entry upon success and an error otherwise
pub fn get_encrypted_payload_content(xml: &[u8]) -> Result<Vec<u8>> {
    let xml_cursor = Cursor::new(xml);
    let profile = plist::Value::from_reader(xml_cursor).map_err(|_e| Error::Plist)?;

    let profile_dict = match profile.as_dictionary() {
        Some(d) => d,
        None => {
            error!("Failed to parse profile as a dictionary");
            return Err(Error::Plist);
        }
    };

    match profile_dict.get("EncryptedPayloadContent") {
        Some(p) => match p.as_data() {
            Some(v) => Ok(v.to_vec()),
            None => {
                error!("Failed to read data from EncryptedPayloadContent entry");
                Err(Error::Plist)
            }
        },
        None => {
            error!("Profile did not contain an EncryptedPayloadContent entry");
            Err(Error::Plist)
        }
    }
}

/// Takes a buffer and returns a String containing an ASCII hex representation of the buffer's contents
pub fn buffer_to_hex(buffer: &[u8]) -> String {
    let hex = hex::encode_upper(buffer);
    let r = std::str::from_utf8(hex.as_slice());
    if let Ok(s) = r {
        s.to_string()
    } else {
        String::new()
    }
}

/// Takes an EncapsulatedContentInfo and returned the encapsulated content as a buffer. Do not
/// log error information before returning.
pub fn get_encap_content(eci: &EncapsulatedContentInfo) -> Result<Vec<u8>> {
    let encap = match &eci.econtent {
        Some(e) => e,
        None => return Err(Error::ParseError),
    };

    let enc_os = encap.to_der()?;
    let os = OctetString::from_der(&enc_os)?;
    Ok(os.as_bytes().to_vec())
}

/// Processes the provided content as a SignedData message and verifies the signer's certificate relative to the given
/// environment. Returns the encapsulated content as a byte array.
pub async fn purebred_authorize_request(content: &[u8], env: &str) -> Result<Vec<u8>> {
    let ci_sd = ContentInfo::from_der(content)?;
    if ci_sd.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        error!(
            "Unexpected content type (expected ID_SIGNED_DATA): {:?}",
            ci_sd.content_type
        );
        return Err(Error::ParseError);
    }

    let bytes2 = ci_sd.content.to_der()?;
    let sd = SignedData::from_der(&bytes2)?;

    let xml = match get_encap_content(&sd.encap_content_info) {
        Ok(xml) => xml,
        Err(e) => {
            error!("Failed to read encapsulated content from request: {e:?}");
            return Err(e);
        }
    };

    let hashes = hash_content(&sd, &xml)?;

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let (intermediate_ca_certs, leaf_cert) = get_candidate_signer_cert(&sd)?;
    let leaf_cert_buf = leaf_cert.to_der()?;
    for si in sd.signer_infos.0.iter() {
        if check_message_digest_attr(&hashes, si).is_err() {
            continue;
        }

        let data_to_verify = si.signed_attrs.to_der()?;
        if pe
            .verify_signature_message(
                &pe,
                &data_to_verify[..],
                si.signature.as_bytes(),
                &si.signature_algorithm,
                leaf_cert.tbs_certificate().subject_public_key_info(),
            )
            .is_ok()
        {
            return match validate_cert(&leaf_cert_buf, intermediate_ca_certs, env).await {
                Ok(_) => Ok(xml),
                Err(e) => {
                    error!("Failed to validate certificate purebred_authorize_request: {e:?}");
                    Err(Error::BadInput)
                }
            };
        }
    }
    Err(Error::BadInput)
}

/// Create a SKID-based SignerIdentifier from certificate
pub fn signer_identifier_from_cert(cert: &Certificate, use_skid: bool) -> Result<SignerIdentifier> {
    if use_skid {
        let skid_bytes = skid_from_cert(cert)?;
        let os = match OctetString::new(skid_bytes) {
            Ok(os) => os,
            Err(e) => return Err(Error::Asn1(e)),
        };
        let skid = SubjectKeyIdentifier::from(os);

        Ok(SignerIdentifier::SubjectKeyIdentifier(skid))
    } else {
        let ias = IssuerAndSerialNumber {
            issuer: cert.tbs_certificate().issuer().clone(),
            serial_number: cert.tbs_certificate().serial_number().clone(),
        };
        Ok(SignerIdentifier::IssuerAndSerialNumber(ias))
    }
}

/// Create a SKID-based RecipientIdentifier from certificate
pub fn recipient_identifier_from_cert(cert: &Certificate) -> Result<RecipientIdentifier> {
    let skid_bytes = skid_from_cert(cert)?;
    let os = match OctetString::new(skid_bytes) {
        Ok(os) => os,
        Err(e) => return Err(Error::Asn1(e)),
    };
    let skid = SubjectKeyIdentifier::from(os);

    Ok(RecipientIdentifier::SubjectKeyIdentifier(skid))
}

/// Generates a SignedData object covering the `data_to_sign` using the provided `yubikey` and `slot_id`, which
/// are assumed to related to the provided `signers_certificate`.
pub fn get_signed_data<S>(
    signer: &S,
    signers_cert: &Certificate,
    data_to_sign: &[u8],
    encap_type: Option<ObjectIdentifier>,
    use_skid: bool,
) -> Result<Vec<u8>>
where
    S: Keypair + DynSignatureAlgorithmIdentifier + Signer<rsa::pkcs1v15::Signature>,
    <S as Keypair>::VerifyingKey: EncodePublicKey,
{
    let econtent_type = encap_type.unwrap_or(const_oid::db::rfc5911::ID_DATA);

    let content = EncapsulatedContentInfo {
        econtent_type,
        econtent: Some(Any::new(Tag::OctetString, data_to_sign)?),
    };

    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: Some(Any::from(AnyRef::NULL)),
    };

    let si = signer_identifier_from_cert(signers_cert, use_skid)?;

    let external_message_digest = None;
    let signer_info_builder_1 = match SignerInfoBuilder::new(
        si,
        digest_algorithm.clone(),
        &content,
        external_message_digest,
    ) {
        Ok(sib) => sib,
        Err(e) => {
            error!("Failed to create SignerInfoBuilder: {e:?}");
            return Err(Error::Unrecognized);
        }
    };

    let mut builder = SignedDataBuilder::new(&content);

    let signed_data_pkcs7 = builder
        .add_digest_algorithm(digest_algorithm)
        .map_err(|_err| Error::Unrecognized)?
        .add_certificate(CertificateChoices::Certificate(signers_cert.clone()))
        .map_err(|_err| Error::Unrecognized)?
        .add_signer_info(signer_info_builder_1, signer)
        .map_err(|_err| Error::Unrecognized)?
        .build()
        .map_err(|_err| Error::Unrecognized)?;

    let signed_data_pkcs7_der = match signed_data_pkcs7.to_der() {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to encoded SignedData: {e:?}");
            return Err(Error::Asn1(e));
        }
    };
    Ok(signed_data_pkcs7_der)
}

/// Extract SKID extension value from certificate or calculate a SKID value from the SubjectPublicKeyInfo
pub fn skid_from_cert(cert: &Certificate) -> Result<Vec<u8>> {
    if let Some(exts) = cert.tbs_certificate().extensions() {
        for ext in exts {
            if ext.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER {
                match OctetString::from_der(ext.extn_value.as_bytes()) {
                    Ok(b) => return Ok(b.as_bytes().to_vec()),
                    Err(e) => {
                        error!("Failed to parse SKID extension: {e:?}. Ignoring error and will use calculated value.");
                    }
                }
            }
        }
    }

    let working_spki = cert.tbs_certificate().subject_public_key_info();
    match working_spki.subject_public_key.as_bytes() {
        Some(spki) => Ok(Sha256::digest(spki).to_vec()),
        None => {
            error!("Failed to render SPKI as bytes");
            Err(Error::Unrecognized)
        }
    }
}

/// Returns a vector containing distinct `rfc822Name` values read from `SubjectAltName` entries in `dict`.
/// When no `rfc822Name` values are found, an empty vector is returned.
pub fn get_email_addresses(dict: &Dictionary) -> Vec<String> {
    let mut rv: Vec<String> = vec![];
    if let Some(san) = dict.get("SubjectAltName") {
        if let Some(san) = san.as_dictionary() {
            if let Some(rfc822_names) = san.get("rfc822Name") {
                if let Some(rfc822_names) = rfc822_names.as_array() {
                    for email in rfc822_names {
                        if let Some(s) = email.as_string() {
                            let c = s.to_string();
                            if !rv.contains(&c) {
                                rv.push(c);
                            }
                        }
                    }
                }
            }
        }
    }
    rv
}

/// Returns an RSA key size. Defaults to 2048.
pub fn get_key_size(dict: &Dictionary) -> i32 {
    let mut retval = 2048;
    if let Some(san) = dict.get("Keysize") {
        if let Some(size) = san.as_signed_integer() {
            retval = size as i32;
        }
    }
    retval
}

/// Returns a Name prepared using elements in the `Subject` entry in `dict`
pub fn get_subject_name(dict: &Dictionary) -> Result<Name> {
    let mut dn = vec![];
    if let Some(subject_array) = dict.get("Subject") {
        if let Some(subject_array) = subject_array.as_array() {
            for elem in subject_array.iter().rev() {
                if let Some(rdns) = elem.as_array() {
                    let mut rdn_vec = vec![];
                    for rdn in rdns {
                        if let Some(type_and_val) = rdn.as_array() {
                            if 2 == type_and_val.len() {
                                let rdn_type = match type_and_val[0].as_string() {
                                    Some(t) => t,
                                    None => return Err(Error::Plist),
                                };
                                let rdn_value = match type_and_val[1].as_string() {
                                    Some(t) => t,
                                    None => return Err(Error::Plist),
                                };
                                rdn_vec.push(format!("{rdn_type}={rdn_value}"));
                            }
                        }
                    }
                    dn.push(rdn_vec.join("+"))
                } else {
                    error!("Failed to an RDN entry as an array");
                    return Err(Error::Plist);
                }
            }
        } else {
            error!("Failed to parse Subject entry as an array");
            return Err(Error::Plist);
        }
    } else {
        error!("No Subject entry was found in the dictionary");
        return Err(Error::Plist);
    }

    let s = dn.join(",");
    match Name::from_str(&s) {
        Ok(n) => Ok(n),
        Err(e) => Err(Error::Asn1(e)),
    }
}

/// Retrieves the value associated with the given key from the given dictionary as a String if possible
pub fn get_as_string(dict: &Dictionary, key: &str) -> Option<String> {
    if let Some(value) = dict.get(key) {
        if let Some(rv) = value.as_string() {
            return Some(rv.to_string());
        }
    }
    None
}
