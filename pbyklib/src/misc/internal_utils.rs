use std::{
    collections::BTreeMap,
    io::Cursor,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use log::{error, info};
use plist::Dictionary;
use rand_core::{OsRng, RngCore};
use subtle_encoding::hex;

use cipher::{generic_array::GenericArray, BlockDecryptMut, KeyIvInit};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use cms::{
    builder::{SignedDataBuilder, SignerInfoBuilder},
    cert::CertificateChoices,
    content_info::ContentInfo,
    enveloped_data::{EnvelopedData, RecipientIdentifier, RecipientInfo},
    signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo},
};
use const_oid::{
    db::{
        rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER, rfc5911::ID_MESSAGE_DIGEST,
        rfc5912::ID_CE_BASIC_CONSTRAINTS,
    },
    ObjectIdentifier,
};
use der::{
    asn1::{OctetString, UtcTime},
    Any, Decode, Encode, Tag,
};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoRef};
use x509_cert::{
    builder::CertificateBuilder,
    ext::pkix::{BasicConstraints, SubjectKeyIdentifier},
    name::Name,
    serial_number::SerialNumber,
    time::{Time, Validity},
    Certificate,
};
use yubikey::{
    certificate::yubikey_signer::{Rsa2048, YubiRsa},
    piv,
    piv::{AlgorithmId, SlotId},
    MgmKey, PinPolicy, TouchPolicy, YubiKey,
};

use certval::{populate_5280_pki_environment, PkiEnvironment};

use crate::{
    misc::{
        p12::import_p12, pki::validate_cert, rsa_utils::decrypt_inner, scep::process_scep_payload,
    },
    Error, Result,
};

//------------------------------------------------------------------------------------
// Local methods
//------------------------------------------------------------------------------------
/// Accepts a buffer that notionally contains a PList containing a Dictionary with an
/// EncryptedPayloadContent entry. Returns the contents of entry upon success and an error otherwise
fn get_encrypted_payload_content(xml: &[u8]) -> Result<Vec<u8>> {
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
    match &cert.tbs_certificate.extensions {
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
/// Generates a self-signed certificate containing a public key corresponding to the given algorithm
/// and a subject DN set to the provided value using the indicated slot on the provided YubiKey.
pub(crate) fn generate_self_signed_cert(
    yubikey: &mut YubiKey,
    slot: SlotId,
    algorithm: AlgorithmId,
    name: &str,
) -> Result<Certificate> {
    // Generate a new key in the selected slot.
    let public_key = match piv::generate(
        yubikey,
        slot,
        algorithm,
        PinPolicy::Default,
        TouchPolicy::Default,
    ) {
        Ok(public_key) => public_key,
        Err(e) => return Err(Error::YubiKey(e)),
    };

    let mut serial = [0u8; 20];
    OsRng.fill_bytes(&mut serial);
    serial[0] = 0x01;
    let serial = SerialNumber::new(&serial[..]).expect("serial can't be more than 20 bytes long");

    // Generate a self-signed certificate for the new key.
    let ten_years_duration = Duration::from_secs(365 * 24 * 60 * 60 * 10);
    let ten_years_time = match SystemTime::now().checked_add(ten_years_duration) {
        Some(t) => t,
        None => return Err(Error::Unrecognized),
    };
    let not_after = Time::UtcTime(
        UtcTime::from_unix_duration(
            ten_years_time
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Unrecognized)?,
        )
        .map_err(|_| Error::Unrecognized)?,
    );
    let validity = Validity {
        not_before: Time::UtcTime(
            UtcTime::from_unix_duration(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Error::Unrecognized)?,
            )
            .map_err(|_| Error::Unrecognized)?,
        ),
        not_after,
    };
    let name = Name::from_str(name)?;
    let spkibuf = public_key.to_der()?;
    let b = Sha1::digest(spkibuf);
    let os = OctetString::new(b.as_slice())?;
    let skid = SubjectKeyIdentifier(os);

    match yubikey::certificate::Certificate::generate_self_signed(
        yubikey,
        SlotId::CardAuthentication,
        serial,
        validity,
        name,
        public_key,
        |builder: &mut CertificateBuilder<
            '_,
            yubikey::certificate::yubikey_signer::Signer<'_, YubiRsa<Rsa2048>>,
        >| {
            builder.add_extension(&skid).unwrap();
            Ok(())
        },
    ) {
        Ok(cert) => Ok(cert.cert),
        Err(e) => Err(Error::YubiKey(e)),
    }
}

/// Takes a buffer and returns a String containing an ASCII hex representation of the buffer's contents
pub(crate) fn buffer_to_hex(buffer: &[u8]) -> String {
    let hex = hex::encode_upper(buffer);
    let r = std::str::from_utf8(hex.as_slice());
    if let Ok(s) = r {
        s.to_string()
    } else {
        "".to_string()
    }
}

/// Takes an EncapsulatedContentInfo and returned the encapsulated content as a buffer. Do not
/// log error information before returning.
pub(crate) fn get_encap_content(eci: &EncapsulatedContentInfo) -> Result<Vec<u8>> {
    let encap = match &eci.econtent {
        Some(e) => e,
        None => return Err(Error::ParseError),
    };

    let encos = encap.to_der()?;
    let os = OctetString::from_der(&encos)?;
    Ok(os.as_bytes().to_vec())
}

pub(crate) async fn purebred_authorize_request(content: &[u8], env: &str) -> Result<Vec<u8>> {
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
    populate_5280_pki_environment(&mut pe);
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
                &leaf_cert.tbs_certificate.subject_public_key_info,
            )
            .is_ok()
        {
            match validate_cert(&leaf_cert_buf, intermediate_ca_certs, env).await {
                Ok(_) => {
                    return Ok(xml);
                }
                Err(e) => {
                    error!("Failed to validate certificate purebred_authorize_request: {e:?}");
                    return Err(Error::BadInput);
                }
            }
        }
    }
    Err(Error::BadInput)
}

/// Verifies a SignedData then decrypts an encapsulated EnvelopedData and returns the encapsulated
/// contents from it as a buffer.
pub(crate) async fn verify_and_decrypt(
    yubikey: &mut YubiKey,
    slot: SlotId,
    content: &[u8],
    is_ota: bool,
    pin: &[u8],
    mgmt_key: &MgmKey,
    env: &str,
) -> Result<Vec<u8>> {
    assert!(yubikey.verify_pin(pin).is_ok());
    assert!(yubikey.authenticate(mgmt_key.clone()).is_ok());

    let xml = purebred_authorize_request(content, env).await?;

    let enc_ci = match is_ota {
        true => get_encrypted_payload_content(&xml)?,
        false => xml.to_vec(),
    };

    let ci_ed = ContentInfo::from_der(&enc_ci)?;
    if ci_ed.content_type != const_oid::db::rfc5911::ID_ENVELOPED_DATA {
        error!(
            "Unexpected content type (expected ID_ENVELOPED_DATA): {:?}",
            ci_ed.content_type
        );
        return Err(Error::ParseError);
    }
    let bytes2ed = ci_ed.content.to_der()?;
    let ed = EnvelopedData::from_der(&bytes2ed)?;

    let params = match ed.encrypted_content.content_enc_alg.parameters {
        Some(p) => p,
        None => return Err(Error::Unrecognized),
    };
    let enc_params = params.to_der()?;

    let os_iv = OctetString::from_der(&enc_params)?;
    let iv = os_iv.as_bytes();

    let ct = match ed.encrypted_content.encrypted_content {
        Some(ct) => ct.as_bytes().to_vec(),
        None => return Err(Error::Unrecognized),
    };

    for ri in ed.recip_infos.0.iter() {
        let dec_key = match ri {
            RecipientInfo::Ktri(ktri) => {
                let dk = match piv::decrypt_data(
                    yubikey,
                    ktri.enc_key.as_bytes(),
                    AlgorithmId::Rsa2048,
                    slot,
                ) {
                    Ok(dk) => dk,
                    Err(_e) => continue,
                };
                match decrypt_inner(dk.to_vec(), 256) {
                    Ok(dec_key) => dec_key,
                    Err(_) => continue,
                }
            }
            _ => continue,
        };

        let key = GenericArray::from_slice(&dec_key.1[dec_key.2 as usize..]);

        // decryption
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
        let cipher = Aes256CbcDec::new(key, iv.into());
        if let Ok(pt) = cipher.decrypt_padded_vec_mut::<aes::cipher::block_padding::Pkcs7>(&ct) {
            return Ok(pt);
        }
    }
    Err(Error::Unrecognized)
}

/// Create a SKID-based SignerIdentifier from certificate
pub(crate) fn signer_identifier_from_cert(cert: &Certificate) -> Result<SignerIdentifier> {
    let skidbytes = skid_from_cert(cert)?;
    let os = match OctetString::new(skidbytes) {
        Ok(os) => os,
        Err(e) => return Err(Error::Asn1(e)),
    };
    let skid = SubjectKeyIdentifier::from(os);

    Ok(SignerIdentifier::SubjectKeyIdentifier(skid))
}

/// Create a SKID-based RecipientIdentifier from certificate
pub(crate) fn recipient_identifier_from_cert(cert: &Certificate) -> Result<RecipientIdentifier> {
    let skidbytes = skid_from_cert(cert)?;
    let os = match OctetString::new(skidbytes) {
        Ok(os) => os,
        Err(e) => return Err(Error::Asn1(e)),
    };
    let skid = SubjectKeyIdentifier::from(os);

    Ok(RecipientIdentifier::SubjectKeyIdentifier(skid))
}

/// Generates a SignedData object covering the `data_to_sign` using the provided `yubikey` and `slot_id`, which
/// are assumed to related to the provided `signers_certificate`.
pub(crate) fn get_signed_data(
    yubikey: &mut YubiKey,
    slot_id: SlotId,
    signers_cert: &Certificate,
    data_to_sign: &[u8],
) -> Result<Vec<u8>> {
    let content = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: Some(Any::new(Tag::OctetString, data_to_sign)?),
    };

    let enc_spki = signers_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()?;
    let spki_ref = SubjectPublicKeyInfoRef::from_der(&enc_spki)?;

    let signer: yubikey::certificate::yubikey_signer::Signer<'_, YubiRsa<Rsa2048>> =
        yubikey::certificate::yubikey_signer::Signer::new(yubikey, slot_id, spki_ref)
            .map_err(|_| Error::Unrecognized)?;

    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };

    let si = signer_identifier_from_cert(signers_cert)?;

    let external_message_digest = None;
    let signer_info_builder_1 = match SignerInfoBuilder::new(
        &signer,
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
        .add_signer_info(signer_info_builder_1)
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
pub(crate) fn skid_from_cert(cert: &Certificate) -> Result<Vec<u8>> {
    if let Some(exts) = &cert.tbs_certificate.extensions {
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

    let working_spki = &cert.tbs_certificate.subject_public_key_info;
    match working_spki.subject_public_key.as_bytes() {
        Some(spki) => Ok(Sha256::digest(spki).to_vec()),
        None => {
            error!("Failed to render SPKI as bytes");
            Err(Error::Unrecognized)
        }
    }
}

/// Processes payloads from the presented `xml` generating and import keys using the provided YubiKey
pub(crate) async fn process_payloads(
    yubikey: &mut YubiKey,
    xml: &[u8],
    pin: &[u8],
    mgmt_key: &MgmKey,
    env: &str,
    is_recover: bool,
) -> Result<()> {
    let xml_cursor = Cursor::new(xml);
    let profile = match plist::Value::from_reader(xml_cursor) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to parse XML in process_payloads: {e:?}");
            return Err(Error::Plist);
        }
    };
    let payloads = match profile.as_array() {
        Some(d) => d,
        None => {
            error!("Failed to parse profile as an array");
            return Err(Error::Plist);
        }
    };

    let mut p12_index = 0;
    let mut recovered_index = 0;
    for payload in payloads {
        if let Some(dict) = payload.as_dictionary() {
            if let Some(payload_type) = dict.get("PayloadType") {
                match payload_type.as_string() {
                    Some(t) => {
                        if "com.apple.security.scep" == t {
                            let payload_content = match dict.get("PayloadContent") {
                                Some(pc) => match pc.as_dictionary() {
                                    Some(d) => d,
                                    None => {
                                        error!("Failed to parse PayloadContent as a dictionary for SCEP payload.");
                                        return Err(Error::Plist);
                                    }
                                },
                                None => {
                                    error!("SCEP payload missing PayloadContent.");
                                    return Err(Error::Plist);
                                }
                            };

                            if let Err(e) = process_scep_payload(
                                yubikey,
                                payload_content,
                                false,
                                pin,
                                mgmt_key,
                                get_as_string(dict, "PayloadDisplayName"),
                                env,
                            )
                            .await
                            {
                                error!("Failed to process SCEP payload: {e:?}.");
                                return Err(e);
                            }
                        } else if "com.apple.security.pkcs12" == t {
                            let payload_content = match dict.get("PayloadContent") {
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

                            let password = match dict.get("Password") {
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

                            info!("Processing PKCS #12 payload with index {p12_index}");
                            if let Err(e) = import_p12(
                                yubikey,
                                payload_content,
                                password,
                                recovered_index,
                                None,
                            )
                            .await
                            {
                                error!("Failed to process PKCS #12 payload at index {p12_index}: {e:?}.");
                                return Err(e);
                            }
                            p12_index += 1;
                            if is_recover {
                                recovered_index += 1;
                            }
                        }
                    }
                    None => {
                        continue;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Returns a vector containing distinct `rfc822Name` values read from `SubjectAltName` entries in `dict`.
/// When no `rfc822Name` values are found, an empty vector is returned.
pub(crate) fn get_email_addresses(dict: &Dictionary) -> Vec<String> {
    let mut retval: Vec<String> = vec![];
    if let Some(san) = dict.get("SubjectAltName") {
        if let Some(san) = san.as_dictionary() {
            if let Some(rfc822_names) = san.get("rfc822Name") {
                if let Some(rfc822_names) = rfc822_names.as_array() {
                    for email in rfc822_names {
                        if let Some(s) = email.as_string() {
                            let c = s.to_string();
                            if !retval.contains(&c) {
                                retval.push(c);
                            }
                        }
                    }
                }
            }
        }
    }
    retval
}

/// Returns a Name prepared using elements in the `Subject` entry in `dict`
pub(crate) fn get_subject_name(dict: &Dictionary) -> Result<Name> {
    let mut dn = vec![];
    if let Some(subject_array) = dict.get("Subject") {
        if let Some(subject_array) = subject_array.as_array() {
            for elem in subject_array.iter().rev() {
                if let Some(rdns) = elem.as_array() {
                    let mut vrdn = vec![];
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
                                vrdn.push(format!("{rdn_type}={rdn_value}"));
                            }
                        }
                    }
                    dn.push(vrdn.join("+"))
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

pub(crate) fn get_as_string(dict: &Dictionary, key: &str) -> Option<String> {
    if let Some(value) = dict.get(key) {
        if let Some(retval) = value.as_string() {
            return Some(retval.to_string());
        }
    }
    None
}

//------------------------------------------------------------------------------------
// Tests
//------------------------------------------------------------------------------------
#[cfg(feature = "dev")]
#[tokio::test]
async fn purebred_authorize_request_sha256_test() {
    use hex_literal::hex;
    let content = hex!("3082250E06092A864886F70D010702A08224FF308224FB020103310D300B060960864801650304020130821EBB06092A864886F70D010701A0821EAC04821EA83C3F786D6C2076657273696F6E3D22312E302220656E636F64696E673D225554462D38223F3E0A3C21444F435459504520706C697374205055424C494320222D2F2F4170706C652F2F44544420504C49535420312E302F2F454E222022687474703A2F2F7777772E6170706C652E636F6D2F445444732F50726F70657274794C6973742D312E302E647464223E0A3C706C6973742076657273696F6E3D22312E30223E0A3C646963743E0A093C6B65793E456E637279707465645061796C6F6164436F6E74656E743C2F6B65793E0A093C646174613E0A094D4949554441594A4B6F5A496876634E415163446F4949542F544343452F6B4341514978676745774D4949424C414942416F4155772F7464474B55776C4C71334A7945560A094C573538494D6567307577774451594A4B6F5A496876634E415145424251414567674541506D4F6C6B757A2F324870315A6C3830697A302B346F766B4A44766A527436770A0974512F3773686A69455079304C424547425437683757764456514F437A587A5071756C4279477A556A32694E583247444C75594E3632675573367A336E5963364D3561590A0956694B63625547663031695A686D695934716F48515159317978595A676662634563425131706A433959344A436D70325174416E6E4D514E576764546F644D49416976640A092B4672343150507856302B5376355A395877646B6368724C4971463978337944594A314E486336696D6A3563785677384335573445736D466C3466493950736B544569590A096D4C4D3170795146724A765971665251543169424E30486469524F2B567034466D626B7A464A3645634F505278332F574E485169336D4D666F5A33632F4469796A6648300A097974445730367856352F4E5279616575755662676D7A515353366672614A45573458623842544343457234474353714753496233445145484154416442676C67686B67420A095A514D4541536F45454E577838344D34594F4D4C6949514151356C6B622B534167684B51594E6E557A4B78535454554C34494F7736306C555443644F67424276674158680A09553649323856757234734A3054427675332B686133566B704C4668776F59556C37576D30302F56464369686869306A656A6A6B655053594A414F673144712B30566A36300A092B75665A3064442B6A75397372544B4D4D5A72752B4335346F4131694B4A3634654D706B4F494C7A4D6A5472302F447734434F396C66485278585A346A525A62676C6A680A092F694538663145483865444A43417739777762374A32446F54666359576A38734D614A444E4836764E416F654F6535463145443059766A62667A43516F7434792B7948570A09547963326B2B35745537625974736B353975343246437772496A753455536E695075743255374C4E5A73515A74706B35526F446E5A4A736547516E75546959683633492B0A09527757516841454C675954704435424C344F6F7153517641783579796D3076367A4D6C51643457504C713764644D634A6361496354755052475274685975354F533366660A093037564D6F682F4B67587936594F756263385052337A7A4252436D58587558682B386B444E6B7454462F76424D2F7A4D4C694A7352344A4D795363356C327465493332710A09306E4B7A393951636F574E325356445A6C3656415169416D4F4150584D544876737367664C643558334F4F62767636584635533572724B6A5A32523268633647537757330A09322B4870766855456A7162306246306545704D6668552B492B736369343349684E4A6A2F4E7864754C5158627A7767502F4A6935474A4F725673734E746972576E4F52470A096A58316F396479784E716E41457453627338792F7A70784B6E6E52797151647162386B4E614577306C7A74527744453065457230437265466A51536F43464C72747832490A09313656523351746F4F4C6D34766E436759467246787944354F614A4C3648654C655A36673051347834563161624B7352623872374E6C4D4E464A6E7545774B38306279450A094777776E784879394D345649665A4769453232726B756B4738564C4C5A5942686B584B415050314F6B73704C35436475684268705147396A47633739624E584E694C444D0A093072513455415167752F3851674A466F65527858615670434B5848696B56436D3043386F6B50764F6C6A745975654E6378574D706B754F4B71567057344268596F324A310A09554C47504179474561793931737879566569454E55443639627546317578496F2B6B6D4D77726B4951724D56754573414D44625331364C6F56573276654E6C4155735A480A094E6D546B4935536B575145564C544E45364E352F796C7A7579445156326A517938304A385871394F426268775849324C4B59394D6A48584C42376238475A4646446F77410A095A7A785751764C534737335837517072656E68747A425351303538784E4D68396C7472392F6F504A6C716464426573356B543277507138444765527A46396B474D4551540A09677A54784F4E506B6D53464737677346576E46647648535175796E3042455A7367695A417337375A67395257466A365065516763454B2F486C4138727A783647754D69560A096C3771566A55616847747678423053347A724D2F65396F324C4B756D48536E3072543433712F72483934314D4C4932395953622B45717A583449754E6B7A6C36634558520A09503536795739354A726F726C70376C6F79496B64363461667978514B30615349754A754255554F42716363792F77536C754168447833706B6C354E5750496243673543510A096C36784D61364E3573514A6D6E6E694B4E2B352F4B67564D51527339675653312B304F454872684C624E512F45392F41422B6E6252615151703148616242444A584637580A09575955703374624B316833496657343538723766637A685555792B7231454C5243546F5253686E7A71655A4C4A32642B71624F4A784666704C554D612F66515038635A640A0941447937304765555077695133595A7A5A6D63544530364579634C4D317373466E6D34446C373744415846362B516374466B31356737724137334A69384164466D4344700A09657131664C777732396D645242316D4963464175536D3759522B436A2B794D717864632B2F42646736777056787A4B7A38316B5A43776C586F7A777964447158527468760A09367249654E313548424E4E6B7361764D73786776443544714E53696250373967326A4B687976767A375357527271754C386658324E364A574B4C2F57796B4D49684534370A097944506B68763865644A794C764D522F30474D4C4E6E34346D6344797265336B432B2F343179466369757379466972766E546B6351504731544446655155514F7A3238380A09415A58463946637A705A31326541464B476A314D6A59303462736D6E5165364B35584A455A334C4B427A756F7671786A4C68526D7757396B71366936774E78426153537A0A0939344A41646D53585144506A77633575354E53507370677950415348425A4E3568523842614872654B616A35647441375068716B596B647643666B36755330726D2B6F4B0A094676566F314E3436786A4E4A5844487157503468657431742B72494530555945456D6F715339326F357362576831376D36763476474F43695658336B45565342524F47550A0930356F744F386B41656669464D3242657857794162526E74775648694F6642576C736745574238483876516E7A357461334D5A3570414E3641356731506E4A614F4931440A0951354B452F58522B454D7475647954636A785363386F71767575666659637746755832557A796B734D505A64642B486A336437355377487642344D4B5867446D394E4D420A09677976416C6148377931334332752B55697A377A2B2B6350624F4D6C5234434F4A7763667374344D75544D347957705462696E3070314B62415167366F3175463648342B0A09716737326D466E5959427953444B6477655957656A306A756C78484F3264616F6C416A7974694A43703759676B62332B426F62486D4D5559696E683749343849327942510A0957716F464A673543466C314B5068644A704544445537494D6F33624F364858536B4C3939776743745A2F774E7069557A716B664749396C56676C4F78412B4B546459386B0A094746724F3872395032543438727472667A2B32324643304279666F654B5A58357574655677377A4B5053776551467635424D5152314148456D4E342F656667395A3332310A0979694F577972776753714E7A4B47644668524D5472593845314C70356D66446D714B4C56364871344B5874623042737478316A33735545676334565A465A624C524B78460A096A30497070714835572B776E435837794A416761384C4B55673942495179506569743633646F4D6B327A414F485A593764423041465A6D484659676B71436E3157576F370A094E65454F3433776F6A6B646E51564672756A556E5A542B475A2F4E2F59376A4D4A5A2F65552B63355666556559392B7234757537732F78516C2F35497A79445155764C300A097044417233577131643562784835457945543466444F2F77344275414869364E4768376730636B35314159366D327578566C644A42534C69733077316A78334A3779304F0A09636C6E7065576554773964506B50757833545565316639684F666B78354C7A387968716B3757304E39587A4567397336725478366735754C504C313635616C34524149490A0974483149624C4F526633356D36334B6B6D37664375784572377A62695439414E5744716665444F34765948654E795A755958625732744676567756747063794E545970760A094F756C5275367A595A46664F6D66574D41555A4A437A64564D444F392F4F39545659576E764F3048413568734A334364706275532F4F313977484C662F687956363656360A0967724E6E2F474C5269566A4749736762433655794357526E7056446C562B53346335526877634B684D335143587A4D444E6F5553314F5A5A42324F347777675A2B5034570A096F6A76614D6D4A79594E4B397A4A796B5A482B452B677564704461485444384C78753457484A59614E5A54394C74304E36447730587A4E4D49456434656B67667A7749560A09476F306464746B4A44614F593747765A6D46743258414D487369656B6A55577776504E306876633252646448745670534C3933627A504538537A5A345973313454544F530A09327777347146504176446D313949776330536D686E3350467A41397931703567547470744A643059725174684A394E63522B376866334839495170496445627455656F770A097A4A4C4837332F4F5A6B4A5A4157684458666F2B51676D683358737237776E6F664C427944312B595356396B5253544B5066466262574A714A704961622F6F31766655570A096254435874636B487535365474746B687065444175754774666777345A354435746A49584A46786B65713144366461704D63663878674F496D793667396C476942304B520A09794874646A79655938767A615945696B664D314772674E7169637A7344514F494A304B6A506577463245466F444934544E6E6A6A525A344B77686B4C634F554148762F420A094F656E6955752F617A7332707844455968784D54736A32465244594B6769687A524C724D4631756D41794B743676374359494B6C4D6D594E57596E6777485933427273370A0979416D397267714B65683859416F3337474B594930776C34614C39583065753471456D46746639752B6874736B317A647A7A5538485441776F61444B5364457444442F650A094438784A583765664D3967726F58472F646742384C4E4F6D654472776A35616D42506A6771444D4B487958497A3765785A496732324B5939414E544D76694A73512F5A4C0A0948784C7651463359384572694B3072456C4F5658396A6B59674334776F49747A51504A6F354E774537435834797A754653644F38426A6A53626970572B693035774D31390A09336E3562756A4B6E774578657131724B5366704A42535443432B6631347972306D6B6145415A707A6E41666A6F42656A664B7A477A454A3470726C394F58667779736E4F0A0944737939464A62586A69316A57783334726868354C5349676F77436F4C6B79487834636B35736172484F453632496D5356426870323945305077455441496E714D5955370A09777578343870723132763658774F466978422F59586147424678383146395056525079394930567A4471762F446D46675356742F713176504A6C593076644564683064550A094D467A544244313849682B464B4D4C6744427855433336794532656B2F6A6346586875314B63387730624435437167416F6E4D39752B4A644674724778786B41444F52350A09474F6B58333958685939585148676E78746F75786A626333684F3674484F74614A63624B6F74565153416831566531776157566A426F58524B664B2F3661374B673742770A097461655478316955416C566F39456D7275702F625947334264616B51372B52683157706C382F4E79487944475A333542754C6434342F585051554E5858674B79613539370A097673464A615A49754F783774304E346F76444C382B6A3537394C463862463138544B535551784E364970396A656365574A5768627A6E32384A38376A4D744850584B616B0A09744B6D5A6E59344D4555334936375A722B6B563668466238436C567135496541474F716C5537346A6D3541796F6C6A5A6836365A394877596D5359434F74747A324761300A094158614B592F454C5A4A3479484C7572767155566B6E6E757277316F47706A6B342B61353869577A3972635636627652452B44447030385A4632464D51446C444D79654E0A09362B68316774416C52385535352B7A2F5A6F61474C456350352B775A686B4A57697954654C30683250416B757353656C732B4E76304E647642564A316E48367A417449750A096C57512F31764749537958782B4E4C7854773053464836456F582B3765396969564A654D493137352B4C5358664776692F395A314E766E37524738414D4B3936613246540A09712B7451684D51422B344C516F2B52594F32724F4D753450655748356877326256386739617069584D59704F373174532B46654A34473742667548327A7356386C552F330A09496B4F66374C2F3357524A6773385A712F62777A334C616564547772484B676853394B7931445676625A4271326B2F31556638786674735A5A4C2B784349415452392B6A0A094669506C5742614F50796331714A7553434C346E65757A6568616D426A2B30682B38473068596A7A7439306D34537478776B66465965646F33754C6A735A415575497A510A096B416C762B426874366C4171695462444F536147562F46423371773653306E49494D726470655368754B6E6C5A6A6A4934364C51686A4D497A43756D596F416D344A63310A096735516730362B434767784A6856526257674151335A3233482F694444506968566544517A33497764435033633471744F426C694D3071434773453038796251446752500A0954595043394D79706E5A414677454D6D5438344C46794F54724C2F376C7A752B4D4775697A63343442564D4A2F577934304C6A53595349546467476174394C476E6568770A09612F63426C44473659426B442B322F4F5A4A6A305A4630676D45574F5335703467514B39345968374642617971664567526E46646C684F5962597553764C4B655A7746510A09424E495745306235645771536C4F32464378574F57496C3739506272532F35436C68656636693669445839724D4F4B43796D56452B2B56395831746A636D4934327154320A094D4F455A364D4F644B487574777A554D76394D553676774E4F3858592F582B49744C464E70376D793738687755776B67593349662F6A6B364373552F3678775A2B554F520A096B494E4B394F6250546D6D686E42386362545A5162515844664A435370694544786C6C5542793449415A5A316C724F63534C792B3850666C3438694F46327564586F46690A095639574E7469564D535A646C7072506C6E36626261334330463764367A6A664E35377149735069657A44734A643372535134554B4E62577741634F573573754A4F4441750A09466D5A71684A694A4B4667647030687A6F45726E712F38593364574A52484763425A426A334549346876455948746F6C746B693977426E683961444E335974664F7532610A095A7167336A36614248694571656B6D6167732F65744C32756F6553435372626E2F495179616B634B41756D354A5A774B53797A7278446538684E3248494238766C5274490A092B443372706A4F724B65337968736753777078452B6356506F594B6A526736714A6C6E70694D464A546F51572F307A7847687145723347616E6E447252595436425248550A09787842794E4458726E504D676E55414B49436D3563535371796174444A6A39394E526536366478757568507469686B74524F46664A52624F396C3053677A3565584137300A0973657178494B4B4A2B7836377973646A4B37524F71382F79536E3944495878695153364C6D547A54614C48502F41507148516D3049505749482B702F6263325575576F2F0A09383042516F676F475958472B6E4A436F58486B423938326B4D77572B6266442F7A70464F704B6D755475625876694D38444D5650397455756F376B6C316D4B4164477A4C0A093731586777774856674F752F2B3567314B583351486E6B7751352F6154436657776D6F596F5449752F71524B54554A6376686A4656444568334578586E497134614C47690A09756E786C41724F735550766756796E484D6E716563417536653770744F336E656A66522B726C767A384C6E6F6E555A33454B4455344D413944426E4842497A6749664B790A0948716B363974693877566F7264706E46304C4A684F4E6C50794F4E4B41314233363832595733374C78782F5243355734364F30746D687135564A673876684844664252470A09534264643936667A336C6F386B4C4C31573878674D506E6A67365179466F5950512F74562B342F2B5652465A522F5A6F516836514D376A446E6D784E47456E4C7A7171330A0973544C4966644E754B2F696E522B5A5773534F6156504438536B476A75315530357668425261306A3764386363776A4F6A717762726D4A714C36337272565367667644440A09623547643568336B71334F625466557A6F6678626C47524D734D7241592B504F676F3653697730504D3378344C68565047397A6A364A6167715532444358394B385577660A09664B456A72754D4D74466E41326C3756516C51675532743269714C5448465546744150436562504962376F4D77777139545956504956396E375239734473614B4E5443720A0950714357393231356556366D6E64785148465643506F4A6464515673346F326C4E706F637A626C535A336359444B7A416C5563686A7845484E6D67714E666852797262550A09655A636459376861496246783772746A4157314D35572B36477A444D62394D30524A66414A6A7359514A714C3578552F48485631584E4D4734757A7A4D7259374D3358700A094632366D43476151623556522F4843744C6F4B4E4E3551493154336976746E6A2B394F54596B626A434B676C332F7267646A446B6637555A6B46576D7265635A457457710A09554F55336D426C44315365334855366B4C506C62636954584B50655835345A4C66524A77636171766F7174314F50382F4E457A36677659776E6A656464356B79797261750A0972676E414B5961364C466C4C7462565A4A4E5144544155657138635655782B4C77624570512B756E4A4B3366524B7A49676B2F2F747559672F6C497A6B647752756930550A09354D6946786A51412F7A662F39634541545A783158413242344531634655706236564D36417447364D6D486651412B5459655A5878637A3354724241425335557176652B0A09377648724B32584C4C6D3652614E4E78507366754549347970507767417548553847687569386271614E4A33397958420A093C2F646174613E0A093C6B65793E5061796C6F61644465736372697074696F6E3C2F6B65793E0A093C737472696E673E5068617365203220636F6E66696775726174696F6E2070726F66696C653C2F737472696E673E0A093C6B65793E5061796C6F6164446973706C61794E616D653C2F6B65793E0A093C737472696E673E507572656272656420436F6E66696775726174696F6E202870686173652032293C2F737472696E673E0A093C6B65793E5061796C6F61644964656E7469666965723C2F6B65793E0A093C737472696E673E7265642E686F756E642E70726F66696C652D736572766963652E39316237346438612D363738322D313165652D383566652D3065336562366136613564643C2F737472696E673E0A093C6B65793E5061796C6F61644F7267616E697A6174696F6E3C2F6B65793E0A093C737472696E673E446F443C2F737472696E673E0A093C6B65793E5061796C6F616452656D6F76616C446973616C6C6F7765643C2F6B65793E0A093C66616C73652F3E0A093C6B65793E5061796C6F6164547970653C2F6B65793E0A093C737472696E673E436F6E66696775726174696F6E3C2F737472696E673E0A093C6B65793E5061796C6F6164555549443C2F6B65793E0A093C737472696E673E39316237346438612D363738322D313165652D383566652D3065336562366136613564643C2F737472696E673E0A093C6B65793E5061796C6F616456657273696F6E3C2F6B65793E0A093C696E74656765723E313C2F696E74656765723E0A3C2F646963743E0A3C2F706C6973743E0AA082049A308204963082037EA00302010202025EED300D06092A864886F70D01010B0500305D310B300906035504061302555331183016060355040A0C0F552E532E20476F7665726E6D656E74310C300A060355040B0C03446F44310C300A060355040B0C03504B493118301606035504030C0F444F442050422053572043412D3533301E170D3232303531393136353331365A170D3235303430383130353130345A3057310B300906035504061302555331183016060355040A0C0F552E532E20476F7665726E6D656E74310C300A060355040B0C03504B493120301E06035504030C175075726562726564205061796C6F6164205369676E657230820122300D06092A864886F70D01010105000382010F003082010A0282010100BD9E57FAEA20C4C4AF323D8D5ED46FF71BB0F6E705A037CC425D33BE74F7CE06981C65975F8A4663BDF5F177B754DFBD17D386324189B8F62EB2FA361BA7ABF5F307CB5E69E81948C88E86E0642352E0033D61E3EDE4412BF870392E5CA85D894ED7748E687E1B4443E08AC06AA73513D4E5D4C99843873F470B143A302F1B3DEC04E8F63D988AEE170C16826129E94F000A816C541AD67615686198918197EF23A50C2B14DB04E2E175AE4D9440C9E6DCE9287514DE4CC09B6139779E0D12E07575C4A72D311487241E2D1E520B5CAA1E1F668B0A211114485744BD12027B92DFF3320ABFF7560C11D70C8C3C87DDB6D88D315C0656EBCE8EF06AA3F275CCE30203010001A382016430820160301F0603551D2304183016801461BF1745A00B56DC28F3EEC5FB6DA305C3B5F48C301D0603551D0E04160414D8D53B10803CBE8B58533012B4AA4D00F901D30F30818306082B0601050507010104773075304306082B060105050730028637687474703A2F2F706263726C2E726564686F756E64736F6674776172652E6E65742F7369676E2F444F445042535743415F35332E636572302E06082B060105050730018622687474703A2F2F70626F6373702E726564686F756E64736F6674776172652E6E6574300E0603551D0F0101FF0404030205A030470603551D1F0440303E303CA03AA0388636687474703A2F2F706263726C2E726564686F756E64736F6674776172652E6E65742F63726C2F444F445042535743415F35332E63726C30160603551D20040F300D300B0609608648016502010B2730270603551D250420301E06082B0601050507030106082B0601050507030206082B06010505080202300D06092A864886F70D01010B05000382010100926B181913EB28DE70DEC9D07DC782114A78513E820A575C64321039616C83BB4ED7E0C7B53F641E335A3F1191013F3B5222C127C59AD8E32A8E5E1D58BE8DA1895C2FDF480490646D604209A99898E3D469C9DE37746750DFB20AE22A68998064E630BFB1562132667FFB4C40D3A700757AA139A40243658F3FC5A12ECE9D9BDBE0F1B0B6D6A30FD0230DE69F4321E6AE9A3EE339622312EB8D1526D294F9D70E08B99E2E009D7D95923AC20226B322EFB3736AFB08D9D96E6A6C5BD7ACED8947EAC1AA29B79B7443F1F55C69C844CED9182762AFE749B9A21B78D3BDB98C3624021B459901FAA988AF910312F8AC65FDF720EF1125F1A8C2B7EE21EE3AF95731820188308201840201038014D8D53B10803CBE8B58533012B4AA4D00F901D30F300B0609608648016503040201A04B301806092A864886F70D010903310B06092A864886F70D010701302F06092A864886F70D01090431220420813255942A5700BE4D51DC2B639C064CC8E8C74C60D4D392C53451CB0EB63676300B06092A864886F70D01010B04820100751834CFE00CA210B84DB14BDA6F6C8C157C01CF8A984A99221B85CAB0830C3E59D8E58A84D4DFF32CEAD87CE3763CCE7A3E5CBFCA9A66C024942CA7229830F45CCBB34DE2853737EFECF3480B3449EA985CA64E7BEFA7438B61F041FF314CC8C21D10DF19A1D66E44724A84D68A31B90C2472D33E8DC9FD3CFE8EC61E5A114C3DD8463E3BE048E01036BAB1C88EE22243BC91B970A572B4D45370472849F319F98B54EC85C7F7426700AA1FD2C660EF72EC0189052AC471E08C6AC3958327F4D10F02B78CC2B1B889BEB4D47BCBD99880F193DC62A18DEFF2B865C02E3C9C32689B44262C45D0C7BECA54963E6616DFB3DA715CB0B83E522C1116BD4C770107");
    let _xml = purebred_authorize_request(&content, "DEV").await.unwrap();

    let content_sipr_om = hex!("3082257406092A864886F70D010702A082256530822561020103310D300B060960864801650304020130821EFD06092A864886F70D010701A0821EEE04821EEA3C3F786D6C2076657273696F6E3D22312E302220656E636F64696E673D225554462D38223F3E0A3C21444F435459504520706C697374205055424C494320222D2F2F4170706C652F2F44544420504C49535420312E302F2F454E222022687474703A2F2F7777772E6170706C652E636F6D2F445444732F50726F70657274794C6973742D312E302E647464223E0A3C706C6973742076657273696F6E3D22312E30223E0A3C646963743E0A093C6B65793E456E637279707465645061796C6F6164436F6E74656E743C2F6B65793E0A093C646174613E0A094D4949555041594A4B6F5A496876634E415163446F4949554C54434346436B4341514978676745774D4949424C414942416F415571536B6D46435530456B494A513470680A09723948587932394A525655774451594A4B6F5A496876634E41514542425141456767454173634B6B674748453446532F4B6864525751627655455061446E6238574F51580A09584F4E2B335451674B5579495057474C636C42547242466253614B33674E6C744A69524C7A33716865654B3748377251596D433853793834715A414B76716C5848794D470A09672F7057445A4B46526E307A7A7938704D443843787838364D2F474E593232446D5642736E797A34456767674A3266596866356D41644F52517846574F515A63337757630A094541344E3973524D6D6C536554537A6B4C3767564652373141454D7858585556556C4E323858474944344A2F4F57424766513032726E702F4866767754464756495148710A09744C6336433154315A6C4A755733424F5653696736586A724942586444622B73377135384F65614355715868754E444665647865663350344374366B367270713857396B0A0963397A7652754C6D4B58716F4D732F696A6E533676674D7130533874347A7167334C634634444343457534474353714753496233445145484154416442676C67686B67420A095A514D4541536F45454A457565434F4E4836307074634D766A43766E4F64614167684C414533387A775A617368646B576756685A364C6A4634423152394B6941485044510A095842616B6A4A7A425678414938794569616253574A7A746B546979663831376F2F35713566584331487231375A743832624253764A6574474A4870397475316B6A6A43640A0936793058574673314F34656266344F707275497A3476355966497374564F2B576F50744731554C312F764F75525568636375466B31476C4E5433636E644378346952504B0A095157654B7371326A34512B4553764A7A4544444735474842354A34574756434D5073385863775A6B434D3747533675693230674C7A4E464E59615258464C2F6F653777460A09797A55627248763169442B326737707567462F37734F61324E647742666352433539352F54582B6A70414F6E6853317437744C2B66687948683633315057746C4F7257350A095769495A6567552F56523741446F70624A77666F7144724B524C4445635551627354787843557235554838555369746C4D59674C784435524A45517A534942536F762F640A093965377350326D4E6B524E51794F777A77417A6847694351657636517770506175346E724A766F774C68676D56745A4B51703465596A3342543571795A42622F346938620A0955526B304863746C4A484236656B54363242756E56507874454D3067637156764C436A55586D6F6D34734A516E4864667444693267716651554D4F6C7A78424C517745680A097857467444636B304A2B483661496D37652B58726B594953306C56373772746E73643169584F79472B625579434B516555776457446D786D5247334D494667664C3746570A0959436A7563384B725639624F7A6F777A674B366976766359325934545849682F676D387A634C4376384874755544704E47314F51516834724B772F3544625133706C6F480A09533773323662753965466F377765536F534C38727630373574493342705338762F624A574C475777467857725772504775514B6752454C687549373642465272584151360A097148397A42646732734A306E4A577061767746506E42416261735778366251776B4253667375304B596F6E583467334D4A30545339484C2F397466586C2B5664673671380A09734F7A535231476E48304955476A6453302F7978774159706D444657723137796E473838543252634F6D53524554304D693361784971346D55474D77556A472B2F7437580A096C553672795734354F7832374D644E656D4331586E6975452F5A6D65623679416B58724C386378465962327A4E5852415A43524D7668714D4F56503645475749464A76370A0978482B6F726E56467A6C5A6F7753783336526B686D374E707532397243527475502F73456841544E56504E304A33654162384D48643372394C7037314C44765159534E470A092B6C704A677A58617756416A44726A4832507476356E6E4774414F434E62497A6E6A3139565A735437467557516F462F76504D33426E5A795362365046316C657A6866710A094C6262627A745564644A4C6A6C514538796F773472766838313033624B76386F2B386D765A4B327769454C675152335A635077575250465947315661775A7949595864540A09514D68425171486F4E746E44374F4B2F73726A56745934786269614F454F724E302B4B776B714E315037777644524F3875745A386C38386659566C464F2B484D3736692F0A09756F30435336517072665378512B6646497133356E6E43656E6E6E75484958796A47576F5375397045536D6852775658635956466A6C525A6C414A576946634E524251370A093373506C53476758734D2F6B6469467771726B73636949454D4C364237736D764D646A484742533039483146614B4F52616A4D41316D58344532705776442F5A6275755A0A094D46764B6B7943685574764259572B743762455371446B502B51415353305671554C31586F6B6F66555A2B4D4D342F57444F65556C5832597A3766366E36445A31382B300A094C4B426B4C3550353338483374357A557742726866793851516D37344C5A524762436264364E6D666C306C34495175636939344E4174763754446E626559626F584747550A094239632B316F735476436B5861652F4D4D6174744342706B65535666524933736A43314F43574A4D53466B4B4B727A753370477868774232594D524549796151337476500A096D6A335147574D496C524853343539614E634B2F3866684937395A72587A4C7273506830426E42784476597561597633326E4F766D52364E334741436B64786D2F3849580A09576C514F4966417A4F786B55675447566B3763655A4C735341684B797A6F6A3072774C6A624757776F76646366583341544146734952644A2F4D6C356B66664C644E44300A09736B6D70617368436F4B5A4241686D69466F7536362F724C32595451595A424C47366E546A3833484B4150486D6339632B616B767541595A6F384635787A724C2F4E7A6A0A0945324B4D42387A4254356C504D644A6564674444554F4336635462776B396271354C514B4A647344325749722B34576F63646E462B6E6E5965386C6D4B687131333778630A096A76712B7A673374502F7A4F31685A4F567A6B396A69346E544D62663154614A637642316C4350587A2B336673306A41622B46457A327931365A47656E63752B54346A560A096F30764D424E2B495062715149596E7574456E2B6E33794937396472716B4B3868554B57514B776F46694E3862387443704A6F324239594F344867433472467669776A540A0947587A6A3154793967566B3371746B4E2F6B56334A79484551526D6F7753392F7175524F55432F7763696E646B4C78504E504B673738464C612F35786C36622B516C49760A095941634A783366415832484C4E4B33376B6D6E324B525967445A7850346943653944346230696869413735565752772F7154334836414D73445269596F6E364178526A2F0A096D674C5A556E544B496F5049474F62486C53714569362F382B48525962415465654E64547873673167616F6B77427054307269776F557856546C317777503863316D56610A0977614A42314A44553161363446567852303472745A485358737454544647326B796F4252746B2B4745556C42466549564635796A5241643161624C7877537442365677550A09324E746364673541586E4E4B3332444462646363486E4B48644352736445496E5155494249784B516D4B7566716B49544E37584C637242463650533135426263394978410A09377A74515746776B544731595650744E33756C2F6A46746A2F386F57475664573762726E6638657637317151326A62324B684B386A5761724536787279456D5358315A580A09305479617372685130357565626B7938676F47746C4C68674D5666316C68776F706A7661695242734D7477537441736D384839656B5457387969426F7963477A304D4B520A0970677878622F567857596A58476B6F6879553934757630452B6266747644364F454B6B596C524F704941473570526B4D664C6D42644F6C2B54757171694A4938704C68620A096F716F4A3153346A364573557A664A39714A6D6C5066736A6362774A443655767241652F7662666E4F4A584E5A566A2B5176484B3357436442306B517743746F75424E700A0942695A4F59634D77346E356E61366A3576616C73754C5847363144346B6C2B2B4572506D6C304E555073784B72614D4762316D524E5967752F784F4E37484B3472477A770A096B776237446D72415537563771304C6E66546A5664653649526C787747755968485664494E4736763638383235655A7256746E362F4B504B514F686467744A31762F72430A09505A6431796C6138496D3967534656644439427A76754E71453044335368756378587152442B7855515761654E67576139726F6651326F2B4C6930786D566463744136610A09784C6842445A53454A503344347836516A3475724D6B654F33454B33663766616478752F35576268624D49334F68446859512B62544A323135767175413472596E7359350A097155584647546E545A5556477A68674A6B64644A54574D624B374750764A556946576377507A54784B32354868685A4B705A472F455A70735970437A77526338474B71750A097571654A387035494C3267556B4E674E78554B6B577967657363397038355179307A31495966724A53796155684A72713855784F6B724E6961334445724F55565A4B72590A09784734315032634E46482B4937616772722B68324B36357230517A7062584168395265516E36453754476634464C55796A5143634D36352B583732723535346E6C4B4D5A0A094A71532F5559717966424C6E4B4F7955744D7541456B64384F6A5154504D5A6C6B3674677974766B7373304957725743465331474E317469696F6D7532716B74372B68770A09445764523659326E4B72795559654B31615839616D646178416C496656345047596E7A4533346D49386853696C2B2B57414F6C7656614B7449383830473774714E564D470A097847774A73686441487A36434B2B5562393151337239774F317776435A33526E76454D714168634A30777056485A554B36556B566337686E65346C4B4F326C707043764B0A095836365A33797A616B6C507073494A6E4C4865316E35314D6D7038676B742F36646D6A436F53614A4345376350714644416B752B326E347955366737737554506F717A620A0961614A61457A3956436D3447714B496474314D3237476A5A6445527646576A395662667A5A397071765553764A5133397549664C315456495879514E6F4C787967374A410A094A69386C736D474B56434349665274653476424F54365A56414A5867566B6831446370593853676F644B586E61582F46492F64774C446873774738546D794B6D4E5737790A09714C6D6C6D2B387861394D787073674A4E53334E6434473652302F546C346B5971696D674859566F6D7063656D4B78416E5A647A4C6C4F696F565656484D3156676559510A09774F50664C4C345239787A6243637763357439794D67396B5139776350343031346A6A30707A7551772B686D357670394779635A686B44782B522B4F3670596D3551556C0A094F373044465A4768634B5639753267497474744769767A546D344539495774787171336564706B4E692B6B4F2F4962333935497141596D2B4A2B443938484B41666562580A096E385430546A6A6E757459432F4838452F705044463379496F4B71704A6F656B73364A6C39474A6A2B4142482F763676427255562B4535555038717843544A4B4A4C522B0A094E56706E555152746B5A5432725A6D65644852524D30743966766F7864544734394D7758543147454A46374232666574356C75717757695937362F55303157774D4C37630A094654376175375A6D586E6430442F686E424D534C704A44624A3046547142526C44524C4D584F6D673376494A34765453323664586862366C6C4D674F787853746548536D0A094C3442332F693641624F4C4E65637A48786A5274646F3473446C6B4A54392F39474B52346478354F554E65573730507A67524538627931426D456D4964375538693253360A0949514466466E76753733726372535637532F6E6C37716C4A44736844306C63694334785878585738347364744D53654C5030426E6D3150306E304C5455384357705573550A093072416B365637776A6C52304B527965633866394771526B69442F4833616739717565434F706135344F72574F7631676B714C7A6843396B4E4C7145537172774B666A330A094434544571494933304F58656F6B7043636F6743364354314A6932553065726C4B51737070714D545546537A722B592B68596F4C45465737306A36664D32786C4D5352420A0948434D70774F6E33764D2B6E313242683566616D4265547958467A474A413470484835654F36486B41766C364442496F6336712F3765767A6743763346774A53666473660A09726178656D7951677753425231336C6B364775635864436C6274576B65304A4154492B726F636762636F316A5A6236704748346D534F6942776C672F304E7959454754340A0938662F575137694F37417278707A7255472B304B444A6B38664B71456C654A5770754A6679572B7962466D2B656F494D56537A6778476D424973344D31364146526867570A0976546A6C387747694C4E45657772544572516F6A71444C447161576569524B77383645784A79712F636437375439474B49483437614141666553665057644839553576660A096D4F6E67754C32556F6E4166637462662F557249745254526B69792F5A474B797855455042453346704C557263565853456D482B346B72746E6639374D74796B693750440A0964376D4B4F727570716777476C66726F6E5362613630674F724D526F67383032342B6436522B626F44312B70334168763958455839556165776965397463447250746E630A09706433493965584F754E6B54655A7770553674746C385347654A3159317133526337416B6971633964524963733561584E454C6335724369556846637141314E4A4965340A09375A43516539696D5677586D694A495539316E345549733876442F4E657A682B496E7239307142366B596463657451754143466A6131532B4750645266346939596A49470A096F52324F444D444436376A324B50412B514135307346353753355A6D6C34326B31653869767A75626170576A7A5775324F557A45573552535A744B58374F6E4E714C2F530A097052447533453756446978453071467542365349672B2F4173387278565A494549492B50416B65445557745641496E784972474657343451376B7A776C635875416144440A09736E637234304672634E6F7933494856633354706B64624744497637487065507361677477347856645246616542664E54513571624362443061475A504E2F394B6155700A09584348706A7572506E6F4655394F61746270746B6D68556B795146686162507A727A6B412B6F505A5446796D79484552686D685743566231704278484A2B345A596E4B790A09704C755852366548346148414A454A782F546F314B536935746C6A6B6E2F4D2F4358765A4A384747504B7731305372443730434539592B48335676357045763350784E430A09764D474945534742616C647146446C5359747232305477356347424E315A456B79544663682F302F7276307743334B7068454E7A5845526E674D364C564A5170624D37460A09667073506641322F52317A54564A2B392B2F5A4746744A73694A4775666F3035334C4A4B53464C2B4C4A447367702B514E6B5861653156727843767166423045477247480A09374F614D4630352B2B55764B74654A54542B754170344B55694E6F7A74594C6E6C676C545768696678575342486E714A5A5A642F652F4D767A6175503854516D6B4449580A0932522B69434331754C64765477555237792F526D334F7133664F436965423336707A6D52633871524A6B5631377458774A49652B4E5150594B624677433466785674724E0A094C5270464837387676493366427A4532367264646B6B68706E50507745553835612B4B774C6466533962445A784A2F494F65324846757154544B463363637451675147490A097A627530414776686443785359734775314B783963412B387461674B4F315670736E306B3441744B7342756F536A4A545862396251436A386B2B6D3041335265567744320A0941795A596F743675444C494E3134706E2F74645874733438466B38724F7533636C6D5A684844496F6F32796B4C46713343376841344A4C6765703459484C6962466970570A09354943342F6F4F7164426C5A4E30692F6D636B624943626F58713971656D4A7964454C744A356C357453702F48534C304F477857305644334130417433366945494A756B0A096F2B794548724C57704D574B70496C794D616C5878652B5075714A6F446E36317143434B4C55316C55574734355A656C34387148626D3979312F796D2B66646F633336780A09753946733152485952333543724F38744542335835397479484452715451784F6156736C4D2B46574B303857636261444B61477A4C74636D4A2B6679527845364C7148590A096D7278754963694251376E676D4F7A7A5865684A3655336B7A42734C366B7778427474447A594453665658746A464B5339593267634268433452635579595976583655460A096D4C3375772F546B42366B7949436638476773462F365847794A305765467171717A525073554E395A77334A614D6B6E573436786971446B3334475145527370426F71740A0974382F42474C566A6D447164352B2B42784B3061587258316C6F43693451323444666E58446730526C63563636306D6B652B686637746155592F4176616D5A6E4D796D510A094E796A32654C3163464A326E324138566E6C6354356970464379555A577A7371357473534A65535851786732617A6657623953374C2F316F426D73426A4A2F6D507670690A092B584D4C57574A65434562787259496B49612F39497339654E6C2B4E654C414C596D4F614D7A50307278485272344759794D2B4E48784E6635682F6F63306E464E764D560A0975707755754157573661514A785153726648486866384E44704B5244616232342F41384C676B626B484A4451314B5559312F396F357574555647757A7868343670344D6C0A093374434E34767137626C4154614F4A2B417A6756324552386B566449643938614958524637497A426F4441584F4751613541396E7A3633776541564C345759736B6B4C470A09724E684733396964484B355A704A764151594857744834744372674A6B5A4761546B49615A57717647496F3755394956586274494C4A334C4841736F4666684F716771680A092F35574E57512B57396A666D75794F6E544A6F784E6634387458643536384357534D6A5A69505270325232713946496D744367747050386A547150685A7042455A32614D0A094976414954775865642B78412B324F4E57767A664B312B30546473776C4F4A67544B4D2F736C4F34445A686C3237524144416C4233454B6A6F70366143787548736C76640A0946505271504858476B6B3247464C5630567A52597433497371786A323751616E6F42594132397A54345A74340A093C2F646174613E0A093C6B65793E5061796C6F61644465736372697074696F6E3C2F6B65793E0A093C737472696E673E5068617365203220636F6E66696775726174696F6E2070726F66696C653C2F737472696E673E0A093C6B65793E5061796C6F6164446973706C61794E616D653C2F6B65793E0A093C737472696E673E507572656272656420436F6E66696775726174696F6E202870686173652032293C2F737472696E673E0A093C6B65793E5061796C6F61644964656E7469666965723C2F6B65793E0A093C737472696E673E7265642E686F756E642E70726F66696C652D736572766963652E66393936333133612D363835622D313165652D626430332D3532353430306161366366663C2F737472696E673E0A093C6B65793E5061796C6F61644F7267616E697A6174696F6E3C2F6B65793E0A093C737472696E673E446F443C2F737472696E673E0A093C6B65793E5061796C6F616452656D6F76616C446973616C6C6F7765643C2F6B65793E0A093C66616C73652F3E0A093C6B65793E5061796C6F6164547970653C2F6B65793E0A093C737472696E673E436F6E66696775726174696F6E3C2F737472696E673E0A093C6B65793E5061796C6F6164555549443C2F6B65793E0A093C737472696E673E66393936333133612D363835622D313165652D626430332D3532353430306161366366663C2F737472696E673E0A093C6B65793E5061796C6F616456657273696F6E3C2F6B65793E0A093C696E74656765723E313C2F696E74656765723E0A3C2F646963743E0A3C2F706C6973743E0AA08204BE308204BA308203A2A00302010202022CD3300D06092A864886F70D01010B0500308182310B300906035504061302555331183016060355040A130F552E532E20476F7665726E6D656E74310C300A060355040B13034E5353310C300A060355040B1303446F4431223020060355040B131943657274696669636174696F6E20417574686F72697469657331193017060355040313104E5353204A4954432053572D43412D37301E170D3232313130333134323030305A170D3235313130333134323030305A3065310B300906035504061302555331183016060355040A0C0F552E532E20476F7665726E6D656E74310C300A060355040B0C034E5353310C300A060355040B0C03446F443120301E06035504030C175075726562726564205061796C6F6164205369676E657230820122300D06092A864886F70D01010105000382010F003082010A0282010100B61F2C255BAF7971E4C842AED1BC09EA894B73EDEC5700F8BDA8FFAFDB8215821AA58438689E759D196CE50D6372F7D2F797ABAFD5C0E4E40995F5DCF43B353964862AC7796A432172A6C1033AC696FD9DF4FBCB9FAE5A7B1892D5D589679CB35B6A8930BEAD448669A6FAFD2C550DA4A9060E30E43D2615F637EA8B6492A17052228083746ABBA02B3D8A2E130D5C6EB7712AE7C99459F5B03DF94DBED73F02F8A25BEAFF0E9B17DCF1BE3FAAF8777FFEE6ED2E502C8DC64C2179F761C72A8E8A4727C7F2C31315A9A05FDB186BFBCEC879AF928987EA9C130BDC027F28FF098A5766BB8EFBDE1349494A0E2572774539B114DC36D3F9B4BCF24F7D15513E210203010001A382015430820150301F0603551D2304183016801479C598CFB5A4A40D9F723620A7C6C869869E073E301D0603551D0E04160414540E0DBF5BAADD5803C93D60D4DA6B2D917C80D9307B06082B06010505070101046F306D303B06082B06010505073002862F687474703A2F2F63726C2E6E69742E646973612E6D696C2F7369676E2F4E53534A49544353575F43415F372E636572302E06082B060105050730018622687474703A2F2F6F6373702E6E736E302E726376732E6E69742E646973612E6D696C300E0603551D0F0101FF0404030205A0303F0603551D1F043830363034A032A030862E687474703A2F2F63726C2E6E69742E646973612E6D696C2F63726C2F4E53534A49544353575F43415F372E63726C30170603551D200410300E300C060A6086480165030201150330270603551D250420301E06082B0601050507030106082B0601050507030206082B06010505080202300D06092A864886F70D01010B050003820101007A887761D5C3AB44B3735715910A680DD8F67DA86F7B2D6B8C247A045F39DD6DDEF776205F267BF99E113A7D6D01448C2BB5A532322BE15851D73BF1D5DDA700302613996C036F2285F5680263D1244751F69780AE1BA4F724D32F17649EEB96A7D5429A3892DBBF0B7B2CD26A77DA199F6F23697A121825AFC5CD1508EFAFC4062090E566159E2EFFE11B9302ED2659B48F7841545892BE3E20B53F1E8C2D978F6B01AA3D5165865FC1C0D5C33415558C7C1C3421A7718ABCE935325248909FE83484E31E813BD9B235702EDF09558DEA3D9D3E83CE41D3710765F6ACE29063B34244AB32D380D9C52B719D2025EA4A223D8195DF1376A93528D026E211308C31820188308201840201038014540E0DBF5BAADD5803C93D60D4DA6B2D917C80D9300B0609608648016503040201A04B301806092A864886F70D010903310B06092A864886F70D010701302F06092A864886F70D010904312204201E64EE63F57A3760F31A8433A62DA18E7D4FB33F67F0B28BB46CF4E62B1154ED300B06092A864886F70D01010B048201000EC98725BC1ADBB60D129A48C5D94BD3169B49AC668DF17414F2D99714CA88FE0BC3D3918936F88EF2F3C3827ACE8D490435BB5FD340E2C8F3A5E84E3D461B5F163435986867F997D8B9452A39C240A66A5734A6FBEBBA3D8894DE556C7281FB425C57FBA3A9CEBC289464EFA08B4ABCADC107300721FE368DD5E810FC10AE15C76FF0AE7CCAE0401BCAC4FF869639195E4DA97823DF968E562A86895DABB09AC2E83E6E65BB04A9257F4FFB05741E5DA046AA9D59B4DE50397CAA03417437F3CE70E71670368CB66F5E2C8DAB11B0B9BAE28978D41B1D01ED5BCC262CE15580804704E75B06330DAE18E0AAFA8342DEA10F2F6B57208D59759464B196EA24E8");
    assert!(purebred_authorize_request(&content_sipr_om, "DEV")
        .await
        .is_err());
}

#[cfg(feature = "om_sipr")]
#[tokio::test]
async fn purebred_authorize_request_sha256_test_sipr_om() {
    use hex_literal::hex;
    let content = hex!("3082257406092A864886F70D010702A082256530822561020103310D300B060960864801650304020130821EFD06092A864886F70D010701A0821EEE04821EEA3C3F786D6C2076657273696F6E3D22312E302220656E636F64696E673D225554462D38223F3E0A3C21444F435459504520706C697374205055424C494320222D2F2F4170706C652F2F44544420504C49535420312E302F2F454E222022687474703A2F2F7777772E6170706C652E636F6D2F445444732F50726F70657274794C6973742D312E302E647464223E0A3C706C6973742076657273696F6E3D22312E30223E0A3C646963743E0A093C6B65793E456E637279707465645061796C6F6164436F6E74656E743C2F6B65793E0A093C646174613E0A094D4949555041594A4B6F5A496876634E415163446F4949554C54434346436B4341514978676745774D4949424C414942416F415571536B6D46435530456B494A513470680A09723948587932394A525655774451594A4B6F5A496876634E41514542425141456767454173634B6B674748453446532F4B6864525751627655455061446E6238574F51580A09584F4E2B335451674B5579495057474C636C42547242466253614B33674E6C744A69524C7A33716865654B3748377251596D433853793834715A414B76716C5848794D470A09672F7057445A4B46526E307A7A7938704D443843787838364D2F474E593232446D5642736E797A34456767674A3266596866356D41644F52517846574F515A63337757630A094541344E3973524D6D6C536554537A6B4C3767564652373141454D7858585556556C4E323858474944344A2F4F57424766513032726E702F4866767754464756495148710A09744C6336433154315A6C4A755733424F5653696736586A724942586444622B73377135384F65614355715868754E444665647865663350344374366B367270713857396B0A0963397A7652754C6D4B58716F4D732F696A6E533676674D7130533874347A7167334C634634444343457534474353714753496233445145484154416442676C67686B67420A095A514D4541536F45454A457565434F4E4836307074634D766A43766E4F64614167684C414533387A775A617368646B576756685A364C6A4634423152394B6941485044510A095842616B6A4A7A425678414938794569616253574A7A746B546979663831376F2F35713566584331487231375A743832624253764A6574474A4870397475316B6A6A43640A0936793058574673314F34656266344F707275497A3476355966497374564F2B576F50744731554C312F764F75525568636375466B31476C4E5433636E644378346952504B0A095157654B7371326A34512B4553764A7A4544444735474842354A34574756434D5073385863775A6B434D3747533675693230674C7A4E464E59615258464C2F6F653777460A09797A55627248763169442B326737707567462F37734F61324E647742666352433539352F54582B6A70414F6E6853317437744C2B66687948683633315057746C4F7257350A095769495A6567552F56523741446F70624A77666F7144724B524C4445635551627354787843557235554838555369746C4D59674C784435524A45517A534942536F762F640A093965377350326D4E6B524E51794F777A77417A6847694351657636517770506175346E724A766F774C68676D56745A4B51703465596A3342543571795A42622F346938620A0955526B304863746C4A484236656B54363242756E56507874454D3067637156764C436A55586D6F6D34734A516E4864667444693267716651554D4F6C7A78424C517745680A097857467444636B304A2B483661496D37652B58726B594953306C56373772746E73643169584F79472B625579434B516555776457446D786D5247334D494667664C3746570A0959436A7563384B725639624F7A6F777A674B366976766359325934545849682F676D387A634C4376384874755544704E47314F51516834724B772F3544625133706C6F480A09533773323662753965466F377765536F534C38727630373574493342705338762F624A574C475777467857725772504775514B6752454C687549373642465272584151360A097148397A42646732734A306E4A577061767746506E42416261735778366251776B4253667375304B596F6E583467334D4A30545339484C2F397466586C2B5664673671380A09734F7A535231476E48304955476A6453302F7978774159706D444657723137796E473838543252634F6D53524554304D693361784971346D55474D77556A472B2F7437580A096C553672795734354F7832374D644E656D4331586E6975452F5A6D65623679416B58724C386378465962327A4E5852415A43524D7668714D4F56503645475749464A76370A0978482B6F726E56467A6C5A6F7753783336526B686D374E707532397243527475502F73456841544E56504E304A33654162384D48643372394C7037314C44765159534E470A092B6C704A677A58617756416A44726A4832507476356E6E4774414F434E62497A6E6A3139565A735437467557516F462F76504D33426E5A795362365046316C657A6866710A094C6262627A745564644A4C6A6C514538796F773472766838313033624B76386F2B386D765A4B327769454C675152335A635077575250465947315661775A7949595864540A09514D68425171486F4E746E44374F4B2F73726A56745934786269614F454F724E302B4B776B714E315037777644524F3875745A386C38386659566C464F2B484D3736692F0A09756F30435336517072665378512B6646497133356E6E43656E6E6E75484958796A47576F5375397045536D6852775658635956466A6C525A6C414A576946634E524251370A093373506C53476758734D2F6B6469467771726B73636949454D4C364237736D764D646A484742533039483146614B4F52616A4D41316D58344532705776442F5A6275755A0A094D46764B6B7943685574764259572B743762455371446B502B51415353305671554C31586F6B6F66555A2B4D4D342F57444F65556C5832597A3766366E36445A31382B300A094C4B426B4C3550353338483374357A557742726866793851516D37344C5A524762436264364E6D666C306C34495175636939344E4174763754446E626559626F584747550A094239632B316F735476436B5861652F4D4D6174744342706B65535666524933736A43314F43574A4D53466B4B4B727A753370477868774232594D524549796151337476500A096D6A335147574D496C524853343539614E634B2F3866684937395A72587A4C7273506830426E42784476597561597633326E4F766D52364E334741436B64786D2F3849580A09576C514F4966417A4F786B55675447566B3763655A4C735341684B797A6F6A3072774C6A624757776F76646366583341544146734952644A2F4D6C356B66664C644E44300A09736B6D70617368436F4B5A4241686D69466F7536362F724C32595451595A424C47366E546A3833484B4150486D6339632B616B767541595A6F384635787A724C2F4E7A6A0A0945324B4D42387A4254356C504D644A6564674444554F4336635462776B396271354C514B4A647344325749722B34576F63646E462B6E6E5965386C6D4B687131333778630A096A76712B7A673374502F7A4F31685A4F567A6B396A69346E544D62663154614A637642316C4350587A2B336673306A41622B46457A327931365A47656E63752B54346A560A096F30764D424E2B495062715149596E7574456E2B6E33794937396472716B4B3868554B57514B776F46694E3862387443704A6F324239594F344867433472467669776A540A0947587A6A3154793967566B3371746B4E2F6B56334A79484551526D6F7753392F7175524F55432F7763696E646B4C78504E504B673738464C612F35786C36622B516C49760A095941634A783366415832484C4E4B33376B6D6E324B525967445A7850346943653944346230696869413735565752772F7154334836414D73445269596F6E364178526A2F0A096D674C5A556E544B496F5049474F62486C53714569362F382B48525962415465654E64547873673167616F6B77427054307269776F557856546C317777503863316D56610A0977614A42314A44553161363446567852303472745A485358737454544647326B796F4252746B2B4745556C42466549564635796A5241643161624C7877537442365677550A09324E746364673541586E4E4B3332444462646363486E4B48644352736445496E5155494249784B516D4B7566716B49544E37584C637242463650533135426263394978410A09377A74515746776B544731595650744E33756C2F6A46746A2F386F57475664573762726E6638657637317151326A62324B684B386A5761724536787279456D5358315A580A09305479617372685130357565626B7938676F47746C4C68674D5666316C68776F706A7661695242734D7477537441736D384839656B5457387969426F7963477A304D4B520A0970677878622F567857596A58476B6F6879553934757630452B6266747644364F454B6B596C524F704941473570526B4D664C6D42644F6C2B54757171694A4938704C68620A096F716F4A3153346A364573557A664A39714A6D6C5066736A6362774A443655767241652F7662666E4F4A584E5A566A2B5176484B3357436442306B517743746F75424E700A0942695A4F59634D77346E356E61366A3576616C73754C5847363144346B6C2B2B4572506D6C304E555073784B72614D4762316D524E5967752F784F4E37484B3472477A770A096B776237446D72415537563771304C6E66546A5664653649526C787747755968485664494E4736763638383235655A7256746E362F4B504B514F686467744A31762F72430A09505A6431796C6138496D3967534656644439427A76754E71453044335368756378587152442B7855515761654E67576139726F6651326F2B4C6930786D566463744136610A09784C6842445A53454A503344347836516A3475724D6B654F33454B33663766616478752F35576268624D49334F68446859512B62544A323135767175413472596E7359350A097155584647546E545A5556477A68674A6B64644A54574D624B374750764A556946576377507A54784B32354868685A4B705A472F455A70735970437A77526338474B71750A097571654A387035494C3267556B4E674E78554B6B577967657363397038355179307A31495966724A53796155684A72713855784F6B724E6961334445724F55565A4B72590A09784734315032634E46482B4937616772722B68324B36357230517A7062584168395265516E36453754476634464C55796A5143634D36352B583732723535346E6C4B4D5A0A094A71532F5559717966424C6E4B4F7955744D7541456B64384F6A5154504D5A6C6B3674677974766B7373304957725743465331474E317469696F6D7532716B74372B68770A09445764523659326E4B72795559654B31615839616D646178416C496656345047596E7A4533346D49386853696C2B2B57414F6C7656614B7449383830473774714E564D470A097847774A73686441487A36434B2B5562393151337239774F317776435A33526E76454D714168634A30777056485A554B36556B566337686E65346C4B4F326C707043764B0A095836365A33797A616B6C507073494A6E4C4865316E35314D6D7038676B742F36646D6A436F53614A4345376350714644416B752B326E347955366737737554506F717A620A0961614A61457A3956436D3447714B496474314D3237476A5A6445527646576A395662667A5A397071765553764A5133397549664C315456495879514E6F4C787967374A410A094A69386C736D474B56434349665274653476424F54365A56414A5867566B6831446370593853676F644B586E61582F46492F64774C446873774738546D794B6D4E5737790A09714C6D6C6D2B387861394D787073674A4E53334E6434473652302F546C346B5971696D674859566F6D7063656D4B78416E5A647A4C6C4F696F565656484D3156676559510A09774F50664C4C345239787A6243637763357439794D67396B5139776350343031346A6A30707A7551772B686D357670394779635A686B44782B522B4F3670596D3551556C0A094F373044465A4768634B5639753267497474744769767A546D344539495774787171336564706B4E692B6B4F2F4962333935497141596D2B4A2B443938484B41666562580A096E385430546A6A6E757459432F4838452F705044463379496F4B71704A6F656B73364A6C39474A6A2B4142482F763676427255562B4535555038717843544A4B4A4C522B0A094E56706E555152746B5A5432725A6D65644852524D30743966766F7864544734394D7758543147454A46374232666574356C75717757695937362F55303157774D4C37630A094654376175375A6D586E6430442F686E424D534C704A44624A3046547142526C44524C4D584F6D673376494A34765453323664586862366C6C4D674F787853746548536D0A094C3442332F693641624F4C4E65637A48786A5274646F3473446C6B4A54392F39474B52346478354F554E65573730507A67524538627931426D456D4964375538693253360A0949514466466E76753733726372535637532F6E6C37716C4A44736844306C63694334785878585738347364744D53654C5030426E6D3150306E304C5455384357705573550A093072416B365637776A6C52304B527965633866394771526B69442F4833616739717565434F706135344F72574F7631676B714C7A6843396B4E4C7145537172774B666A330A094434544571494933304F58656F6B7043636F6743364354314A6932553065726C4B51737070714D545546537A722B592B68596F4C45465737306A36664D32786C4D5352420A0948434D70774F6E33764D2B6E313242683566616D4265547958467A474A413470484835654F36486B41766C364442496F6336712F3765767A6743763346774A53666473660A09726178656D7951677753425231336C6B364775635864436C6274576B65304A4154492B726F636762636F316A5A6236704748346D534F6942776C672F304E7959454754340A0938662F575137694F37417278707A7255472B304B444A6B38664B71456C654A5770754A6679572B7962466D2B656F494D56537A6778476D424973344D31364146526867570A0976546A6C387747694C4E45657772544572516F6A71444C447161576569524B77383645784A79712F636437375439474B49483437614141666553665057644839553576660A096D4F6E67754C32556F6E4166637462662F557249745254526B69792F5A474B797855455042453346704C557263565853456D482B346B72746E6639374D74796B693750440A0964376D4B4F727570716777476C66726F6E5362613630674F724D526F67383032342B6436522B626F44312B70334168763958455839556165776965397463447250746E630A09706433493965584F754E6B54655A7770553674746C385347654A3159317133526337416B6971633964524963733561584E454C6335724369556846637141314E4A4965340A09375A43516539696D5677586D694A495539316E345549733876442F4E657A682B496E7239307142366B596463657451754143466A6131532B4750645266346939596A49470A096F52324F444D444436376A324B50412B514135307346353753355A6D6C34326B31653869767A75626170576A7A5775324F557A45573552535A744B58374F6E4E714C2F530A097052447533453756446978453071467542365349672B2F4173387278565A494549492B50416B65445557745641496E784972474657343451376B7A776C635875416144440A09736E637234304672634E6F7933494856633354706B64624744497637487065507361677477347856645246616542664E54513571624362443061475A504E2F394B6155700A09584348706A7572506E6F4655394F61746270746B6D68556B795146686162507A727A6B412B6F505A5446796D79484552686D685743566231704278484A2B345A596E4B790A09704C755852366548346148414A454A782F546F314B536935746C6A6B6E2F4D2F4358765A4A384747504B7731305372443730434539592B48335676357045763350784E430A09764D474945534742616C647146446C5359747232305477356347424E315A456B79544663682F302F7276307743334B7068454E7A5845526E674D364C564A5170624D37460A09667073506641322F52317A54564A2B392B2F5A4746744A73694A4775666F3035334C4A4B53464C2B4C4A447367702B514E6B5861653156727843767166423045477247480A09374F614D4630352B2B55764B74654A54542B754170344B55694E6F7A74594C6E6C676C545768696678575342486E714A5A5A642F652F4D767A6175503854516D6B4449580A0932522B69434331754C64765477555237792F526D334F7133664F436965423336707A6D52633871524A6B5631377458774A49652B4E5150594B624677433466785674724E0A094C5270464837387676493366427A4532367264646B6B68706E50507745553835612B4B774C6466533962445A784A2F494F65324846757154544B463363637451675147490A097A627530414776686443785359734775314B783963412B387461674B4F315670736E306B3441744B7342756F536A4A545862396251436A386B2B6D3041335265567744320A0941795A596F743675444C494E3134706E2F74645874733438466B38724F7533636C6D5A684844496F6F32796B4C46713343376841344A4C6765703459484C6962466970570A09354943342F6F4F7164426C5A4E30692F6D636B624943626F58713971656D4A7964454C744A356C357453702F48534C304F477857305644334130417433366945494A756B0A096F2B794548724C57704D574B70496C794D616C5878652B5075714A6F446E36317143434B4C55316C55574734355A656C34387148626D3979312F796D2B66646F633336780A09753946733152485952333543724F38744542335835397479484452715451784F6156736C4D2B46574B303857636261444B61477A4C74636D4A2B6679527845364C7148590A096D7278754963694251376E676D4F7A7A5865684A3655336B7A42734C366B7778427474447A594453665658746A464B5339593267634268433452635579595976583655460A096D4C3375772F546B42366B7949436638476773462F365847794A305765467171717A525073554E395A77334A614D6B6E573436786971446B3334475145527370426F71740A0974382F42474C566A6D447164352B2B42784B3061587258316C6F43693451323444666E58446730526C63563636306D6B652B686637746155592F4176616D5A6E4D796D510A094E796A32654C3163464A326E324138566E6C6354356970464379555A577A7371357473534A65535851786732617A6657623953374C2F316F426D73426A4A2F6D507670690A092B584D4C57574A65434562787259496B49612F39497339654E6C2B4E654C414C596D4F614D7A50307278485272344759794D2B4E48784E6635682F6F63306E464E764D560A0975707755754157573661514A785153726648486866384E44704B5244616232342F41384C676B626B484A4451314B5559312F396F357574555647757A7868343670344D6C0A093374434E34767137626C4154614F4A2B417A6756324552386B566449643938614958524637497A426F4441584F4751613541396E7A3633776541564C345759736B6B4C470A09724E684733396964484B355A704A764151594857744834744372674A6B5A4761546B49615A57717647496F3755394956586274494C4A334C4841736F4666684F716771680A092F35574E57512B57396A666D75794F6E544A6F784E6634387458643536384357534D6A5A69505270325232713946496D744367747050386A547150685A7042455A32614D0A094976414954775865642B78412B324F4E57767A664B312B30546473776C4F4A67544B4D2F736C4F34445A686C3237524144416C4233454B6A6F70366143787548736C76640A0946505271504858476B6B3247464C5630567A52597433497371786A323751616E6F42594132397A54345A74340A093C2F646174613E0A093C6B65793E5061796C6F61644465736372697074696F6E3C2F6B65793E0A093C737472696E673E5068617365203220636F6E66696775726174696F6E2070726F66696C653C2F737472696E673E0A093C6B65793E5061796C6F6164446973706C61794E616D653C2F6B65793E0A093C737472696E673E507572656272656420436F6E66696775726174696F6E202870686173652032293C2F737472696E673E0A093C6B65793E5061796C6F61644964656E7469666965723C2F6B65793E0A093C737472696E673E7265642E686F756E642E70726F66696C652D736572766963652E66393936333133612D363835622D313165652D626430332D3532353430306161366366663C2F737472696E673E0A093C6B65793E5061796C6F61644F7267616E697A6174696F6E3C2F6B65793E0A093C737472696E673E446F443C2F737472696E673E0A093C6B65793E5061796C6F616452656D6F76616C446973616C6C6F7765643C2F6B65793E0A093C66616C73652F3E0A093C6B65793E5061796C6F6164547970653C2F6B65793E0A093C737472696E673E436F6E66696775726174696F6E3C2F737472696E673E0A093C6B65793E5061796C6F6164555549443C2F6B65793E0A093C737472696E673E66393936333133612D363835622D313165652D626430332D3532353430306161366366663C2F737472696E673E0A093C6B65793E5061796C6F616456657273696F6E3C2F6B65793E0A093C696E74656765723E313C2F696E74656765723E0A3C2F646963743E0A3C2F706C6973743E0AA08204BE308204BA308203A2A00302010202022CD3300D06092A864886F70D01010B0500308182310B300906035504061302555331183016060355040A130F552E532E20476F7665726E6D656E74310C300A060355040B13034E5353310C300A060355040B1303446F4431223020060355040B131943657274696669636174696F6E20417574686F72697469657331193017060355040313104E5353204A4954432053572D43412D37301E170D3232313130333134323030305A170D3235313130333134323030305A3065310B300906035504061302555331183016060355040A0C0F552E532E20476F7665726E6D656E74310C300A060355040B0C034E5353310C300A060355040B0C03446F443120301E06035504030C175075726562726564205061796C6F6164205369676E657230820122300D06092A864886F70D01010105000382010F003082010A0282010100B61F2C255BAF7971E4C842AED1BC09EA894B73EDEC5700F8BDA8FFAFDB8215821AA58438689E759D196CE50D6372F7D2F797ABAFD5C0E4E40995F5DCF43B353964862AC7796A432172A6C1033AC696FD9DF4FBCB9FAE5A7B1892D5D589679CB35B6A8930BEAD448669A6FAFD2C550DA4A9060E30E43D2615F637EA8B6492A17052228083746ABBA02B3D8A2E130D5C6EB7712AE7C99459F5B03DF94DBED73F02F8A25BEAFF0E9B17DCF1BE3FAAF8777FFEE6ED2E502C8DC64C2179F761C72A8E8A4727C7F2C31315A9A05FDB186BFBCEC879AF928987EA9C130BDC027F28FF098A5766BB8EFBDE1349494A0E2572774539B114DC36D3F9B4BCF24F7D15513E210203010001A382015430820150301F0603551D2304183016801479C598CFB5A4A40D9F723620A7C6C869869E073E301D0603551D0E04160414540E0DBF5BAADD5803C93D60D4DA6B2D917C80D9307B06082B06010505070101046F306D303B06082B06010505073002862F687474703A2F2F63726C2E6E69742E646973612E6D696C2F7369676E2F4E53534A49544353575F43415F372E636572302E06082B060105050730018622687474703A2F2F6F6373702E6E736E302E726376732E6E69742E646973612E6D696C300E0603551D0F0101FF0404030205A0303F0603551D1F043830363034A032A030862E687474703A2F2F63726C2E6E69742E646973612E6D696C2F63726C2F4E53534A49544353575F43415F372E63726C30170603551D200410300E300C060A6086480165030201150330270603551D250420301E06082B0601050507030106082B0601050507030206082B06010505080202300D06092A864886F70D01010B050003820101007A887761D5C3AB44B3735715910A680DD8F67DA86F7B2D6B8C247A045F39DD6DDEF776205F267BF99E113A7D6D01448C2BB5A532322BE15851D73BF1D5DDA700302613996C036F2285F5680263D1244751F69780AE1BA4F724D32F17649EEB96A7D5429A3892DBBF0B7B2CD26A77DA199F6F23697A121825AFC5CD1508EFAFC4062090E566159E2EFFE11B9302ED2659B48F7841545892BE3E20B53F1E8C2D978F6B01AA3D5165865FC1C0D5C33415558C7C1C3421A7718ABCE935325248909FE83484E31E813BD9B235702EDF09558DEA3D9D3E83CE41D3710765F6ACE29063B34244AB32D380D9C52B719D2025EA4A223D8195DF1376A93528D026E211308C31820188308201840201038014540E0DBF5BAADD5803C93D60D4DA6B2D917C80D9300B0609608648016503040201A04B301806092A864886F70D010903310B06092A864886F70D010701302F06092A864886F70D010904312204201E64EE63F57A3760F31A8433A62DA18E7D4FB33F67F0B28BB46CF4E62B1154ED300B06092A864886F70D01010B048201000EC98725BC1ADBB60D129A48C5D94BD3169B49AC668DF17414F2D99714CA88FE0BC3D3918936F88EF2F3C3827ACE8D490435BB5FD340E2C8F3A5E84E3D461B5F163435986867F997D8B9452A39C240A66A5734A6FBEBBA3D8894DE556C7281FB425C57FBA3A9CEBC289464EFA08B4ABCADC107300721FE368DD5E810FC10AE15C76FF0AE7CCAE0401BCAC4FF869639195E4DA97823DF968E562A86895DABB09AC2E83E6E65BB04A9257F4FFB05741E5DA046AA9D59B4DE50397CAA03417437F3CE70E71670368CB66F5E2C8DAB11B0B9BAE28978D41B1D01ED5BCC262CE15580804704E75B06330DAE18E0AAFA8342DEA10F2F6B57208D59759464B196EA24E8");
    let _xml = purebred_authorize_request(&content, "OM_SIPR")
        .await
        .unwrap();

    let content_dev = hex!("3082250E06092A864886F70D010702A08224FF308224FB020103310D300B060960864801650304020130821EBB06092A864886F70D010701A0821EAC04821EA83C3F786D6C2076657273696F6E3D22312E302220656E636F64696E673D225554462D38223F3E0A3C21444F435459504520706C697374205055424C494320222D2F2F4170706C652F2F44544420504C49535420312E302F2F454E222022687474703A2F2F7777772E6170706C652E636F6D2F445444732F50726F70657274794C6973742D312E302E647464223E0A3C706C6973742076657273696F6E3D22312E30223E0A3C646963743E0A093C6B65793E456E637279707465645061796C6F6164436F6E74656E743C2F6B65793E0A093C646174613E0A094D4949554441594A4B6F5A496876634E415163446F4949542F544343452F6B4341514978676745774D4949424C414942416F4155772F7464474B55776C4C71334A7945560A094C573538494D6567307577774451594A4B6F5A496876634E415145424251414567674541506D4F6C6B757A2F324870315A6C3830697A302B346F766B4A44766A527436770A0974512F3773686A69455079304C424547425437683757764456514F437A587A5071756C4279477A556A32694E583247444C75594E3632675573367A336E5963364D3561590A0956694B63625547663031695A686D695934716F48515159317978595A676662634563425131706A433959344A436D70325174416E6E4D514E576764546F644D49416976640A092B4672343150507856302B5376355A395877646B6368724C4971463978337944594A314E486336696D6A3563785677384335573445736D466C3466493950736B544569590A096D4C4D3170795146724A765971665251543169424E30486469524F2B567034466D626B7A464A3645634F505278332F574E485169336D4D666F5A33632F4469796A6648300A097974445730367856352F4E5279616575755662676D7A515353366672614A45573458623842544343457234474353714753496233445145484154416442676C67686B67420A095A514D4541536F45454E577838344D34594F4D4C6949514151356C6B622B534167684B51594E6E557A4B78535454554C34494F7736306C555443644F67424276674158680A09553649323856757234734A3054427675332B686133566B704C4668776F59556C37576D30302F56464369686869306A656A6A6B655053594A414F673144712B30566A36300A092B75665A3064442B6A75397372544B4D4D5A72752B4335346F4131694B4A3634654D706B4F494C7A4D6A5472302F447734434F396C66485278585A346A525A62676C6A680A092F694538663145483865444A43417739777762374A32446F54666359576A38734D614A444E4836764E416F654F6535463145443059766A62667A43516F7434792B7948570A09547963326B2B35745537625974736B353975343246437772496A753455536E695075743255374C4E5A73515A74706B35526F446E5A4A736547516E75546959683633492B0A09527757516841454C675954704435424C344F6F7153517641783579796D3076367A4D6C51643457504C713764644D634A6361496354755052475274685975354F533366660A093037564D6F682F4B67587936594F756263385052337A7A4252436D58587558682B386B444E6B7454462F76424D2F7A4D4C694A7352344A4D795363356C327465493332710A09306E4B7A393951636F574E325356445A6C3656415169416D4F4150584D544876737367664C643558334F4F62767636584635533572724B6A5A32523268633647537757330A09322B4870766855456A7162306246306545704D6668552B492B736369343349684E4A6A2F4E7864754C5158627A7767502F4A6935474A4F725673734E746972576E4F52470A096A58316F396479784E716E41457453627338792F7A70784B6E6E52797151647162386B4E614577306C7A74527744453065457230437265466A51536F43464C72747832490A09313656523351746F4F4C6D34766E436759467246787944354F614A4C3648654C655A36673051347834563161624B7352623872374E6C4D4E464A6E7545774B38306279450A094777776E784879394D345649665A4769453232726B756B4738564C4C5A5942686B584B415050314F6B73704C35436475684268705147396A47633739624E584E694C444D0A093072513455415167752F3851674A466F65527858615670434B5848696B56436D3043386F6B50764F6C6A745975654E6378574D706B754F4B71567057344268596F324A310A09554C47504179474561793931737879566569454E55443639627546317578496F2B6B6D4D77726B4951724D56754573414D44625331364C6F56573276654E6C4155735A480A094E6D546B4935536B575145564C544E45364E352F796C7A7579445156326A517938304A385871394F426268775849324C4B59394D6A48584C42376238475A4646446F77410A095A7A785751764C534737335837517072656E68747A425351303538784E4D68396C7472392F6F504A6C716464426573356B543277507138444765527A46396B474D4551540A09677A54784F4E506B6D53464737677346576E46647648535175796E3042455A7367695A417337375A67395257466A365065516763454B2F486C4138727A783647754D69560A096C3771566A55616847747678423053347A724D2F65396F324C4B756D48536E3072543433712F72483934314D4C4932395953622B45717A583449754E6B7A6C36634558520A09503536795739354A726F726C70376C6F79496B64363461667978514B30615349754A754255554F42716363792F77536C754168447833706B6C354E5750496243673543510A096C36784D61364E3573514A6D6E6E694B4E2B352F4B67564D51527339675653312B304F454872684C624E512F45392F41422B6E6252615151703148616242444A584637580A09575955703374624B316833496657343538723766637A685555792B7231454C5243546F5253686E7A71655A4C4A32642B71624F4A784666704C554D612F66515038635A640A0941447937304765555077695133595A7A5A6D63544530364579634C4D317373466E6D34446C373744415846362B516374466B31356737724137334A69384164466D4344700A09657131664C777732396D645242316D4963464175536D3759522B436A2B794D717864632B2F42646736777056787A4B7A38316B5A43776C586F7A777964447158527468760A09367249654E313548424E4E6B7361764D73786776443544714E53696250373967326A4B687976767A375357527271754C386658324E364A574B4C2F57796B4D49684534370A097944506B68763865644A794C764D522F30474D4C4E6E34346D6344797265336B432B2F343179466369757379466972766E546B6351504731544446655155514F7A3238380A09415A58463946637A705A31326541464B476A314D6A59303462736D6E5165364B35584A455A334C4B427A756F7671786A4C68526D7757396B71366936774E78426153537A0A0939344A41646D53585144506A77633575354E53507370677950415348425A4E3568523842614872654B616A35647441375068716B596B647643666B36755330726D2B6F4B0A094676566F314E3436786A4E4A5844487157503468657431742B72494530555945456D6F715339326F357362576831376D36763476474F43695658336B45565342524F47550A0930356F744F386B41656669464D3242657857794162526E74775648694F6642576C736745574238483876516E7A357461334D5A3570414E3641356731506E4A614F4931440A0951354B452F58522B454D7475647954636A785363386F71767575666659637746755832557A796B734D505A64642B486A336437355377487642344D4B5867446D394E4D420A09677976416C6148377931334332752B55697A377A2B2B6350624F4D6C5234434F4A7763667374344D75544D347957705462696E3070314B62415167366F3175463648342B0A09716737326D466E5959427953444B6477655957656A306A756C78484F3264616F6C416A7974694A43703759676B62332B426F62486D4D5559696E683749343849327942510A0957716F464A673543466C314B5068644A704544445537494D6F33624F364858536B4C3939776743745A2F774E7069557A716B664749396C56676C4F78412B4B546459386B0A094746724F3872395032543438727472667A2B32324643304279666F654B5A58357574655677377A4B5053776551467635424D5152314148456D4E342F656667395A3332310A0979694F577972776753714E7A4B47644668524D5472593845314C70356D66446D714B4C56364871344B5874623042737478316A33735545676334565A465A624C524B78460A096A30497070714835572B776E435837794A416761384C4B55673942495179506569743633646F4D6B327A414F485A593764423041465A6D484659676B71436E3157576F370A094E65454F3433776F6A6B646E51564672756A556E5A542B475A2F4E2F59376A4D4A5A2F65552B63355666556559392B7234757537732F78516C2F35497A79445155764C300A097044417233577131643562784835457945543466444F2F77344275414869364E4768376730636B35314159366D327578566C644A42534C69733077316A78334A3779304F0A09636C6E7065576554773964506B50757833545565316639684F666B78354C7A387968716B3757304E39587A4567397336725478366735754C504C313635616C34524149490A0974483149624C4F526633356D36334B6B6D37664375784572377A62695439414E5744716665444F34765948654E795A755958625732744676567756747063794E545970760A094F756C5275367A595A46664F6D66574D41555A4A437A64564D444F392F4F39545659576E764F3048413568734A334364706275532F4F313977484C662F687956363656360A0967724E6E2F474C5269566A4749736762433655794357526E7056446C562B53346335526877634B684D335143587A4D444E6F5553314F5A5A42324F347777675A2B5034570A096F6A76614D6D4A79594E4B397A4A796B5A482B452B677564704461485444384C78753457484A59614E5A54394C74304E36447730587A4E4D49456434656B67667A7749560A09476F306464746B4A44614F593747765A6D46743258414D487369656B6A55577776504E306876633252646448745670534C3933627A504538537A5A345973313454544F530A09327777347146504176446D313949776330536D686E3350467A41397931703567547470744A643059725174684A394E63522B376866334839495170496445627455656F770A097A4A4C4837332F4F5A6B4A5A4157684458666F2B51676D683358737237776E6F664C427944312B595356396B5253544B5066466262574A714A704961622F6F31766655570A096254435874636B487535365474746B687065444175754774666777345A354435746A49584A46786B65713144366461704D63663878674F496D793667396C476942304B520A09794874646A79655938767A615945696B664D314772674E7169637A7344514F494A304B6A506577463245466F444934544E6E6A6A525A344B77686B4C634F554148762F420A094F656E6955752F617A7332707844455968784D54736A32465244594B6769687A524C724D4631756D41794B743676374359494B6C4D6D594E57596E6777485933427273370A0979416D397267714B65683859416F3337474B594930776C34614C39583065753471456D46746639752B6874736B317A647A7A5538485441776F61444B5364457444442F650A094438784A583765664D3967726F58472F646742384C4E4F6D654472776A35616D42506A6771444D4B487958497A3765785A496732324B5939414E544D76694A73512F5A4C0A0948784C7651463359384572694B3072456C4F5658396A6B59674334776F49747A51504A6F354E774537435834797A754653644F38426A6A53626970572B693035774D31390A09336E3562756A4B6E774578657131724B5366704A42535443432B6631347972306D6B6145415A707A6E41666A6F42656A664B7A477A454A3470726C394F58667779736E4F0A0944737939464A62586A69316A57783334726868354C5349676F77436F4C6B79487834636B35736172484F453632496D5356426870323945305077455441496E714D5955370A09777578343870723132763658774F466978422F59586147424678383146395056525079394930567A4471762F446D46675356742F713176504A6C593076644564683064550A094D467A544244313849682B464B4D4C6744427855433336794532656B2F6A6346586875314B63387730624435437167416F6E4D39752B4A644674724778786B41444F52350A09474F6B58333958685939585148676E78746F75786A626333684F3674484F74614A63624B6F74565153416831566531776157566A426F58524B664B2F3661374B673742770A097461655478316955416C566F39456D7275702F625947334264616B51372B52683157706C382F4E79487944475A333542754C6434342F585051554E5858674B79613539370A097673464A615A49754F783774304E346F76444C382B6A3537394C463862463138544B535551784E364970396A656365574A5768627A6E32384A38376A4D744850584B616B0A09744B6D5A6E59344D4555334936375A722B6B563668466238436C567135496541474F716C5537346A6D3541796F6C6A5A6836365A394877596D5359434F74747A324761300A094158614B592F454C5A4A3479484C7572767155566B6E6E757277316F47706A6B342B61353869577A3972635636627652452B44447030385A4632464D51446C444D79654E0A09362B68316774416C52385535352B7A2F5A6F61474C456350352B775A686B4A57697954654C30683250416B757353656C732B4E76304E647642564A316E48367A417449750A096C57512F31764749537958782B4E4C7854773053464836456F582B3765396969564A654D493137352B4C5358664776692F395A314E766E37524738414D4B3936613246540A09712B7451684D51422B344C516F2B52594F32724F4D753450655748356877326256386739617069584D59704F373174532B46654A34473742667548327A7356386C552F330A09496B4F66374C2F3357524A6773385A712F62777A334C616564547772484B676853394B7931445676625A4271326B2F31556638786674735A5A4C2B784349415452392B6A0A094669506C5742614F50796331714A7553434C346E65757A6568616D426A2B30682B38473068596A7A7439306D34537478776B66465965646F33754C6A735A415575497A510A096B416C762B426874366C4171695462444F536147562F46423371773653306E49494D726470655368754B6E6C5A6A6A4934364C51686A4D497A43756D596F416D344A63310A096735516730362B434767784A6856526257674151335A3233482F694444506968566544517A33497764435033633471744F426C694D3071434773453038796251446752500A0954595043394D79706E5A414677454D6D5438344C46794F54724C2F376C7A752B4D4775697A63343442564D4A2F577934304C6A53595349546467476174394C476E6568770A09612F63426C44473659426B442B322F4F5A4A6A305A4630676D45574F5335703467514B39345968374642617971664567526E46646C684F5962597553764C4B655A7746510A09424E495745306235645771536C4F32464378574F57496C3739506272532F35436C68656636693669445839724D4F4B43796D56452B2B56395831746A636D4934327154320A094D4F455A364D4F644B487574777A554D76394D553676774E4F3858592F582B49744C464E70376D793738687755776B67593349662F6A6B364373552F3678775A2B554F520A096B494E4B394F6250546D6D686E42386362545A5162515844664A435370694544786C6C5542793449415A5A316C724F63534C792B3850666C3438694F46327564586F46690A095639574E7469564D535A646C7072506C6E36626261334330463764367A6A664E35377149735069657A44734A643372535134554B4E62577741634F573573754A4F4441750A09466D5A71684A694A4B4667647030687A6F45726E712F38593364574A52484763425A426A334549346876455948746F6C746B693977426E683961444E335974664F7532610A095A7167336A36614248694571656B6D6167732F65744C32756F6553435372626E2F495179616B634B41756D354A5A774B53797A7278446538684E3248494238766C5274490A092B443372706A4F724B65337968736753777078452B6356506F594B6A526736714A6C6E70694D464A546F51572F307A7847687145723347616E6E447252595436425248550A09787842794E4458726E504D676E55414B49436D3563535371796174444A6A39394E526536366478757568507469686B74524F46664A52624F396C3053677A3565584137300A0973657178494B4B4A2B7836377973646A4B37524F71382F79536E3944495878695153364C6D547A54614C48502F41507148516D3049505749482B702F6263325575576F2F0A09383042516F676F475958472B6E4A436F58486B423938326B4D77572B6266442F7A70464F704B6D755475625876694D38444D5650397455756F376B6C316D4B4164477A4C0A093731586777774856674F752F2B3567314B583351486E6B7751352F6154436657776D6F596F5449752F71524B54554A6376686A4656444568334578586E497134614C47690A09756E786C41724F735550766756796E484D6E716563417536653770744F336E656A66522B726C767A384C6E6F6E555A33454B4455344D413944426E4842497A6749664B790A0948716B363974693877566F7264706E46304C4A684F4E6C50794F4E4B41314233363832595733374C78782F5243355734364F30746D687135564A673876684844664252470A09534264643936667A336C6F386B4C4C31573878674D506E6A67365179466F5950512F74562B342F2B5652465A522F5A6F516836514D376A446E6D784E47456E4C7A7171330A0973544C4966644E754B2F696E522B5A5773534F6156504438536B476A75315530357668425261306A3764386363776A4F6A717762726D4A714C36337272565367667644440A09623547643568336B71334F625466557A6F6678626C47524D734D7241592B504F676F3653697730504D3378344C68565047397A6A364A6167715532444358394B385577660A09664B456A72754D4D74466E41326C3756516C51675532743269714C5448465546744150436562504962376F4D77777139545956504956396E375239734473614B4E5443720A0950714357393231356556366D6E64785148465643506F4A6464515673346F326C4E706F637A626C535A336359444B7A416C5563686A7845484E6D67714E666852797262550A09655A636459376861496246783772746A4157314D35572B36477A444D62394D30524A66414A6A7359514A714C3578552F48485631584E4D4734757A7A4D7259374D3358700A094632366D43476151623556522F4843744C6F4B4E4E3551493154336976746E6A2B394F54596B626A434B676C332F7267646A446B6637555A6B46576D7265635A457457710A09554F55336D426C44315365334855366B4C506C62636954584B50655835345A4C66524A77636171766F7174314F50382F4E457A36677659776E6A656464356B79797261750A0972676E414B5961364C466C4C7462565A4A4E5144544155657138635655782B4C77624570512B756E4A4B3366524B7A49676B2F2F747559672F6C497A6B647752756930550A09354D6946786A51412F7A662F39634541545A783158413242344531634655706236564D36417447364D6D486651412B5459655A5878637A3354724241425335557176652B0A09377648724B32584C4C6D3652614E4E78507366754549347970507767417548553847687569386271614E4A33397958420A093C2F646174613E0A093C6B65793E5061796C6F61644465736372697074696F6E3C2F6B65793E0A093C737472696E673E5068617365203220636F6E66696775726174696F6E2070726F66696C653C2F737472696E673E0A093C6B65793E5061796C6F6164446973706C61794E616D653C2F6B65793E0A093C737472696E673E507572656272656420436F6E66696775726174696F6E202870686173652032293C2F737472696E673E0A093C6B65793E5061796C6F61644964656E7469666965723C2F6B65793E0A093C737472696E673E7265642E686F756E642E70726F66696C652D736572766963652E39316237346438612D363738322D313165652D383566652D3065336562366136613564643C2F737472696E673E0A093C6B65793E5061796C6F61644F7267616E697A6174696F6E3C2F6B65793E0A093C737472696E673E446F443C2F737472696E673E0A093C6B65793E5061796C6F616452656D6F76616C446973616C6C6F7765643C2F6B65793E0A093C66616C73652F3E0A093C6B65793E5061796C6F6164547970653C2F6B65793E0A093C737472696E673E436F6E66696775726174696F6E3C2F737472696E673E0A093C6B65793E5061796C6F6164555549443C2F6B65793E0A093C737472696E673E39316237346438612D363738322D313165652D383566652D3065336562366136613564643C2F737472696E673E0A093C6B65793E5061796C6F616456657273696F6E3C2F6B65793E0A093C696E74656765723E313C2F696E74656765723E0A3C2F646963743E0A3C2F706C6973743E0AA082049A308204963082037EA00302010202025EED300D06092A864886F70D01010B0500305D310B300906035504061302555331183016060355040A0C0F552E532E20476F7665726E6D656E74310C300A060355040B0C03446F44310C300A060355040B0C03504B493118301606035504030C0F444F442050422053572043412D3533301E170D3232303531393136353331365A170D3235303430383130353130345A3057310B300906035504061302555331183016060355040A0C0F552E532E20476F7665726E6D656E74310C300A060355040B0C03504B493120301E06035504030C175075726562726564205061796C6F6164205369676E657230820122300D06092A864886F70D01010105000382010F003082010A0282010100BD9E57FAEA20C4C4AF323D8D5ED46FF71BB0F6E705A037CC425D33BE74F7CE06981C65975F8A4663BDF5F177B754DFBD17D386324189B8F62EB2FA361BA7ABF5F307CB5E69E81948C88E86E0642352E0033D61E3EDE4412BF870392E5CA85D894ED7748E687E1B4443E08AC06AA73513D4E5D4C99843873F470B143A302F1B3DEC04E8F63D988AEE170C16826129E94F000A816C541AD67615686198918197EF23A50C2B14DB04E2E175AE4D9440C9E6DCE9287514DE4CC09B6139779E0D12E07575C4A72D311487241E2D1E520B5CAA1E1F668B0A211114485744BD12027B92DFF3320ABFF7560C11D70C8C3C87DDB6D88D315C0656EBCE8EF06AA3F275CCE30203010001A382016430820160301F0603551D2304183016801461BF1745A00B56DC28F3EEC5FB6DA305C3B5F48C301D0603551D0E04160414D8D53B10803CBE8B58533012B4AA4D00F901D30F30818306082B0601050507010104773075304306082B060105050730028637687474703A2F2F706263726C2E726564686F756E64736F6674776172652E6E65742F7369676E2F444F445042535743415F35332E636572302E06082B060105050730018622687474703A2F2F70626F6373702E726564686F756E64736F6674776172652E6E6574300E0603551D0F0101FF0404030205A030470603551D1F0440303E303CA03AA0388636687474703A2F2F706263726C2E726564686F756E64736F6674776172652E6E65742F63726C2F444F445042535743415F35332E63726C30160603551D20040F300D300B0609608648016502010B2730270603551D250420301E06082B0601050507030106082B0601050507030206082B06010505080202300D06092A864886F70D01010B05000382010100926B181913EB28DE70DEC9D07DC782114A78513E820A575C64321039616C83BB4ED7E0C7B53F641E335A3F1191013F3B5222C127C59AD8E32A8E5E1D58BE8DA1895C2FDF480490646D604209A99898E3D469C9DE37746750DFB20AE22A68998064E630BFB1562132667FFB4C40D3A700757AA139A40243658F3FC5A12ECE9D9BDBE0F1B0B6D6A30FD0230DE69F4321E6AE9A3EE339622312EB8D1526D294F9D70E08B99E2E009D7D95923AC20226B322EFB3736AFB08D9D96E6A6C5BD7ACED8947EAC1AA29B79B7443F1F55C69C844CED9182762AFE749B9A21B78D3BDB98C3624021B459901FAA988AF910312F8AC65FDF720EF1125F1A8C2B7EE21EE3AF95731820188308201840201038014D8D53B10803CBE8B58533012B4AA4D00F901D30F300B0609608648016503040201A04B301806092A864886F70D010903310B06092A864886F70D010701302F06092A864886F70D01090431220420813255942A5700BE4D51DC2B639C064CC8E8C74C60D4D392C53451CB0EB63676300B06092A864886F70D01010B04820100751834CFE00CA210B84DB14BDA6F6C8C157C01CF8A984A99221B85CAB0830C3E59D8E58A84D4DFF32CEAD87CE3763CCE7A3E5CBFCA9A66C024942CA7229830F45CCBB34DE2853737EFECF3480B3449EA985CA64E7BEFA7438B61F041FF314CC8C21D10DF19A1D66E44724A84D68A31B90C2472D33E8DC9FD3CFE8EC61E5A114C3DD8463E3BE048E01036BAB1C88EE22243BC91B970A572B4D45370472849F319F98B54EC85C7F7426700AA1FD2C660EF72EC0189052AC471E08C6AC3958327F4D10F02B78CC2B1B889BEB4D47BCBD99880F193DC62A18DEFF2B865C02E3C9C32689B44262C45D0C7BECA54963E6616DFB3DA715CB0B83E522C1116BD4C770107");
    assert!(purebred_authorize_request(&content_dev, "OM_SIPR")
        .await
        .is_err());
}
