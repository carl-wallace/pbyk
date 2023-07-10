use cipher::generic_array::GenericArray;
use cipher::BlockDecryptMut;
use cipher::KeyIvInit;
use std::io::Cursor;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use subtle_encoding::hex;

use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::CertificateChoices;
use cms::enveloped_data::{EnvelopedData, RecipientIdentifier, RecipientInfo};
use cms::signed_data::SignerIdentifier;
use cms::{
    content_info::ContentInfo,
    signed_data::{EncapsulatedContentInfo, SignedData},
};
use const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER;
use der::asn1::{OctetString, UtcTime};
use der::{Any, Decode, Encode, Tag};
use plist::Dictionary;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoRef};
use x509_cert::builder::CertificateBuilder;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::Certificate;
use yubikey::{
    piv,
    piv::{AlgorithmId, SlotId},
    MgmKey, PinPolicy, TouchPolicy, YubiKey,
};

use crate::p12::import_p12;
use crate::rsa_utils::decrypt_inner;
use crate::scep::process_scep_payload;
use crate::{log_error, Error, Result};
use yubikey::certificate::yubikey_signer::Rsa2048;
use yubikey::certificate::yubikey_signer::YubiRsa;

/// Generates a self-signed certificate containing a public key corresponding to the given algorithm
/// and a subject DN set to "cn=<cn>, c=US" using the indicated slot on the provided YubiKey.
pub fn generate_self_signed_cert(
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
    let name = Name::from_str(name).map_err(Error::Asn1)?;
    let spkibuf = public_key.to_der().map_err(Error::Asn1)?;
    let b = Sha1::digest(spkibuf);
    let os = OctetString::new(b.as_slice()).map_err(Error::Asn1)?;
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
pub fn buffer_to_hex(buffer: &[u8]) -> String {
    let hex = hex::encode_upper(buffer);
    let r = std::str::from_utf8(hex.as_slice());
    if let Ok(s) = r {
        s.to_string()
    } else {
        "".to_string()
    }
}

pub(crate) fn get_encap_content(eci: &EncapsulatedContentInfo) -> Result<Vec<u8>> {
    let encap = match &eci.econtent {
        Some(e) => e,
        None => return Err(Error::ParseError),
    };

    let encos = encap.to_der().map_err(Error::Asn1)?;
    let os = OctetString::from_der(&encos).map_err(Error::Asn1)?;
    Ok(os.as_bytes().to_vec())
}

fn get_encrypted_payload_content(xml: &[u8]) -> Result<Vec<u8>> {
    let xml_cursor = Cursor::new(xml);
    let profile = plist::Value::from_reader(xml_cursor).map_err(|_e| Error::Plist)?;

    let profile_dict = match profile.as_dictionary() {
        Some(d) => d,
        None => return Err(Error::Plist),
    };

    match profile_dict.get("EncryptedPayloadContent") {
        Some(p) => match p.as_data() {
            Some(v) => Ok(v.to_vec()),
            None => Err(Error::Plist),
        },
        None => Err(Error::Plist),
    }
}

/// Verifies (not at present) a SignedData then decrypts an encapsulated EnvelopedData and returns
/// the encapsulated contents  from it as a buffer.
pub(crate) fn verify_and_decrypt(
    yubikey: &mut YubiKey,
    slot: SlotId,
    content: &[u8],
    is_ota: bool,
    pin: &[u8],
    mgmt_key: &MgmKey,
) -> Result<Vec<u8>> {
    assert!(yubikey.verify_pin(pin).is_ok());
    assert!(yubikey.authenticate(mgmt_key.clone()).is_ok());

    let ci_sd = ContentInfo::from_der(content).map_err(Error::Asn1)?;
    if ci_sd.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        log_error(&format!(
            "Unexpected content type (expected ID_SIGNED_DATA): {:?}",
            ci_sd.content_type
        ));
        return Err(Error::ParseError);
    }

    // todo verify signature and validate path to signer

    let bytes2 = ci_sd.content.to_der().map_err(Error::Asn1)?;
    let sd = SignedData::from_der(&bytes2).map_err(Error::Asn1)?;
    let xml = get_encap_content(&sd.encap_content_info)?;

    let enc_ci = match is_ota {
        true => get_encrypted_payload_content(&xml)?,
        false => xml.to_vec(),
    };

    let ci_ed = ContentInfo::from_der(&enc_ci).map_err(Error::Asn1)?;
    if ci_ed.content_type != const_oid::db::rfc5911::ID_ENVELOPED_DATA {
        log_error(&format!(
            "Unexpected content type (expected ID_ENVELOPED_DATA): {:?}",
            ci_ed.content_type
        ));
        return Err(Error::ParseError);
    }
    let bytes2ed = ci_ed.content.to_der().map_err(Error::Asn1)?;
    let ed = EnvelopedData::from_der(&bytes2ed).map_err(Error::Asn1)?;

    let params = match ed.encrypted_content.content_enc_alg.parameters {
        Some(p) => p,
        None => return Err(Error::Unrecognized),
    };
    let enc_params = params.to_der().map_err(Error::Asn1)?;

    let os_iv = OctetString::from_der(&enc_params).map_err(Error::Asn1)?;
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
        econtent: Some(Any::new(Tag::OctetString, data_to_sign).map_err(Error::Asn1)?),
    };

    let enc_spki = signers_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(Error::Asn1)?;
    let spki_ref = SubjectPublicKeyInfoRef::from_der(&enc_spki).map_err(Error::Asn1)?;

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
            log_error(&format!("Failed to create SignerInfoBuilder: {:?}", e));
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
            log_error(&format!("Failed to encoded SignedData: {:?}", e));
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
                        log_error(&format!("Failed to parse SKID extension: {:?}. Ignoring error and will use calculated value.", e));
                    }
                }
            }
        }
    }

    let working_spki = &cert.tbs_certificate.subject_public_key_info;
    match working_spki.subject_public_key.as_bytes() {
        Some(spki) => Ok(Sha256::digest(spki).to_vec()),
        None => {
            log_error("Failed to render SPKI as bytes");
            Err(Error::Unrecognized)
        }
    }
}

/// Processes payloads from the presented `xml` generating and import keys using the provided YubiKey
pub async fn process_payloads(
    yubikey: &mut YubiKey,
    xml: &[u8],
    pin: &[u8],
    mgmt_key: &MgmKey,
) -> Result<()> {
    let xml_cursor = Cursor::new(xml);
    let profile = match plist::Value::from_reader(xml_cursor) {
        Ok(p) => p,
        Err(e) => {
            log_error(&format!("Failed to parse XML in process_payloads: {:?}", e));
            return Err(Error::Plist);
        }
    };
    let payloads = match profile.as_array() {
        Some(d) => d,
        None => {
            log_error("Failed to parse profile as an array: {:?}");
            return Err(Error::Plist);
        }
    };

    let mut p12_index = 0;
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
                                        log_error("Failed to parse PayloadContent as a dictionary for SCEP payload.");
                                        return Err(Error::Plist);
                                    }
                                },
                                None => {
                                    log_error("SCEP payload missing PayloadContent.");
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
                            )
                            .await
                            {
                                log_error(&format!("Failed to process SCEP payload: {:?}.", e));
                                return Err(e);
                            }
                        } else if "com.apple.security.pkcs12" == t {
                            let payload_content = match dict.get("PayloadContent") {
                                Some(pc) => match pc.as_data() {
                                    Some(d) => d,
                                    None => {
                                        log_error("Failed to parse PayloadContent as a data for PKCS #12 payload.");
                                        return Err(Error::Plist);
                                    }
                                },
                                None => {
                                    log_error("PKCS #12 payload missing PayloadContent.");
                                    return Err(Error::Plist);
                                }
                            };
                            let password = match dict.get("Password") {
                                Some(pc) => match pc.as_string() {
                                    Some(d) => d,
                                    None => {
                                        log_error("Failed to parse Password as a data for PKCS #12 payload.");
                                        return Err(Error::Plist);
                                    }
                                },
                                None => {
                                    log_error("PKCS #12 payload missing Password.");
                                    return Err(Error::Plist);
                                }
                            };
                            if let Err(e) =
                                import_p12(yubikey, payload_content, password, p12_index).await
                            {
                                log_error(&format!("Failed to process PKCS #12 payload at index {p12_index}: {:?}.", e));
                                return Err(e);
                            }
                            p12_index += 1;
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
            for elem in subject_array {
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
                                vrdn.push(format!("{}={}", rdn_type, rdn_value));
                            }
                        }
                    }
                    dn.push(vrdn.join("+"))
                } else {
                    log_error("Failed to an RDN entry as an array");
                    return Err(Error::Plist);
                }
            }
        } else {
            log_error("Failed to parse Subject entry as an array");
            return Err(Error::Plist);
        }
    } else {
        log_error("No Subject entry was found in the dictionary");
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
