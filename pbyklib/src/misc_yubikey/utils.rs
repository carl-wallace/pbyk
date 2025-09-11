//! YubiKey-related utility functions

use std::{
    io::Cursor,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use log::{error, info};
use rand_core::{OsRng, RngCore, TryRngCore};

use cipher::{BlockModeDecrypt, KeyIvInit};
use sha1::{Digest, Sha1};

use cms::{
    content_info::ContentInfo,
    enveloped_data::{EnvelopedData, RecipientInfo},
    signed_data::EncapsulatedContentInfo,
};
use const_oid::db::rfc4519::COMMON_NAME;
use der::zeroize::Zeroizing;
use der::{
    Decode, Encode, Tag, Tagged,
    asn1::{
        Ia5StringRef, OctetString, PrintableStringRef, TeletexStringRef, UtcTime, Utf8StringRef,
    },
};
use x509_cert::{
    Certificate,
    builder::CertificateBuilder,
    ext::pkix::SubjectKeyIdentifier,
    name::Name,
    serial_number::SerialNumber,
    time::{Time, Validity},
};

use yubikey::{
    Key, MgmKey, PinPolicy, TouchPolicy, Uuid, YubiKey,
    certificate::{SelfSigned, yubikey_signer},
    piv,
    piv::{AlgorithmId, SlotId},
};

use pbykcorelib::misc::utils::{
    get_as_string, get_encrypted_payload_content, purebred_authorize_request,
};

use crate::{
    Error, Result,
    misc::rsa_utils::decrypt_inner,
    misc_yubikey::{p12::import_p12, scep::process_scep_payload},
    ota_yubikey::enroll::get_rsa_algorithm,
    utils::get_cert_from_slot,
};

/// Generates an attestation for the indicated slot and returns a P7 containing that attestation and
/// the attestation certificate read from the Attestation slot.
pub(crate) fn get_attestation_p7(yubikey: &mut YubiKey, slot_id: SlotId) -> Result<Vec<u8>> {
    let attestation = match piv::attest(yubikey, slot_id) {
        Ok(a) => a,
        Err(e) => {
            error!(
                "Failed to attest to key generated in slot {slot_id}: {:?}",
                e
            );
            return Err(Error::YubiKey(e));
        }
    };

    let ac = match Certificate::from_der(attestation.as_slice()) {
        Ok(ac) => ac,
        Err(e) => {
            error!(
                "Failed to parse attestation for key generated in slot {slot_id}: {:?}",
                e
            );
            return Err(Error::Asn1(e));
        }
    };

    let content = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: None,
    };

    let mut builder = cms::builder::SignedDataBuilder::new(&content);
    match Key::list(yubikey) {
        Ok(keys) => {
            let mut found = false;
            for key in keys {
                if key.slot() == SlotId::Attestation {
                    match builder.add_certificate(cms::cert::CertificateChoices::Certificate(
                        key.certificate().cert.clone(),
                    )) {
                        Ok(_) => {
                            found = true;
                        }
                        Err(e) => {
                            error!(
                                "Failed to add certificate read from Attestation slot: {:?}",
                                e
                            );
                            return Err(Error::Unrecognized);
                        }
                    }
                }
            }
            if !found {
                error!("Failed read certificate from Attestation slot. Ignoring error.");
            }
        }
        Err(e) => {
            error!("Failed to list keys on YubiKey: {e:?}");
            return Err(Error::YubiKey(e));
        }
    }
    if let Err(e) = builder.add_certificate(cms::cert::CertificateChoices::Certificate(ac)) {
        error!(
            "Failed to add attestation certificate for slot {slot_id}: {:?}",
            e
        );
        return Err(Error::Unrecognized);
    }

    let signed_data_pkcs7 = match builder.build() {
        Ok(sd) => sd,
        Err(e) => {
            error!("Failed build attestation PKCS7 for slot {slot_id}: {e:?}");
            return Err(Error::Unrecognized);
        }
    };

    match signed_data_pkcs7.to_der() {
        Ok(attestation_p7) => Ok(attestation_p7),
        Err(e) => {
            error!(
                "Failed encode attestation PKCS7 for slot {slot_id}: {:?}",
                e
            );
            Err(Error::Asn1(e))
        }
    }
}

/// Reads certificate from CardAuthentication and extracts common name RDN in subject name. The value
/// in the CN attribute is notionally a UUID.
pub(crate) fn get_uuid_from_cert(yubikey: &mut YubiKey) -> Result<String> {
    let cert = match yubikey::certificate::Certificate::read(yubikey, SlotId::CardAuthentication) {
        Ok(c) => c,
        Err(e) => {
            error!(
                "Failed to read certificate from the CardAuthentication slot to harvest UUID value: {:?}",
                e
            );
            return Err(Error::Unrecognized);
        }
    };

    for n in cert.cert.tbs_certificate().subject().iter_rdn() {
        for a in n.iter() {
            if a.oid == COMMON_NAME {
                let val = match a.value.tag() {
                    Tag::PrintableString => PrintableStringRef::try_from(&a.value)
                        .ok()
                        .map(|s| s.as_str()),
                    Tag::Utf8String => Utf8StringRef::try_from(&a.value).ok().map(|s| s.as_str()),
                    Tag::Ia5String => Ia5StringRef::try_from(&a.value).ok().map(|s| s.as_str()),
                    Tag::TeletexString => TeletexStringRef::try_from(&a.value)
                        .ok()
                        .map(|s| s.as_str()),
                    _ => None,
                };
                if let Some(v) = val {
                    if Uuid::parse_str(v).is_err() {
                        error!(
                            "Value read from common name of certificate read from CardAuthentication slot could not be parsed as a UUID: {v}"
                        );
                        return Err(Error::UnexpectedValue);
                    }
                    return Ok(v.to_string());
                }
            }
        }
    }
    Err(Error::Unrecognized)
}

/// Generates a self-signed certificate containing a public key corresponding to the given algorithm
/// and a subject DN set to the provided value using the indicated slot on the provided YubiKey.
pub(crate) fn generate_self_signed_cert(
    yubikey: &mut YubiKey,
    slot: SlotId,
    algorithm: AlgorithmId,
    name: &str,
    pin: &[u8],
    mgmt_key: &MgmKey,
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
    OsRng.unwrap_err().fill_bytes(&mut serial);
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
    let validity = Validity::new(
        Time::UtcTime(
            UtcTime::from_unix_duration(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Error::Unrecognized)?,
            )
            .map_err(|_| Error::Unrecognized)?,
        ),
        not_after,
    );
    let name = Name::from_str(name)?;
    let spki_buffer = public_key.to_der()?;
    let b = Sha1::digest(spki_buffer);
    let os = OctetString::new(b.as_slice())?;
    let skid = SubjectKeyIdentifier(os);

    if let Err(e) = yubikey.verify_pin(pin) {
        error!("Failed to verify PIN in generate_self_signed_cert: {e:?}");
        return Err(Error::YubiKey(e));
    }
    if let Err(e) = yubikey.authenticate(mgmt_key) {
        error!("Failed to authenticate using management key in generate_self_signed_cert: {e:?}");
        return Err(Error::YubiKey(e));
    }

    let builder = |builder: &mut CertificateBuilder<SelfSigned>| {
        if let Err(e) = builder.add_extension(&skid) {
            error!(
                "Failed to add SKID extension to certificate builder when generating self-signed certificate for Yubikey: {e:?}"
            );
        }
        Ok(())
    };

    let result = match algorithm {
        AlgorithmId::Rsa2048 => {
            yubikey::certificate::Certificate::generate_self_signed::<
                _,
                yubikey_signer::YubiRsa<yubikey_signer::Rsa2048>,
            >(yubikey, slot, serial, validity, name, public_key, builder)
        }
        AlgorithmId::Rsa3072 => {
            yubikey::certificate::Certificate::generate_self_signed::<
                _,
                yubikey_signer::YubiRsa<yubikey_signer::Rsa3072>,
            >(yubikey, slot, serial, validity, name, public_key, builder)
        }
        AlgorithmId::Rsa4096 => {
            yubikey::certificate::Certificate::generate_self_signed::<
                _,
                yubikey_signer::YubiRsa<yubikey_signer::Rsa4096>,
            >(yubikey, slot, serial, validity, name, public_key, builder)
        }
        _ => {
            error!("Unsupported algorithm: {algorithm:?}");
            return Err(Error::Unrecognized);
        }
    };

    match result {
        Ok(cert) => Ok(cert.cert),
        Err(e) => Err(Error::YubiKey(e)),
    }
}

/// Verifies a SignedData then decrypts an encapsulated EnvelopedData and returns the encapsulated
/// contents from it as a buffer.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify_and_decrypt(
    yubikey: &mut YubiKey,
    slot: SlotId,
    content: &[u8],
    is_ota: bool,
    pin: &[u8],
    mgmt_key: &MgmKey,
    env: &str,
    alg: AlgorithmId,
) -> Result<Zeroizing<Vec<u8>>> {
    if let Err(e) = yubikey.verify_pin(pin) {
        error!("Failed to verify PIN in verify_and_decrypt: {e:?}");
        return Err(Error::YubiKey(e));
    }
    if let Err(e) = yubikey.authenticate(mgmt_key) {
        error!("Failed to authenticate using management key in verify_and_decrypt: {e:?}");
        return Err(Error::YubiKey(e));
    }

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

    let mut ct = match ed.encrypted_content.encrypted_content {
        Some(ct) => ct.as_bytes().to_vec(),
        None => return Err(Error::Unrecognized),
    };

    for ri in ed.recip_infos.0.iter() {
        let dec_key = match ri {
            RecipientInfo::Ktri(ktri) => {
                let dk = match piv::decrypt_data(yubikey, ktri.enc_key.as_bytes(), alg, slot) {
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

        /// decryption type
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
        let cipher = match Aes256CbcDec::new_from_slices(&dec_key.1[dec_key.2 as usize..], iv) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to create new Aes256CbcDec instance: {e}. Continuing...");
                continue;
            }
        };
        if let Ok(pt) = cipher.decrypt_padded::<cipher::block_padding::Pkcs7>(&mut ct) {
            return Ok(Zeroizing::new(pt.to_vec()));
        }
    }
    Err(Error::Unrecognized)
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
        if let Some(dict) = payload.as_dictionary()
            && let Some(payload_type) = dict.get("PayloadType")
        {
            match payload_type.as_string() {
                Some(t) => {
                    if "com.apple.security.scep" == t {
                        let payload_content = match dict.get("PayloadContent") {
                            Some(pc) => match pc.as_dictionary() {
                                Some(d) => d,
                                None => {
                                    error!(
                                        "Failed to parse PayloadContent as a dictionary for SCEP payload."
                                    );
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
                                    error!(
                                        "Failed to parse PayloadContent as a data for PKCS #12 payload."
                                    );
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
                                    error!(
                                        "Failed to parse Password as a data for PKCS #12 payload."
                                    );
                                    return Err(Error::Plist);
                                }
                            },
                            None => {
                                error!("PKCS #12 payload missing Password.");
                                return Err(Error::Plist);
                            }
                        };

                        info!("Processing PKCS #12 payload with index {p12_index}");
                        if let Err(e) =
                            import_p12(yubikey, payload_content, password, recovered_index, None)
                                .await
                        {
                            error!(
                                "Failed to process PKCS #12 payload at index {p12_index}: {e:?}."
                            );
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
    Ok(())
}

/// Determines the algorithm associated with the card authentication slow, i.e., RSA 2048, 3072 or 4096.
pub(crate) fn get_card_auth_alg(yubikey: &mut YubiKey) -> Result<AlgorithmId> {
    match get_cert_from_slot(yubikey, SlotId::CardAuthentication) {
        Ok(c) => {
            let enc_spki = c.tbs_certificate().subject_public_key_info().to_der()?;
            get_rsa_algorithm(&enc_spki)
        }
        Err(e) => {
            error!("Failed to get certificate from CardAuthentication slot: {e:?}");
            Err(Error::NotFound)
        }
    }
}
