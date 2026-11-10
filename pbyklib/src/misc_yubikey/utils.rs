//! YubiKey-related utility functions

use std::{
    cell::{Cell, RefCell},
    io::Cursor,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use log::{error, info};
use pbykcorelib::misc::{
    pki::{new_cms_environment, new_pki_environment},
    rng::pb_rng,
};
use rand_core::TryRng;

use sha1::{Digest, Sha1};

use certval_cms::{CmsEnvironment, KeyTransportAlgorithm, RecipientCredential, unpad_pkcs1v15};
use cms::{content_info::ContentInfo, signed_data::EncapsulatedContentInfo};
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
    misc_yubikey::{
        p12::import_p12,
        retry::{is_transient_yubikey_error, retry_after_pcsc_drop},
        scep::process_scep_payload,
    },
    ota_yubikey::enroll::get_rsa_algorithm,
    utils::get_cert_from_slot,
};

/// Generates an attestation for the indicated slot and returns a P7 containing that attestation and
/// the attestation certificate read from the Attestation slot.
///
/// The PIN and management key are used to reconnect to the YubiKey and retry if it drops out of the
/// reader while the attestation is being generated (see [retry_after_pcsc_drop]).
pub(crate) fn get_attestation_p7(
    yubikey: &mut YubiKey,
    slot_id: SlotId,
    pin: &[u8],
    mgmt_key: &MgmKey,
) -> Result<Vec<u8>> {
    retry_after_pcsc_drop(
        yubikey,
        pin,
        mgmt_key,
        &format!("Attestation for slot {slot_id}"),
        |yubikey| get_attestation_p7_inner(yubikey, slot_id),
    )
}

/// Body of [get_attestation_p7], factored out so it can be retried after a dropped connection.
fn get_attestation_p7_inner(yubikey: &mut YubiKey, slot_id: SlotId) -> Result<Vec<u8>> {
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
///
/// On-card RSA key generation is the longest single operation pbyk performs -- minutes for a 4096
/// bit key -- and is where a YubiKey is most likely to drop out of the reader. If that happens the
/// YubiKey is reconnected and the key is generated again (see [retry_after_pcsc_drop]). Generating
/// a fresh key overwrites whatever the interrupted attempt left in the slot.
pub(crate) fn generate_self_signed_cert(
    yubikey: &mut YubiKey,
    slot: SlotId,
    algorithm: AlgorithmId,
    name: &str,
    pin: &[u8],
    mgmt_key: &MgmKey,
) -> Result<Certificate> {
    retry_after_pcsc_drop(
        yubikey,
        pin,
        mgmt_key,
        &format!("Generation of a {algorithm:?} key and self-signed certificate in slot {slot}"),
        |yubikey| generate_self_signed_cert_inner(yubikey, slot, algorithm, name, pin, mgmt_key),
    )
}

/// Body of [generate_self_signed_cert], factored out so it can be retried after a dropped connection.
fn generate_self_signed_cert_inner(
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
    pb_rng()
        .try_fill_bytes(&mut serial)
        .map_err(|_| Error::Unrecognized)?;
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

/// A [`RecipientCredential`] over an RSA key in a YubiKey slot: the card performs the raw RSA
/// operation and certval-cms removes the PKCS #1 v1.5 padding.
///
/// certval-cms stands in a random content-encryption key for a key transport that fails
/// (RFC 3218), so a PC/SC failure during the card operation would otherwise surface only as
/// undecryptable content. The failure is kept here for the caller, which reconnects and retries.
struct YubiKeyRecipientKey<'y> {
    /// The card, borrowed for the decryption; `RecipientCredential` takes `&self`.
    yubikey: RefCell<&'y mut YubiKey>,
    /// The slot holding the key.
    slot: SlotId,
    /// The key's RSA size, which the card's decrypt command and the unpadding need.
    alg: AlgorithmId,
    /// The slot's certificate, which recipient identifiers are matched against.
    certificate: Certificate,
    /// A PC/SC failure met while decrypting, for the caller to reconnect on.
    transient_error: Cell<Option<yubikey::Error>>,
}

impl YubiKeyRecipientKey<'_> {
    /// The length in octets of the key's modulus, which is the length of a raw RSA decryption.
    fn modulus_octets(&self) -> Option<usize> {
        match self.alg {
            AlgorithmId::Rsa2048 => Some(256),
            AlgorithmId::Rsa3072 => Some(384),
            AlgorithmId::Rsa4096 => Some(512),
            _ => None,
        }
    }
}

impl RecipientCredential for YubiKeyRecipientKey<'_> {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn decrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        encrypted_key: &[u8],
    ) -> certval_cms::Result<Zeroizing<Vec<u8>>> {
        // The card decrypts without padding, and the portals encrypt to these keys with PKCS #1
        // v1.5 only.
        if alg != KeyTransportAlgorithm::RsaPkcs1v15 {
            return Err(certval_cms::Error::Unrecognized);
        }
        let Some(k) = self.modulus_octets() else {
            return Err(certval_cms::Error::Unrecognized);
        };
        let mut guard = self.yubikey.borrow_mut();
        let yubikey: &mut YubiKey = &mut guard;
        let em = piv::decrypt_data(yubikey, encrypted_key, self.alg, self.slot).map_err(|e| {
            if is_transient_yubikey_error(&e) {
                error!("YubiKey went away while decrypting a content encryption key: {e:?}");
                self.transient_error.set(Some(e));
            }
            certval_cms::Error::Crypto(String::from("the YubiKey did not decrypt the key"))
        })?;
        unpad_pkcs1v15(&em, k)
    }
}

/// Verifies a SignedData then decrypts an encapsulated EnvelopedData and returns the encapsulated
/// contents from it as a buffer.
///
/// The EnvelopedData is decrypted with the key in `slot`, whose certificate the message must name
/// as a recipient, and with the content encryption algorithm the message names.
///
/// The slot's certificate is read before the PIN is verified: a slot whose PIN policy is "always"
/// refuses the decrypt if the card has answered anything else since the verification.
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
    let certificate = get_cert_from_slot(yubikey, slot)?;
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
    let content_info = ContentInfo::from_der(&enc_ci)?;

    retry_after_pcsc_drop(
        yubikey,
        pin,
        mgmt_key,
        "Decryption of a content encryption key",
        |yubikey| decrypt_enveloped_data(yubikey, slot, alg, certificate.clone(), &content_info),
    )
}

/// Decrypts `content_info`, an EnvelopedData, with the key in `slot`, whose certificate is
/// `certificate`. The decrypt is the first command sent to the card.
///
/// A YubiKey that goes away mid-operation is reported as such rather than as a decryption failure,
/// so the caller can reconnect and try again.
fn decrypt_enveloped_data(
    yubikey: &mut YubiKey,
    slot: SlotId,
    alg: AlgorithmId,
    certificate: Certificate,
    content_info: &ContentInfo,
) -> Result<Zeroizing<Vec<u8>>> {
    let env = new_cms_environment(new_pki_environment());
    let credential = YubiKeyRecipientKey {
        yubikey: RefCell::new(yubikey),
        slot,
        alg,
        certificate,
        transient_error: Cell::new(None),
    };
    match env.decrypt_enveloped_data(content_info, Some(&credential)) {
        Ok(decrypted) => Ok(decrypted.content),
        Err(e) => {
            if let Some(e) = credential.transient_error.take() {
                return Err(Error::YubiKey(e));
            }
            error!("Failed to decrypt EnvelopedData with the key in slot {slot}: {e}");
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
                        if let Err(e) = import_p12(
                            yubikey,
                            payload_content,
                            password,
                            recovered_index,
                            None,
                            pin,
                            mgmt_key,
                        )
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
