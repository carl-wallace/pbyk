//! YubiKey-related utility functions

use cms::signed_data::EncapsulatedContentInfo;
use const_oid::db::rfc4519::COMMON_NAME;
use der::asn1::{Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef};
use der::{Decode, Encode, Tag, Tagged};
use x509_cert::Certificate;
use yubikey::{piv, piv::SlotId, Key, YubiKey};

use crate::{log_error, Error, Result};

/// Generates an attestation for the indicated slot and returns a P7 containing that attestation and
/// the attestation certificate read from the Attestation slot.
pub(crate) fn get_attestation_p7(yubikey: &mut YubiKey, slot_id: SlotId) -> Result<Vec<u8>> {
    let attestation = match piv::attest(yubikey, slot_id) {
        Ok(a) => a,
        Err(e) => {
            log_error(&format!(
                "Failed to attest to key generated in slot {slot_id}: {:?}",
                e
            ));
            return Err(Error::YubiKey(e));
        }
    };

    let ac = match x509_cert::Certificate::from_der(attestation.as_slice()) {
        Ok(ac) => ac,
        Err(e) => {
            log_error(&format!(
                "Failed to parse attestation for key generated in slot {slot_id}: {:?}",
                e
            ));
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
                            log_error(&format!(
                                "Failed to add certificate read from Attestation slot: {:?}",
                                e
                            ));
                            return Err(Error::Unrecognized);
                        }
                    }
                }
            }
            if !found {
                log_error("Failed read certificate from Attestation slot. Ignoring error.");
            }
        }
        Err(e) => {
            log_error(&format!("Failed to list keys on YubiKey: {:?}", e));
            return Err(Error::YubiKey(e));
        }
    }
    if let Err(e) = builder.add_certificate(cms::cert::CertificateChoices::Certificate(ac)) {
        log_error(&format!(
            "Failed to add attestation certificate for slot {slot_id}: {:?}",
            e
        ));
        return Err(Error::Unrecognized);
    }

    let signed_data_pkcs7 = match builder.build() {
        Ok(sd) => sd,
        Err(e) => {
            log_error(&format!(
                "Failed build attestation PKCS7 for slot {slot_id}: {:?}",
                e
            ));
            return Err(Error::Unrecognized);
        }
    };

    match signed_data_pkcs7.to_der() {
        Ok(attestation_p7) => Ok(attestation_p7),
        Err(e) => {
            log_error(&format!(
                "Failed encode attestation PKCS7 for slot {slot_id}: {:?}",
                e
            ));
            Err(Error::Asn1(e))
        }
    }
}

/// Reads a certificate from the given slot and returns a `Certificate` object
pub(crate) fn get_cert_from_slot(yubikey: &mut YubiKey, slot_id: SlotId) -> Result<Certificate> {
    let l = match Key::list(yubikey) {
        Ok(l) => l,
        Err(e) => {
            log_error(&format!("Failed to list keys on YubiKey: {:?}", e));
            return Err(Error::Unrecognized);
        }
    };
    for ac in l {
        if ac.slot() == slot_id {
            if let Some(cert) = Some(ac.certificate().clone()) {
                return Ok(cert.cert);
            }
        }
    }
    Err(Error::BadInput)
}

/// Reads certificate from CardAuthentication and extracts UUID from common name RDN in subject name
pub(crate) fn get_uuid_from_cert(yubikey: &mut YubiKey) -> Result<String> {
    let cert = match yubikey::certificate::Certificate::read(yubikey, SlotId::CardAuthentication) {
        Ok(c) => c,
        Err(e) => {
            log_error(&format!(
                "Failed to read certificate from CardAuthentication to harvest UUID value: {:?}",
                e
            ));
            return Err(Error::Unrecognized);
        }
    };

    for n in cert.cert.tbs_certificate.subject.0.iter() {
        for a in n.0.iter() {
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
                    return Ok(v.to_string());
                }
            }
        }
    }
    Err(Error::Unrecognized)
}
