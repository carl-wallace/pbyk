#![cfg(all(target_os = "windows", feature = "vsc"))]

use log::{debug, error};
use windows::core::HSTRING;
use x509_cert::certificate::Rfc5280;

use crate::misc_win::vsc_state::{get_vsc_id, get_vsc_id_and_uuid};
use crate::{CERT_SYSTEM_STORE_CURRENT_USER, Error, Result};
use windows::Devices::Enumeration::DeviceInformation;
use windows::Devices::SmartCards::{SmartCard, SmartCardReader, SmartCardReaderKind};

// #[cfg(all(target_os = "windows", feature = "vsc", feature = "reset_vsc"))]
// use windows::{
//     Devices::SmartCards::{
//         SmartCardPinCharacterPolicyOption, SmartCardPinPolicy, SmartCardProvisioning,
//     },
//     Security::Cryptography::CryptographicBuffer,
// };

use core::ffi::c_void;
use std::ptr::NonNull;
use std::{ffi::CString, ptr::null};

use windows::Win32::Security::Cryptography::{
    CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_A, CertCloseStore,
    CertEnumCertificatesInStore, CertOpenStore, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

use crate::misc_win::vsc_signer::CertContext;
use certval::{buffer_to_hex, compare_names};
use der::Encode;
use sha1::{Digest, Sha1};
use x509_cert::certificate::CertificateInner;

use crate::misc_win::csr::get_key_provider_info;

pub fn get_vsc_id_from_serial(hardware_id: &str) -> Result<String> {
    get_vsc_id(&HSTRING::from(hardware_id))
}

pub fn get_vsc_id_and_uuid_from_serial(hardware_id: &str) -> Result<(String, String)> {
    get_vsc_id_and_uuid(&HSTRING::from(hardware_id))
}

fn is_self_issued_5280(cert: &CertificateInner<Rfc5280>) -> bool {
    compare_names(
        cert.tbs_certificate().issuer(),
        cert.tbs_certificate().subject(),
    )
}

/// `list_vscs` returns a list of zero or more [SmartCard] objects.
pub async fn list_vscs() -> Result<Vec<SmartCard>> {
    let mut rv = vec![];

    let readers_aqs = SmartCardReader::GetDeviceSelectorWithKind(SmartCardReaderKind::Tpm)?;
    debug!(
        "Searching for TPM-based virtual smart cards using {} filter",
        readers_aqs
    );
    let readers = DeviceInformation::FindAllAsyncAqsFilter(&readers_aqs)?.get()?;
    for (i, item) in readers.into_iter().enumerate() {
        match item.Id() {
            Ok(id) => {
                let ao_scr = match SmartCardReader::FromIdAsync(&id) {
                    Ok(ao_scr) => ao_scr,
                    Err(e) => {
                        error!(
                            "Failed to get async operation for reader #{i} with: {e}. Continuing..."
                        );
                        continue;
                    }
                };
                let reader = match ao_scr.get() {
                    Ok(reader) => reader,
                    Err(e) => {
                        error!("Failed to get reader #{i} with: {e}. Continuing...");
                        continue;
                    }
                };
                let ao_sc = match reader.FindAllCardsAsync() {
                    Ok(ao_sc) => ao_sc,
                    Err(e) => {
                        error!(
                            "Failed to get async operation for cards for reader #{i} with: {e}. Continuing..."
                        );
                        continue;
                    }
                };
                let cards = match ao_sc.get() {
                    Ok(cards) => cards,
                    Err(e) => {
                        error!("Failed to get cards from reader #{i} with: {e}. Continuing...");
                        continue;
                    }
                };
                for card in cards {
                    rv.push(card);
                }
            }
            Err(e) => {
                error!("Failed to read ID for reader #{i} with: {e}. Continuing...");
            }
        }
    }
    // unlike the UWP app, YubiKeys will not be handled via the Vsc abstraction
    Ok(rv)
}

// #[cfg(all(target_os = "windows", feature = "vsc", feature = "reset_vsc"))]
// pub async fn create_vsc() -> Result<()> {
//     let pin_policy = SmartCardPinPolicy::new().unwrap();
//     let _ = pin_policy.SetDigits(SmartCardPinCharacterPolicyOption::Allow);
//     let _ = pin_policy.SetLowercaseLetters(SmartCardPinCharacterPolicyOption::Allow);
//     let _ = pin_policy.SetUppercaseLetters(SmartCardPinCharacterPolicyOption::Allow);
//     let _ = pin_policy.SetSpecialCharacters(SmartCardPinCharacterPolicyOption::Allow);
//     let _ = pin_policy.SetMinLength(8);
//     log::info!("Creating new VSC");
//     if let Err(e) = SmartCardProvisioning::RequestAttestedVirtualSmartCardCreationAsync(
//         &HSTRING::from("pbyk vsc"),
//         &CryptographicBuffer::GenerateRandom(24)?,
//         &pin_policy,
//     )?
//     .await
//     {
//         error!("Failed to create virtual smart card: {e:?}");
//         Err(Error::Vsc)
//     } else {
//         Ok(())
//     }
// }

/// Gets the number of VSCs
pub async fn num_vscs() -> Result<usize> {
    let list = list_vscs().await?;
    Ok(list.len())
}

/// Gets a VSC that matches a given "serial"
pub async fn get_vsc(serial: &String) -> Result<SmartCard> {
    let readers_aqs = SmartCardReader::GetDeviceSelectorWithKind(SmartCardReaderKind::Tpm)?;
    debug!(
        "Searching for TPM-based virtual smart cards using {} filter",
        readers_aqs
    );
    let readers = DeviceInformation::FindAllAsyncAqsFilter(&readers_aqs)?.get()?;
    for (i, item) in readers.into_iter().enumerate() {
        match item.Id() {
            Ok(id) => {
                let ao_scr = match SmartCardReader::FromIdAsync(&id) {
                    Ok(ao_scr) => ao_scr,
                    Err(e) => {
                        error!(
                            "Failed to get async operation for reader #{i} with: {e}. Continuing..."
                        );
                        continue;
                    }
                };
                let reader = match ao_scr.get() {
                    Ok(reader) => reader,
                    Err(e) => {
                        error!("Failed to get reader #{i} with: {e}. Continuing...");
                        continue;
                    }
                };

                if reader.Name().unwrap_or_default().to_string_lossy() == *serial {
                    let ao_sc = match reader.FindAllCardsAsync() {
                        Ok(ao_sc) => ao_sc,
                        Err(e) => {
                            error!("Failed to get reader #{i} with: {e}. Continuing...");
                            continue;
                        }
                    };
                    let cards = match ao_sc.get() {
                        Ok(cards) => cards,
                        Err(e) => {
                            error!("Failed to get cards from reader #{i} with: {e}. Continuing...");
                            continue;
                        }
                    };
                    if let Some(card) = cards.into_iter().next() {
                        return Ok(card);
                    }
                }
            }
            Err(e) => {
                error!("Failed to read ID for reader #{i} with: {e}. Continuing...");
            }
        }
    }
    // unlike the UWP app, YubiKeys will not be handled via the Vsc abstraction
    error!("Failed to find VSC named {serial}");
    Err(Error::Unrecognized)
}

/// Calculate the Pre-enroll hash for given VSC serial number. This is to support interrupted enrollment flows.
pub fn get_pre_enroll_hash(vsc_serial: &str) -> Result<String> {
    match get_vsc_id_and_uuid_from_serial(vsc_serial) {
        Ok((_, uuid)) => {
            if let Ok(cred) = get_device_cred(&uuid, true) {
                let der_cert = cred.cert.to_der()?;
                Ok(buffer_to_hex(&Sha1::digest(der_cert)))
            } else {
                error!("Failed to get device credential to calculate hash");
                Err(Error::Unrecognized)
            }
        }
        Err(e) => Err(e),
    }
}

/// Gets most recently issue CertContext that corresponds ot the given parameters
pub fn get_device_cred(cn: &str, allow_self_signed: bool) -> Result<CertContext> {
    let my_h = match CString::new("MY") {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create CString for CertOpenStore: {e}");
            return Err(Error::Unrecognized);
        }
    };
    let mut rv = vec![];
    unsafe {
        let my_v: *const c_void = my_h.as_ptr() as *const c_void;
        let cert_store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            None,
            CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
            Some(my_v),
        )?;

        let mut cur_cert_context = CertEnumCertificatesInStore(cert_store, Some(null()));
        while !cur_cert_context.is_null() {
            match CertContext::wrap(NonNull::new_unchecked(cur_cert_context as *mut _)) {
                Ok(cert_context) => {
                    if let Err(_e) = get_key_provider_info(&cert_context) {
                        cur_cert_context =
                            CertEnumCertificatesInStore(cert_store, Some(cur_cert_context));
                        continue;
                    };

                    let cur_cert = cert_context.cert();
                    let subject = cur_cert.tbs_certificate().subject().to_string();
                    if subject.contains(cn) {
                        if allow_self_signed || !is_self_issued_5280(cur_cert) {
                            match CertContext::dup(NonNull::new_unchecked(
                                cur_cert_context as *mut _,
                            )) {
                                Ok(cc) => rv.push(cc),
                                Err(e) => {
                                    error!(
                                        "Failed to prepare CertContext in get_device_cred: {e:?}. Continuing..."
                                    )
                                }
                            };
                        } else {
                            debug!("Skipping self-issued");
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to prepare wrapped CertContext in get_device_cred: {e:?}. Continuing..."
                    );
                }
            }
            cur_cert_context = CertEnumCertificatesInStore(cert_store, Some(cur_cert_context));
        }
        if let Err(e) = CertCloseStore(cert_store, 0) {
            error!("CertCloseStore failed with {e:?}. Ignoring and continuing...");
        }
    }

    rv.sort();
    match rv.pop() {
        Some(cc) => Ok(cc),
        None => Err(Error::BadInput),
    }
}
